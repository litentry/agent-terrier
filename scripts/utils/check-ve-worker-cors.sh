#!/usr/bin/env bash
set -euo pipefail
: "${ENV_FILE:?set ENV_FILE to the VE stack environment file}"
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
python3 - <<'PYTHON'
import os
import urllib.error
import urllib.request

origins = [origin.strip().rstrip('/') for origin in os.environ.get('AGENTKEYS_BROWSER_ORIGINS', '').split(',') if origin.strip()]
dashboard_host = os.environ.get('VE_DASHBOARD_HOST', '')
if dashboard_host:
    origins.append('https://' + dashboard_host)
origins = list(dict.fromkeys(origins))
if not origins:
    raise SystemExit('No browser origin is configured for this stack; cannot validate hosted worker access.')
headers = {'content-type', 'authorization', 'x-aws-access-key-id', 'x-aws-secret-access-key', 'x-aws-session-token'}
timeout = float(os.environ.get('WORKER_CORS_TIMEOUT_SECONDS', '20'))
for worker, route in [('CRED', '/v1/cred/put'), ('MEMORY', '/v1/memory/put'), ('CONFIG', '/v1/config/put'), ('CLASSIFY', '/v1/classify'), ('AUDIT', '/v1/audit/append')]:
    host = os.environ['VE_' + worker + '_HOST']
    for origin in origins + ['https://untrusted.example.invalid']:
        expected_origin = origin if origin in origins else None
        request = urllib.request.Request('https://' + host + route, method='OPTIONS', headers={
            'Origin': origin, 'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': ','.join(sorted(headers)),
        })
        try:
            response = urllib.request.urlopen(request, timeout=timeout)
        except urllib.error.HTTPError as failure:
            response = failure
        with response:
            actual_origin = response.headers.get('Access-Control-Allow-Origin')
            allowed_headers = {header.strip().lower() for header in response.headers.get('Access-Control-Allow-Headers', '').split(',')}
            if response.status not in (200, 204):
                raise SystemExit(f'FAIL: {worker}: preflight HTTP {response.status}')
            if actual_origin != expected_origin:
                raise SystemExit(f'FAIL: {worker}: origin {origin!r} returned allow-origin {actual_origin!r}, expected {expected_origin!r}')
            if expected_origin:
                if not headers <= allowed_headers:
                    raise SystemExit(f'FAIL: {worker}: missing request headers {headers - allowed_headers}')
                allowed_methods = {method.strip() for method in response.headers.get('Access-Control-Allow-Methods', '').split(',')}
                if 'POST' not in allowed_methods:
                    raise SystemExit(f'FAIL: {worker}: POST is not allowed')
        print(f'PASS: {worker} preflight {origin}')
PYTHON
