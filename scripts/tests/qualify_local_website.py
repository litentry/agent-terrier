"""Explicit prebuilt website lifecycle and exact-origin qualification with real local services."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import shutil
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

import qualify_local_services as service_scenarios
from qualify_local_owner import LocalOwnerFixture
from qualify_local_chain import available_port
from terrier_local import chain, local_state, services, website


class LocalWebsiteQualification(LocalOwnerFixture):
    services = service_scenarios.LocalServicesQualification.services
    stack = service_scenarios.LocalServicesQualification.stack

    def test_owned_website_restart_origin_allowlist_and_occupied_port_cleanup(self):
        requests = []
        class ForeignListener(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"unrelated-listener")
            def log_message(self, *_arguments):
                pass
        foreign = ThreadingHTTPServer(("127.0.0.1", 0), ForeignListener)
        thread = threading.Thread(target=foreign.serve_forever, daemon=True)
        thread.start()
        web_port = foreign.server_port
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), chain.NoRedirect())

        def request(address, method="GET", origin=None):
            headers = {"Origin":origin} if origin else {}
            if method == "OPTIONS":
                headers.update({"Access-Control-Request-Method":"POST", "Access-Control-Request-Headers":"authorization,content-type"})
            try:
                response = client.open(urllib.request.Request(address, method=method, headers=headers), timeout=3)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                return response.status, response.read(1024 * 1024), response.headers

        root = Path(tempfile.mkdtemp(prefix="terrier-website-", dir="/tmp")).resolve()
        state = root / "state"
        completed = False
        try:
            refused = self.stack(state, "start", "--chain-port", str(available_port()), "--website", "--web-port", str(web_port), success=False)
            self.assertEqual(refused["failed_stage"], "services")
            self.assertIn("Website port is occupied", (state / "services-supervisor.log").read_text(), "Expected an actual occupied-website refusal")
            self.assertFalse(refused["chain"]["running"])
            self.assertFalse(refused["services"]["running"])
            self.assertEqual(requests, [], "Occupied listener must not be probed or stopped")
            self.assertEqual(request(f"http://127.0.0.1:{web_port}/")[1], b"unrelated-listener")
            foreign.shutdown()
            foreign.server_close()
            thread.join(timeout=5)

            started = self.stack(state, "start")
            group = started["services"]
            self.assertTrue(started["ready"])
            self.assertEqual(len(group["services"]), 14)
            address = group["services"]["website"]["url"]
            broker = group["services"]["broker"]["url"]
            self.assertEqual(address, f"http://127.0.0.1:{web_port}")
            self.assertEqual(self.stack(state, "start")["services"], group)
            status, payload, headers = request(address + "/api/healthz")
            self.assertEqual(status, 200)
            self.assertIn("no-store", headers.get("Cache-Control", ""))
            health = json.loads(payload)
            self.assertEqual(health["backend"], {"kind":"core", "url":broker})
            self.assertTrue(website.healthy(address, broker, health["instance"]))
            self.assertFalse(website.healthy(address, broker, "wrong-instance"))
            self.assertFalse(website.healthy(address, "http://127.0.0.1:1", health["instance"]))
            self.assertIn(b"terrier-backend-configuration", request(address)[1])
            foreign_origin = "http://unrelated.example.test"
            for name in ("broker", *services.WORKERS, *services.COMPUTE_WORKERS):
                endpoint = group["services"][name]["url"]
                for method in ("GET", "OPTIONS"):
                    positive = request(endpoint + "/healthz", method, address)
                    denied = request(endpoint + "/healthz", method, foreign_origin)
                    self.assertEqual(positive[2].get("Access-Control-Allow-Origin"), address)
                    self.assertIsNone(denied[2].get("Access-Control-Allow-Origin"))
            config_status, config_body, config_headers = request(broker + "/v1/console/config", origin=address)
            self.assertEqual(config_status, 200, config_body)
            configuration = json.loads(config_body)
            self.assertIsNone(configuration["audit_url"])
            self.assertEqual(config_headers.get("Access-Control-Allow-Origin"), address)
            for field, service_name in (("signer_url", "signer"), ("config_url", "config"),
                    ("memory_url", "memory"), ("credential_url", "credentials"), ("channel_url", "channel"),
                    ("classify_url", "classify")):
                self.assertEqual(configuration[field], group["services"][service_name]["url"])
            self.assertEqual(request(broker + "/v1/auth/session", origin=address)[0], 401)
            self.assertEqual(request(broker + "/v1/console/audit", origin=address)[0], 401)
            manifest = local_state.read_json(state / "services/manifest.json")
            restarted = self.stack(state, "restart")
            self.assertTrue(restarted["ready"])
            self.assertEqual(restarted["services"]["services"]["website"]["url"], address)
            self.assertEqual(local_state.read_json(state / "services/manifest.json"), manifest)
            next_health = json.loads(request(address + "/api/healthz")[1])
            self.assertNotEqual(next_health["instance"], health["instance"])
            self.assertEqual(next_health["backend"], health["backend"])
            self.assertEqual((state / "services/website.log").stat().st_mode & 0o777, 0o600)
            self.assertTrue(self.stack(state, "stop")["state_preserved"])
            self.assertFalse(website.healthy(address, broker, next_health["instance"]))
            self.assertFalse(self.stack(state, "doctor", success=False)["ready"])
            completed = True
        finally:
            foreign.shutdown()
            foreign.server_close()
            thread.join(timeout=5)
            self.services(state, "stop")
            self.invoke(state, "stop")
            if completed:
                shutil.rmtree(root)
            else:
                print(f"Private diagnostic directory: {root}")


if __name__ == "__main__":
    unittest.main()
