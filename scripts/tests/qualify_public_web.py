"""Explicit built-console HTTP qualification, without a browser or private backend."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from qualify_local_chain import REPOSITORY, available_port
from terrier_local import chain, contracts, services, test_lanes


class PublicWebQualification(unittest.TestCase):
    def test_console_assets_and_removed_proxy_have_no_direct_bridge_authority(self):
        application = REPOSITORY / "apps/parent-control"
        self.assertFalse(list(application.glob(".env*")), "Use a checkout without local environment files")
        environment = dict(contracts.tool_environment(), NEXT_TELEMETRY_DISABLED="1", CI="1",
                           NEXT_PUBLIC_AGENTKEYS_DAEMON_URL="http://127.0.0.1:0")
        diagnostics = Path(tempfile.mkdtemp(prefix="terrier-web-qualification-"))
        completed = False
        children = []
        requests = []
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), chain.NoRedirect())

        class ControlledBridge(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                body = json.dumps({"ok": True, "phase": "ready"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_POST = do_GET

            def log_message(self, *_arguments):
                pass

        bridge = ThreadingHTTPServer(("127.0.0.1", 0), ControlledBridge)
        bridge_thread = threading.Thread(target=bridge.serve_forever, daemon=True)
        bridge_thread.start()
        bridge_url = f"http://127.0.0.1:{bridge.server_port}"
        environment["AGENTKEYS_LOCAL_SANDBOX_BRIDGE_URL"] = bridge_url
        environment["AGENTKEYS_LOCAL_SANDBOX_BRIDGE_TOKEN"] = "synthetic-qualification-only"

        def request(url, payload=None):
            data = json.dumps(payload).encode() if payload is not None else None
            request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            try:
                response = opener.open(request, timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                return response.status, response.read(2 * 1024 * 1024), response.headers

        try:
            self.assertEqual(request(bridge_url + "/positive-control")[0], 200)
            requests.clear()
            built = test_lanes.execute(["npm", "run", "build"], application, diagnostics / "build.log",
                                       timeout_seconds=180, extra_environment=environment)
            self.assertEqual(built["status"], "passed", "Console build failed; inspect retained diagnostics")
            executable = subprocess.check_output(["node", "-p", "require.resolve('next/dist/bin/next')"],
                cwd=application, env=environment, text=True, timeout=10).strip()
            port = available_port()
            with (diagnostics / "server.log").open("xb") as log:
                server = subprocess.Popen(["node", executable, "start", "--hostname", "127.0.0.1", "--port", str(port)],
                    cwd=application, env=environment, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            children.append(server)
            base = f"http://127.0.0.1:{port}"
            deadline = time.monotonic() + 10
            while True:
                self.assertIsNone(server.poll(), "Console server exited before readiness")
                try:
                    status, body, _ = request(base + "/")
                    break
                except OSError:
                    self.assertLess(time.monotonic(), deadline, "Console server readiness timed out")
                    time.sleep(0.05)
            self.assertEqual(status, 200)
            self.assertIn(b"<html", body)
            assets = re.findall(rb'<script[^>]+src="(/_next/static/[^"?]+)', body)
            self.assertTrue(assets, "The production page has no executable client assets")
            status, asset, headers = request(base + assets[0].decode())
            self.assertEqual(status, 200)
            self.assertTrue(asset)
            self.assertIn("javascript", headers.get("Content-Type", ""))
            routes = (("/dev/local-sandbox", None),
                      ("/api/dev/local-sandbox/healthz", None),
                      ("/api/dev/local-sandbox/chat", {"text": "synthetic test", "stream": False}))
            responses = [(route, request(base + route, payload)[0]) for route, payload in routes]
            self.assertEqual(responses, [(route, 404) for route, _ in routes])
            self.assertEqual(requests, [], "A removed route reached a privileged bridge")
            completed = True
        finally:
            services.stop_children(children)
            bridge.shutdown()
            bridge.server_close()
            bridge_thread.join(timeout=5)
            if completed:
                for path in diagnostics.iterdir():
                    path.unlink()
                diagnostics.rmdir()
            else:
                print(f"Private diagnostic directory: {diagnostics}")


if __name__ == "__main__":
    unittest.main()
