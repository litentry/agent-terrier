"""Explicit owner login qualification against the real broker and local contracts."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from qualify_local_owner import LocalOwnerFixture
from qualify_local_chain import REPOSITORY, available_port
from terrier_local import chain, contracts, local_state


def request(endpoint, body=None, bearer=None):
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    data = None if body is None else json.dumps(body).encode()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(endpoint, data=data, headers=headers), timeout=3) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


@contextmanager
def capture_assertion(endpoint):
    assertions = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            if self.path not in ("/v1/auth/passkey/start", "/v1/auth/passkey/verify"):
                self.send_error(404)
                return
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.path.endswith("/verify"):
                assertions.append(body)
            status, response = request(endpoint + self.path, body)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", assertions
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def broker(state, profile, port):
    binary = REPOSITORY / "target/debug/agentkeys-broker-server"
    directory = state / "broker"
    local_state.private_directory(directory)
    for purpose in ("oidc", "session"):
        destination = directory / f"{purpose}.json"
        if not destination.exists():
            result = subprocess.run([str(binary), "keygen", "--purpose", purpose, "--out", str(destination)],
                                    env=contracts.tool_environment(), capture_output=True, timeout=15)
            if result.returncode:
                raise RuntimeError("Broker test key generation failed")
    endpoint = f"http://127.0.0.1:{port}"
    environment = contracts.tool_environment()
    environment.update(BROKER_OIDC_ISSUER=endpoint, BROKER_DEV_MODE="true",
                       BROKER_AUDIT_DB_PATH=str(directory / "audit.sqlite"),
                       BROKER_OIDC_KEYPAIR_PATH=str(directory / "oidc.json"),
                       BROKER_SESSION_KEYPAIR_PATH=str(directory / "session.json"),
                       AGENTKEYS_CHAIN_PROFILE_FILE=str(profile))
    process = subprocess.Popen([str(binary), "--port", str(port)], env=environment,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, umask=0o077)
    try:
        deadline = time.monotonic() + 15
        while True:
            if process.poll() is not None:
                raise RuntimeError("Broker exited before readiness")
            try:
                status, response = request(endpoint + "/readyz")
                if status == 200 and json.loads(response)["status"] == "ready":
                    break
            except (OSError, urllib.error.URLError):
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("Broker readiness timed out")
            time.sleep(0.05)
        yield endpoint
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


class LocalLoginTests(LocalOwnerFixture):
    def test_real_login_replay_wrong_key_and_restart(self):
        with tempfile.TemporaryDirectory(prefix="terrier-login-", dir="/tmp") as temporary:
            state = Path(temporary).resolve() / "state"
            port = available_port()
            try:
                running = self.invoke(state, "start", "--port", str(available_port()))
                deployed = self.invoke(state, "deploy", "--offline")
                alice = self.owner(state, "register", "--name", "alice")
                self.owner(state, "register", "--name", "bob")
                before = chain.rpc(running["rpc_http"], "eth_blockNumber")
                with broker(state, deployed["profile"], port) as endpoint:
                    with capture_assertion(endpoint) as (proxy, assertions):
                        receipt = self.owner(state, "login", "--name", "alice", "--broker-url", proxy)
                    session_path = state / "owners/alice/session.json"
                    self.assertEqual(session_path.stat().st_mode & 0o777, 0o600)
                    stored = local_state.read_json(session_path)
                    token = stored["session"]["session_jwt"]
                    self.assertTrue(token not in json.dumps(receipt), "login receipt exposed its bearer")
                    self.assertEqual(receipt["account"], alice["account"])
                    self.assertEqual(stored["device_key_hash"], alice["device_key_hash"])
                    status, response = request(endpoint + "/v1/auth/session", bearer=token)
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(response)["omni_account"], alice["operator_omni"].removeprefix("0x"))
                    self.assertEqual(len(assertions), 1)
                    status, response = request(endpoint + "/v1/auth/passkey/verify", assertions[0])
                    self.assertEqual(status, 401)
                    self.assertIn("already-used challenge", json.loads(response)["message"])
                    self.assertNotIn("session_jwt", json.loads(response))
                    preserved_session = session_path.read_bytes()
                    key_path = state / "owners/alice/passkey.pem"
                    original_key = key_path.read_bytes()
                    local_state.write_private(key_path, (state / "owners/bob/passkey.pem").read_bytes())
                    refused = self.owner(state, "login", "--name", "alice", "--broker-url", endpoint, success=False)
                    self.assertIn("rejected the owner passkey assertion", refused.stderr)
                    self.assertTrue(session_path.read_bytes() == preserved_session, "failed login replaced the session")
                    key_path.unlink()
                    self.owner(state, "login", "--name", "alice", "--broker-url", endpoint, success=False)
                    self.assertFalse(key_path.exists())
                    self.assertTrue(session_path.read_bytes() == preserved_session, "missing key replaced the session")
                    local_state.write_private(key_path, original_key)
                    refused = self.owner(state, "login", "--name", "alice", "--broker-url",
                                         "https://example.invalid", success=False)
                    self.assertIn("loopback HTTP", refused.stderr)
                    self.assertTrue(session_path.read_bytes() == preserved_session, "remote endpoint replaced the session")
                    self.assertEqual(request(endpoint + "/v1/auth/session")[0], 401)
                with broker(state, deployed["profile"], port) as endpoint:
                    self.assertEqual(request(endpoint + "/v1/auth/session", bearer=token)[0], 200)
                    self.owner(state, "login", "--name", "alice", "--broker-url", endpoint)
                    self.assertEqual(chain.rpc(running["rpc_http"], "eth_blockNumber"), before)
            finally:
                self.invoke(state, "stop")


if __name__ == "__main__":
    unittest.main()
