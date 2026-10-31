"""Explicit CLI lifecycle qualification using real services, contracts and owner credentials."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

from qualify_local_chain import REPOSITORY, available_port
from qualify_local_login import request
from qualify_local_owner import LocalOwnerFixture
from terrier_local import contracts, local_state, services


class LocalServicesQualification(LocalOwnerFixture):
    def services(self, state, *arguments, success=True):
        environment = contracts.tool_environment()
        environment["AGENT_TERRIER_STATE_DIR"] = str(state)
        result = subprocess.run([sys.executable, str(REPOSITORY / "terrier"), "services", *arguments],
            env=environment, capture_output=True, text=True, timeout=90)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0)
        return result

    def test_service_lifecycle_real_credentials_and_failure_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="terrier-services-", dir="/tmp") as temporary:
            root = Path(temporary).resolve()
            state = root / "state"
            try:
                running_chain = self.invoke(state, "start", "--port", str(available_port()))
                self.invoke(state, "deploy", "--offline")
                self.services(state, "doctor", success=False)
                running = self.services(state, "start")
                self.assertTrue(running["ready"])
                self.assertEqual(len(running["services"]), 10)
                self.assertEqual(self.services(state, "start"), running)
                self.assertTrue(self.services(state, "doctor")["ready"])
                broker = running["services"]["broker"]["url"]
                self.assertEqual(request(broker + "/v1/auth/session")[0], 401)
                alice = self.owner(state, "register", "--name", "alice")
                self.owner(state, "login", "--name", "alice", "--broker-url", broker)
                session = local_state.read_json(state / "owners/alice/session.json")["session"]["session_jwt"]
                signing_body = {"omni_account":alice["operator_omni"].removeprefix("0x"), "message_hex":b"synthetic-local-signer".hex()}

                def signing_check():
                    signer = running["services"]["signer"]["url"]
                    self.assertEqual(request(signer + "/v1/auth/session")[0], 404)
                    self.assertEqual(request(signer + "/dev/sign-message", signing_body)[0], 401)
                    self.assertEqual(request(signer + "/dev/sign-message", signing_body, "invalid-test-session")[0], 401)
                    refused_status, refused_body = request(signer + "/dev/sign-message",
                        dict(signing_body, omni_account="91" * 32), session)
                    self.assertEqual(refused_status, 401)
                    self.assertEqual(json.loads(refused_body)["error"], "unauthorized")
                    self.assertNotIn("signature", json.loads(refused_body))
                    result_status, result_body = request(signer + "/dev/sign-message", signing_body, session)
                    self.assertEqual(result_status, 200, json.loads(result_body).get("message", "signer request refused"))
                    result = json.loads(result_body)
                    verified = subprocess.run([contracts.foundry_binary("cast"), "wallet", "verify",
                        "--address", result["address"], "synthetic-local-signer", result["signature"]],
                        env=contracts.tool_environment(), capture_output=True, timeout=10)
                    self.assertEqual(verified.returncode, 0, "local signer signature did not verify")
                    return result["address"]

                original_signer_address = signing_check()
                synthetic = "synthetic-service-check-" + secrets.token_hex(16)
                environment = contracts.tool_environment()
                environment.update(AGENTKEYS_OPERATOR_OMNI=alice["operator_omni"],
                    AGENTKEYS_ACTOR_OMNI=alice["operator_omni"], AGENTKEYS_BROKER_URL=broker,
                    AGENTKEYS_DEVICE_KEY_FILE=str(state / "owners/alice/device.key"),
                    AGENTKEYS_SESSION_BEARER=session, TERRIER_SYNTHETIC_CREDENTIAL=synthetic,
                    AGENTKEYS_CRED_MANIFEST=str(state / "absent-manifest.json"))

                def credential(action):
                    environment["AGENTKEYS_WORKER_CRED_URL"] = running["services"]["credentials"]["url"]
                    arguments = [str(REPOSITORY / "target/debug/agentkeys"), "cred", action, "example"]
                    if action == "store":
                        arguments.extend(["--secret-env", "TERRIER_SYNTHETIC_CREDENTIAL"])
                    result = subprocess.run(arguments, env=environment, capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stderr.replace(session, "[redacted]").replace(synthetic, "[redacted]"))
                    if action == "fetch":
                        self.assertTrue(result.stdout.strip() == synthetic, "credential persistence failed")

                credential("store")
                credential("fetch")
                profile_path = state / "chain-profile.json"
                profile = local_state.read_json(profile_path)
                local_state.write_json(profile_path, dict(profile, contract_set_version="different-version"))
                try:
                    unhealthy = self.services(state, "doctor", success=False)
                    self.assertFalse(json.loads(unhealthy.stdout)["profile_matches"])
                finally:
                    local_state.write_json(profile_path, profile)
                self.assertTrue(self.services(state, "doctor")["ready"])
                manifest = local_state.read_json(state / "services/manifest.json")
                keys = [state / "services/broker/oidc.json", state / "services/broker/session.json", state / "services/signer/master.key",
                        *[state / "services" / name / "development.key" for name in services.WORKERS]]
                preserved = {path:path.read_bytes() for path in keys}
                self.assertTrue(self.services(state, "stop")["state_preserved"])
                self.assertFalse(self.services(state, "status")["running"])
                self.assertEqual(self.invoke(state, "status")["instance_id"], running_chain["instance_id"])
                running = self.services(state, "start")
                self.assertEqual(running["services"]["broker"]["url"], broker)
                self.assertEqual(signing_check(), original_signer_address)
                credential("fetch")
                self.assertTrue(all(path.read_bytes() == value for path, value in preserved.items()), "service restart replaced a key")
                self.services(state, "stop")
                missing = state / "services/memory/development.key"
                original = missing.read_bytes()
                missing.unlink()
                refused = self.services(state, "start", success=False)
                self.assertIn("encryption key is missing", refused.stderr)
                self.assertFalse(missing.exists())
                local_state.write_private(missing, original)
                signer_key = state / "services/signer/master.key"
                original = signer_key.read_bytes()
                signer_key.unlink()
                refused = self.services(state, "start", success=False)
                self.assertIn("signer key is missing", refused.stderr)
                self.assertFalse(signer_key.exists())
                local_state.write_private(signer_key, original)
                changed = dict(manifest, profile_identity="another-deployment")
                local_state.write_json(state / "services/manifest.json", changed)
                refused = self.services(state, "start", success=False)
                self.assertIn("another deployment", refused.stderr)
                local_state.write_json(state / "services/manifest.json", manifest)

                class Handler(BaseHTTPRequestHandler):
                    def log_message(self, *_):
                        pass
                    def do_GET(self):
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b"unrelated-service")

                server = ThreadingHTTPServer(("127.0.0.1", manifest["broker_port"]), Handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    self.services(state, "start", success=False)
                    self.assertEqual(request(broker)[1], b"unrelated-service")
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)
                binaries = root / "failing-binaries"
                binaries.mkdir()
                for name in services.BINARIES:
                    destination = binaries / name
                    if name == services.WORKERS["memory"]:
                        destination.write_text(f"#!{sys.executable}\nraise SystemExit(23)\n")
                        destination.chmod(0o700)
                    else:
                        destination.symlink_to(REPOSITORY / "target/debug" / name)
                self.services(state, "start", "--bin-dir", str(binaries), success=False)
                self.assertFalse(self.services(state, "status")["running"])
                with socket.socket() as listener:
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listener.bind(("127.0.0.1", manifest["broker_port"]))
                self.assertEqual(self.invoke(state, "status")["instance_id"], running_chain["instance_id"])
                running = self.services(state, "start")
                credential("fetch")
                for path in keys:
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                logs = b"".join(path.read_bytes() for path in (state / "services").glob("*.log"))
                self.assertTrue(session.encode() not in logs and synthetic.encode() not in logs, "service logs exposed credentials")
                self.assertTrue(signer_key.read_bytes() not in logs, "service logs exposed signing material")
            finally:
                self.services(state, "stop")
                self.invoke(state, "stop")


if __name__ == "__main__":
    unittest.main()
