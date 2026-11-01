"""Real credential and channel CLI using one protected-session authority fixture."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import base64
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

from qualify_local_chain import REPOSITORY, available_port
from qualify_local_owner import LocalOwnerFixture
import qualify_local_services
from terrier_local import contracts, local_state


class LocalCredentialQualification(LocalOwnerFixture):
    services = qualify_local_services.LocalServicesQualification.services

    def test_protected_session_commands_and_denials(self):
        with tempfile.TemporaryDirectory(prefix="terrier-credentials-", dir="/tmp") as temporary:
            state = Path(temporary).resolve() / "state"
            try:
                self.invoke(state, "start", "--port", str(available_port()))
                self.invoke(state, "deploy", "--offline")
                running = self.services(state, "start")
                broker = running["services"]["broker"]["url"]
                alice = self.owner(state, "register", "--name", "alice")
                for name in ("alice", "bob"):
                    if name != "alice":
                        self.owner(state, "register", "--name", name)
                    self.owner(state, "login", "--name", name, "--broker-url", broker)
                owner_directory = state / "owners/alice"
                session_path = owner_directory / "session.json"
                session = local_state.read_json(session_path)
                bearer = session["session"]["session_jwt"]
                synthetic = "synthetic-credential-" + secrets.token_hex(16) + "\nsecond line\n"
                environment = contracts.tool_environment()
                environment["AGENT_TERRIER_STATE_DIR"] = str(state)

                def command(action, denial=None, name="alice", payload=None):
                    arguments = [sys.executable, str(REPOSITORY / "terrier"), "cred", action, "example", "--name", name]
                    if action == "store":
                        arguments.append("--secret-stdin")
                    result = subprocess.run(arguments, env=environment, input=payload,
                        capture_output=True, text=True, timeout=45)
                    self.assertTrue(bearer not in result.stdout + result.stderr, "CLI output exposed a session bearer")
                    self.assertTrue(synthetic not in result.stderr, "CLI error exposed the credential")
                    if denial:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(denial, result.stderr)
                        self.assertFalse(result.stdout.strip(), "denied command returned data")
                        return result
                    self.assertEqual(result.returncode, 0, result.stderr)
                    receipt = json.loads(result.stdout)
                    if action == "store":
                        self.assertTrue(receipt["stored"])
                        self.assertNotIn("secret", receipt)
                    return receipt

                channel_text = "synthetic local channel\nsecond line\n"

                def channel_command(action, denial=None, name="alice", text=None, after=""):
                    arguments = [sys.executable, str(REPOSITORY / "terrier"), "channel", action,
                        "qualification", "--name", name, "--after", after]
                    if action == "publish":
                        arguments.append("--text-stdin")
                    result = subprocess.run(arguments, env=environment, input=text,
                        capture_output=True, text=True, timeout=45)
                    self.assertNotIn(bearer, result.stdout + result.stderr)
                    if denial:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(denial, result.stderr)
                        self.assertFalse(result.stdout.strip())
                        return None
                    self.assertEqual(result.returncode, 0, result.stderr)
                    return json.loads(result.stdout)["response"]

                command("store", payload=synthetic)
                self.assertTrue(command("fetch")["secret"] == synthetic, "exact credential round trip failed")
                database = state / "services/credentials/objects.db"

                def snapshot(data_class="credentials"):
                    selected_database = state / "services" / data_class / "objects.db"
                    connection = sqlite3.connect(f"file:{selected_database}?mode=ro", uri=True)
                    try:
                        return connection.execute("SELECT key, value, revision FROM objects ORDER BY key").fetchall()
                    finally:
                        connection.close()

                published = channel_command("publish", text=channel_text)
                events = channel_command("poll")
                self.assertEqual(len(events["events"]), 1)
                self.assertEqual(events["events"][0]["event_id"], published["event_id"])
                self.assertEqual(base64.b64decode(events["events"][0]["body"]).decode(), channel_text)
                self.assertEqual(channel_command("poll", after=events["cursor"])["events"], [])
                self.assertEqual(channel_command("poll", name="bob")["events"], [])
                channel_before = snapshot("channel")
                self.assertTrue(channel_before)
                self.assertTrue(all(channel_text.encode() not in row[1] for row in channel_before))
                channel_command("publish", "channel text must contain", text="")
                channel_command("publish", "channel text must contain", text="x" * 65537)
                before = snapshot()
                self.assertTrue(synthetic.encode() not in before[0][1], "database contains plaintext")
                command("fetch", "HTTP 404", name="bob")
                mutations = [
                    (dict(session, development_only=False), "development-only"),
                    (dict(session, broker_url="http://127.0.0.1:1"), "another broker"),
                    (dict(session, device_key_hash="0x" + "00" * 32), "another request key"),
                    (dict(session, session=dict(session["session"], expires_at=0)), "expired"),
                    (dict(session, session=dict(session["session"], expires_at=bearer)), "invalid local session"),
                    (dict(session, session=dict(session["session"], session_jwt="invalid-session")), "HTTP 401"),
                    (local_state.read_json(state / "owners/bob/session.json"), "another owner"),
                ]
                for changed, denial in mutations:
                    local_state.write_json(session_path, changed)
                    command("store", denial, payload="must-not-be-stored")
                    channel_command("publish", denial, text="must-not-be-published")
                    self.assertEqual(snapshot("channel"), channel_before)
                    self.assertTrue(snapshot() == before, "denied store changed persisted data")
                local_state.write_json(session_path, session)
                session_path.chmod(0o644)
                command("store", "owner-only", payload="must-not-be-stored")
                channel_command("publish", "owner-only", text="must-not-be-published")
                session_path.chmod(0o600)
                session_path.unlink()
                session_path.symlink_to(state / "owners/bob/session.json")
                command("store", "protected local session", payload="must-not-be-stored")
                channel_command("publish", "protected local session", text="must-not-be-published")
                session_path.unlink()
                local_state.write_json(session_path, session)
                device_path = owner_directory / "device.key"
                key = device_path.read_bytes()
                device_path.unlink()
                command("store", "existing owner request key", payload="must-not-be-stored")
                channel_command("publish", "existing owner request key", text="must-not-be-published")
                self.assertFalse(device_path.exists())
                local_state.write_private(device_path, key)
                identity_path = owner_directory / "identity.json"
                identity = local_state.read_json(identity_path)
                local_state.write_json(identity_path, dict(identity, profile_identity="different-deployment"))
                command("store", "another contract deployment", payload="must-not-be-stored")
                channel_command("publish", "another contract deployment", text="must-not-be-published")
                local_state.write_json(identity_path, identity)
                command("store", "credential must contain", payload="")
                command("store", "credential must contain", payload="x" * 65537)
                self.assertTrue(snapshot() == before, "negative controls changed storage")
                self.assertEqual(snapshot("channel"), channel_before)

                native_environment = contracts.tool_environment()
                native_environment.update(AGENT_TERRIER_LOCAL_DEV="1", AGENTKEYS_CHAIN_PROFILE_FILE=str(state / "chain-profile.json"))
                native = [str(REPOSITORY / "target/debug/agentkeys"), "local", "credential", "fetch", "example",
                    "--operator-omni", alice["operator_omni"], "--device-key-file", str(device_path),
                    "--session-file", str(session_path), "--broker-url", broker]
                channel_native = [native[0], "local", "channel", "poll", "qualification", *native[5:]]
                for remote in ("https://example.invalid", "http://192.0.2.1:9000"):
                    denied = subprocess.run([*native, "--cred-url", remote], env=native_environment,
                        capture_output=True, text=True, timeout=10)
                    self.assertNotEqual(denied.returncode, 0)
                    self.assertIn("loopback", denied.stderr)
                    denied_channel = subprocess.run([*channel_native, "--channel-url", remote], env=native_environment,
                        capture_output=True, text=True, timeout=10)
                    self.assertNotEqual(denied_channel.returncode, 0)
                    self.assertIn("loopback", denied_channel.stderr)

                received = []

                class RedirectHandler(BaseHTTPRequestHandler):
                    def log_message(self, *_):
                        pass
                    def do_POST(self):
                        received.append(self.path)
                        self.send_response(307)
                        self.send_header("Location", "/should-not-receive-capability")
                        self.end_headers()

                server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    worker = f"http://127.0.0.1:{server.server_port}"
                    denied = subprocess.run([*native, "--cred-url", worker], env=native_environment,
                        capture_output=True, text=True, timeout=20)
                    self.assertNotEqual(denied.returncode, 0)
                    self.assertEqual(received, ["/v1/cred/fetch"])
                    self.assertIn("HTTP 307", denied.stderr)
                    self.assertTrue(bearer not in denied.stdout + denied.stderr, "redirect error exposed session")
                    denied_channel = subprocess.run([*channel_native, "--channel-url", worker], env=native_environment,
                        capture_output=True, text=True, timeout=20)
                    self.assertNotEqual(denied_channel.returncode, 0)
                    self.assertIn("HTTP 307", denied_channel.stderr)
                    self.assertEqual(received, ["/v1/cred/fetch", "/v1/channel/poll"])
                    proxied = dict(native_environment, HTTP_PROXY=worker, HTTPS_PROXY=worker,
                        ALL_PROXY=worker, NO_PROXY="", http_proxy=worker, https_proxy=worker, all_proxy=worker, no_proxy="")
                    direct = subprocess.run([*native, "--cred-url", running["services"]["credentials"]["url"]],
                        env=proxied, capture_output=True, text=True, timeout=20)
                    self.assertEqual(direct.returncode, 0, direct.stderr)
                    self.assertTrue(json.loads(direct.stdout)["secret"] == synthetic, "proxy-free read failed")
                    direct_channel = subprocess.run([*channel_native, "--channel-url", running["services"]["channel"]["url"]],
                        env=proxied, capture_output=True, text=True, timeout=20)
                    self.assertEqual(direct_channel.returncode, 0, direct_channel.stderr)
                    self.assertEqual(len(json.loads(direct_channel.stdout)["response"]["events"]), 1)
                    self.assertEqual(received, ["/v1/cred/fetch", "/v1/channel/poll"])
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)
                self.services(state, "stop")
                self.services(state, "start")
                self.assertTrue(command("fetch")["secret"] == synthetic, "restart changed credential")
                self.assertEqual(base64.b64decode(channel_command("poll")["events"][0]["body"]).decode(), channel_text)
            finally:
                self.services(state, "stop")
                self.invoke(state, "stop")


if __name__ == "__main__":
    unittest.main()
