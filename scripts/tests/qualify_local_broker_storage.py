"""Explicit real login, capability, credential worker and persistent storage qualification."""
from contextlib import contextmanager
import json
from pathlib import Path
import secrets
import selectors
import sqlite3
import subprocess
import tempfile
import unittest

import qualify_local_binding
from qualify_local_chain import REPOSITORY, available_port
from qualify_local_login import broker
from qualify_local_owner import LocalOwnerFixture
from terrier_local import contracts, local_state


@contextmanager
def service(binary, *arguments):
    process = subprocess.Popen([str(REPOSITORY / "target/debug" / binary), *map(str, arguments)],
        env=contracts.tool_environment(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, umask=0o077)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=15):
                raise RuntimeError(f"{binary} readiness timed out")
            record = process.stdout.readline()
        if not record:
            raise RuntimeError(f"{binary} exited before readiness")
        yield "http://" + json.loads(record)["listen"]
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()


class LocalBrokerStorageTests(LocalOwnerFixture):
    device = qualify_local_binding.LocalBindingTests.device

    def test_real_owner_and_delegate_storage_authority(self):
        with tempfile.TemporaryDirectory(prefix="terrier-broker-storage-", dir="/tmp") as temporary:
            state = Path(temporary).resolve() / "state"
            try:
                self.invoke(state, "start", "--port", str(available_port()))
                deployed = self.invoke(state, "deploy", "--offline")
                alice = self.owner(state, "register", "--name", "alice")
                self.owner(state, "register", "--name", "bob")
                identity = self.device(state, alice["operator_omni"], "reader", "delegate")
                self.owner(state, "bind", "--name", "alice", "--enrollment-file", identity["enrollment_file"],
                           "--service", "example")
                storage = state / "storage"
                local_state.private_directory(storage)
                database = storage / "credentials.db"
                encryption_key = storage / "development.key"
                local_state.write_private(encryption_key, secrets.token_hex(32).encode())
                public_key = state / "broker/session-public.pem"
                with broker(state, deployed["profile"], available_port()) as endpoint:
                    self.owner(state, "login", "--name", "alice", "--broker-url", endpoint)
                    session = local_state.read_json(state / "owners/alice/session.json")["session"]["session_jwt"]
                    environment = contracts.tool_environment()
                    environment.update(AGENTKEYS_OPERATOR_OMNI=alice["operator_omni"],
                        AGENTKEYS_ACTOR_OMNI=alice["operator_omni"],
                        AGENTKEYS_DEVICE_KEY_FILE=str(state / "owners/alice/device.key"),
                        AGENTKEYS_SESSION_BEARER=session, AGENTKEYS_BROKER_URL=endpoint,
                        AGENTKEYS_CRED_MANIFEST=str(state / "absent-manifest.json"),
                        TERRIER_SYNTHETIC_CREDENTIAL="synthetic-qualification-" + secrets.token_hex(16))

                    def invoke(action, overrides=None, denial=None):
                        child_environment = dict(environment, **(overrides or {}))
                        arguments = [str(REPOSITORY / "target/debug/agentkeys"), "cred", action, "example"]
                        if action == "store":
                            arguments.extend(["--secret-env", "TERRIER_SYNTHETIC_CREDENTIAL"])
                        result = subprocess.run(arguments, env=child_environment, capture_output=True,
                                                text=True, timeout=30)
                        diagnostic = result.stderr
                        for sensitive in (session, environment["TERRIER_SYNTHETIC_CREDENTIAL"]):
                            diagnostic = diagnostic.replace(sensitive, "[redacted]")
                        if denial:
                            self.assertNotEqual(result.returncode, 0, "unauthorized credential operation succeeded")
                            self.assertIn(denial, diagnostic)
                            if denial in {"device_binding_mismatch", "cred_store_not_master_self",
                                          "service_not_in_scope", "device_revoked"}:
                                self.assertIn("HTTP error (403)", diagnostic)
                            self.assertTrue(environment["TERRIER_SYNTHETIC_CREDENTIAL"] not in result.stdout,
                                            "denied request disclosed the stored credential")
                        else:
                            self.assertEqual(result.returncode, 0, diagnostic)
                            if action == "fetch":
                                self.assertTrue(result.stdout.strip() == environment["TERRIER_SYNTHETIC_CREDENTIAL"],
                                                "credential round trip changed the value")
                        return result

                    def snapshot():
                        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
                        try:
                            return connection.execute("SELECT key, value, revision FROM objects ORDER BY key").fetchall()
                        finally:
                            connection.close()

                    for iteration in range(2):
                        with service("agentkeys-local-store", "--development", "--profile", deployed["profile"],
                                     "--database", database, "--broker-public-key", public_key,
                                     "--data-class", "credentials") as storage_url:
                            with service("agentkeys-worker-creds", "--development", "--profile", deployed["profile"],
                                         "--broker-public-key", public_key, "--storage-url", storage_url,
                                         "--development-kek-file", encryption_key) as worker_url:
                                environment["AGENTKEYS_WORKER_CRED_URL"] = worker_url
                                if iteration == 0:
                                    invoke("store")
                                invoke("fetch")
                                persisted = snapshot()
                                self.assertEqual(len(persisted), 1)
                                self.assertTrue(environment["TERRIER_SYNTHETIC_CREDENTIAL"].encode() not in persisted[0][1],
                                                "stored object contains the plaintext credential")
                                if iteration == 1:
                                    break
                                invoke("store", {"AGENTKEYS_DEVICE_KEY_FILE": str(state / "owners/bob/device.key")},
                                       denial="device_binding_mismatch")
                                invoke("fetch", {"AGENTKEYS_SESSION_BEARER": "invalid-session"}, denial="401")
                                missing_key = state / "missing.key"
                                invoke("store", {"AGENTKEYS_DEVICE_KEY_FILE": str(missing_key)}, denial="existing registered device key")
                                self.assertFalse(missing_key.exists())
                                delegated = {"AGENTKEYS_ACTOR_OMNI": identity["enrollment"]["actor_omni"],
                                             "AGENTKEYS_DEVICE_KEY_FILE": str(state / "devices/reader/device.key")}
                                invoke("fetch", delegated)
                                invoke("store", delegated, denial="cred_store_not_master_self")
                                self.owner(state, "revoke", "--name", "alice",
                                           "--actor-omni", identity["enrollment"]["actor_omni"])
                                invoke("fetch", delegated, denial="service_not_in_scope")
                                self.owner(state, "grant", "--name", "alice",
                                           "--actor-omni", identity["enrollment"]["actor_omni"], "--service", "example")
                                invoke("fetch", delegated)
                                self.owner(state, "unbind", "--name", "alice", "--enrollment-file", identity["enrollment_file"])
                                invoke("fetch", delegated, denial="device_revoked")
                                self.assertTrue(snapshot() == persisted, "denied operations changed persisted objects")
                                invoke("fetch")
                    self.assertEqual(database.stat().st_mode & 0o777, 0o600)
            finally:
                self.invoke(state, "stop")


if __name__ == "__main__":
    unittest.main()
