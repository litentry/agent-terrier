"""Real P-256 owner onboarding and scope changes; explicit local qualification."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from qualify_local_chain import LocalChainFixture, REPOSITORY, available_port
from terrier_local import chain, contracts, deployment, local_state, owner


class LocalOwnerFixture(LocalChainFixture):
    def owner(self, state, *arguments, success=True):
        environment = contracts.tool_environment()
        environment["AGENT_TERRIER_STATE_DIR"] = str(state)
        result = subprocess.run([sys.executable, str(REPOSITORY / "terrier"), "owner", *arguments],
                                env=environment, capture_output=True, text=True, timeout=120)
        self.assertNotIn("PRIVATE KEY", result.stdout + result.stderr)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0)
        return result

class LocalOwnerTests(LocalOwnerFixture):
    def test_owner_register_grant_revoke_and_denials_on_real_contracts(self):
        with tempfile.TemporaryDirectory(prefix="terrier-owner-", dir="/tmp") as temporary:
            state = Path(temporary).resolve() / "state"
            port = available_port()
            try:
                running = self.invoke(state, "start", "--port", str(port))
                deployed = self.invoke(state, "deploy", "--offline")
                registered = self.owner(state, "register", "--name", "alice")
                self.assertTrue(registered["registered"])
                self.assertTrue(registered["verified"])
                request_key = state / "owners/alice/device.key"
                self.assertTrue(request_key.is_file(), "owner registration must enroll a real request-signing key")
                request_secret = request_key.read_bytes()
                self.assertEqual(request_key.stat().st_mode & 0o777, 0o600)
                self.assertNotIn(request_secret.decode().removeprefix("0x"), json.dumps(registered))
                operator = registered["operator_omni"]
                before = chain.rpc(running["rpc_http"], "eth_blockNumber")
                repeated = self.owner(state, "register", "--name", "alice")
                self.assertFalse(repeated["registered"])
                self.assertEqual(repeated["account"], registered["account"])
                self.assertEqual(repeated["device_key_hash"], registered["device_key_hash"])
                self.assertEqual(chain.rpc(running["rpc_http"], "eth_blockNumber"), before)
                profile = local_state.read_json(Path(deployed["profile"]))
                scope = next(item["address"] for item in profile["contracts"] if item["name"] == "AgentKeysScope")
                actor = "0x" + "45" * 32
                service = "knowledge:qualification"
                service_hash = subprocess.check_output([contracts.foundry_binary("cast"), "keccak", service],
                                                       env=contracts.tool_environment(), text=True).strip()

                def permitted():
                    return subprocess.check_output([contracts.foundry_binary("cast"), "call", scope,
                        "isServiceInScope(bytes32,bytes32,bytes32)(bool)", operator, actor, service_hash,
                        "--rpc-url", running["rpc_http"]], env=contracts.tool_environment(), text=True).strip() == "true"

                self.assertFalse(permitted())
                beneficiary, keystore, password_file = deployment.developer_wallet(state)
                plan = owner.run_cli(REPOSITORY, Path(deployed["profile"]), ["prepare-owner", "grant",
                    "--operator-omni", operator, "--key-file", str(state / "owners/alice/passkey.pem"),
                    "--device-key-file", str(request_key),
                    "--beneficiary", beneficiary, "--actor-omni", actor, "--service", service])
                original_signature = plan["build"]["user_op"]["signature"].removeprefix("0x")
                altered_signature = bytearray.fromhex(original_signature)
                altered_signature[159] ^= 1
                self.assertEqual(plan["transaction_data"].count(original_signature), 1)
                altered_call = plan["transaction_data"].replace(original_signature, altered_signature.hex())
                denied_transaction = subprocess.run([contracts.foundry_binary("cast"), "send",
                    plan["build"]["entry_point"], "--data", altered_call, "--rpc-url", running["rpc_http"],
                    "--gas-limit", str(owner.DEFAULT_TRANSACTION_GAS), "--keystore", str(keystore),
                    "--password-file", str(password_file), "--json"], env=contracts.tool_environment(),
                    capture_output=True, text=True, timeout=60)
                denied_receipt = json.loads(denied_transaction.stdout)
                self.assertEqual(denied_receipt["status"], "0x0")
                self.assertFalse(permitted())
                granted = self.owner(state, "grant", "--name", "alice", "--actor-omni", actor, "--service", service)
                self.assertTrue(granted["verified"])
                self.assertTrue(permitted())
                original_identity = local_state.read_json(state / "owners/alice/identity.json")
                bob = self.owner(state, "register", "--name", "bob")
                wrong_identity = dict(original_identity, operator_omni=bob["operator_omni"])
                local_state.write_json(state / "owners/alice/identity.json", wrong_identity)
                before = chain.rpc(running["rpc_http"], "eth_blockNumber")
                denied = self.owner(state, "grant", "--name", "alice", "--actor-omni", actor,
                                    "--service", "knowledge:forbidden", success=False)
                self.assertIn("does not match the on-chain master", denied.stderr)
                self.assertEqual(chain.rpc(running["rpc_http"], "eth_blockNumber"), before)
                self.assertTrue(permitted())
                local_state.write_json(state / "owners/alice/identity.json", original_identity)
                revoked = self.owner(state, "revoke", "--name", "alice", "--actor-omni", actor)
                self.assertTrue(revoked["verified"])
                self.assertFalse(permitted())
                failed = self.owner(state, "revoke", "--name", "alice", "--actor-omni", actor, success=False)
                self.assertIn("owner operation reverted", failed.stderr)
                self.assertFalse(permitted())
                self.assertEqual((state / "owners/alice/passkey.pem").stat().st_mode & 0o777, 0o600)
                self.assertEqual((state / "owners/alice").stat().st_mode & 0o777, 0o700)
                key_path = state / "owners/alice/passkey.pem"
                preserved = key_path.read_bytes()
                key_path.unlink()
                missing = self.owner(state, "register", "--name", "alice", success=False)
                self.assertIn("restore its original key", missing.stderr)
                self.assertFalse(key_path.exists())
                local_state.write_private(key_path, preserved)
                self.invoke(state, "stop")
                self.invoke(state, "start", "--port", str(port))
                self.assertEqual(self.owner(state, "register", "--name", "alice")["account"], registered["account"])
                self.assertEqual(request_key.read_bytes(), request_secret)
                request_key.unlink()
                before = chain.rpc(running["rpc_http"], "eth_blockNumber")
                missing_request_key = self.owner(state, "register", "--name", "alice", success=False)
                self.assertIn("owner request key is missing", missing_request_key.stderr)
                self.assertFalse(request_key.exists())
                self.assertEqual(chain.rpc(running["rpc_http"], "eth_blockNumber"), before)
                local_state.write_private(request_key, (state / "owners/bob/device.key").read_bytes())
                wrong_request_key = self.owner(state, "register", "--name", "alice", success=False)
                self.assertIn("does not match the active on-chain master binding", wrong_request_key.stderr)
                self.assertEqual(chain.rpc(running["rpc_http"], "eth_blockNumber"), before)
                local_state.write_private(request_key, request_secret)
                self.assertFalse(permitted())
                environment = contracts.tool_environment()
                environment["AGENTKEYS_CHAIN_PROFILE_FILE"] = deployed["profile"]
                denied = subprocess.run([str(owner.executable(REPOSITORY)), "chain", "prepare-owner", "register",
                    "--operator-omni", operator, "--key-file", str(state / "forbidden.pem"),
                    "--device-key-file", str(state / "forbidden-device.key"),
                    "--beneficiary", registered["account"]], env=environment, capture_output=True, text=True, timeout=15)
                self.assertNotEqual(denied.returncode, 0)
                self.assertFalse((state / "forbidden.pem").exists())
                self.assertFalse((state / "forbidden-device.key").exists())
            finally:
                self.invoke(state, "stop")


if __name__ == "__main__":
    unittest.main()
