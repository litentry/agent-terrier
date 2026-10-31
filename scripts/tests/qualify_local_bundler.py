"""Actual owner-signed operations through the supervised local transaction service."""
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

from qualify_local_chain import REPOSITORY, available_port
from qualify_local_login import request
from qualify_local_owner import LocalOwnerFixture
import qualify_local_services
from terrier_local import chain, contracts, local_state, owner


class LocalBundlerQualification(LocalOwnerFixture):
    services = qualify_local_services.LocalServicesQualification.services

    def test_real_signed_operations_denials_and_persistent_submitter(self):
        with tempfile.TemporaryDirectory(prefix="terrier-bundler-", dir="/tmp") as temporary:
            state = Path(temporary).resolve() / "state"
            try:
                node = self.invoke(state, "start", "--port", str(available_port()))
                self.invoke(state, "deploy", "--offline")
                running = self.services(state, "start")
                endpoint = running["services"]["bundler"]["url"]
                profile_path = state / "chain-profile.json"
                profile = local_state.read_json(profile_path)
                key_path = state / "services/bundler/submitter.key"
                original = key_path.read_bytes()
                binary = REPOSITORY / "target/debug/agentkeys-bundler"
                base = [str(binary), "--development", "--profile", str(profile_path)]
                address_result = subprocess.run([*base, "--signer-key-file", str(key_path), "address"],
                    env=contracts.tool_environment(), capture_output=True, text=True, timeout=10)
                self.assertEqual(address_result.returncode, 0, address_result.stderr)
                submitter = json.loads(address_result.stdout)["address"]
                repeated = subprocess.run([*base, "keygen", "--out", str(key_path)],
                    env=contracts.tool_environment(), capture_output=True, timeout=10)
                self.assertNotEqual(repeated.returncode, 0)
                self.assertTrue(key_path.read_bytes() == original, "key generation replaced the submitter")
                for arguments in ([*base, "--bind", "0.0.0.0:0", "--signer-key-file", str(key_path)],
                                  [*base, "--signer-key-file", str(state / "missing.key")]):
                    result = subprocess.run(arguments, env=contracts.tool_environment(), capture_output=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertTrue(original.removeprefix(b"0x") not in result.stdout + result.stderr, "startup output exposed signing material")
                remote_profile = state / "remote-profile.json"
                local_state.write_json(remote_profile, dict(profile, rpc={"http":"https://rpc.example", "wss":"wss://rpc.example"}))
                refused = subprocess.run([str(binary), "--development", "--profile", str(remote_profile),
                    "keygen", "--out", str(state / "forbidden.key")], env=contracts.tool_environment(), capture_output=True, timeout=10)
                self.assertNotEqual(refused.returncode, 0)
                self.assertFalse((state / "forbidden.key").exists())
                chain.rpc(node["rpc_http"], "anvil_setBalance", [submitter, "0x0"])
                self.assertFalse(json.loads(request(endpoint + "/healthz")[1])["ready"])
                doctor = self.services(state, "doctor", success=False)
                self.assertFalse(json.loads(doctor.stdout)["services"]["bundler"]["healthy"])
                chain.rpc(node["rpc_http"], "anvil_setBalance", [submitter, hex(int(profile["funding"]["account_deposit_wei"]))])
                self.assertTrue(self.services(state, "doctor")["ready"])
                alice = self.owner(state, "register", "--name", "alice")
                actor = "0x" + "45" * 32
                service = "knowledge:bundler-qualification"
                scope = next(item["address"] for item in profile["contracts"] if item["name"] == "AgentKeysScope")
                service_hash = subprocess.check_output([contracts.foundry_binary("cast"), "keccak", service],
                    env=contracts.tool_environment(), text=True).strip()

                def permitted():
                    result = subprocess.check_output([contracts.foundry_binary("cast"), "call", scope,
                        "isServiceInScope(bytes32,bytes32,bytes32)(bool)", alice["operator_omni"], actor, service_hash,
                        "--rpc-url", node["rpc_http"]], env=contracts.tool_environment(), text=True)
                    return result.strip() == "true"

                def prepare(action):
                    arguments = ["prepare-owner", action, "--operator-omni", alice["operator_omni"],
                        "--key-file", str(state / "owners/alice/passkey.pem"),
                        "--device-key-file", str(state / "owners/alice/device.key"),
                        "--beneficiary", submitter, "--actor-omni", actor]
                    if action == "grant":
                        arguments.extend(["--service", service])
                    return owner.run_cli(REPOSITORY, profile_path, arguments)

                def submit(plan, signature=None):
                    operation = dict(plan["rpc_user_op"])
                    if signature is not None:
                        operation["signature"] = signature
                    operation_hash = chain.rpc(endpoint, "eth_sendUserOperation", [operation, plan["build"]["entry_point"]])
                    self.assertEqual(operation_hash, plan["build"]["user_op_hash"])
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        receipt = chain.rpc(endpoint, "eth_getUserOperationReceipt", [operation_hash])
                        if receipt is not None:
                            return receipt
                        time.sleep(0.05)
                    self.fail("transaction service did not report a receipt")

                self.assertFalse(permitted())
                plan = prepare("grant")
                altered = bytearray.fromhex(plan["rpc_user_op"]["signature"].removeprefix("0x"))
                altered[159] ^= 1
                denied = submit(plan, "0x" + altered.hex())
                self.assertFalse(denied["success"])
                self.assertEqual(denied["receipt"]["status"], "0x0")
                self.assertFalse(permitted(), "unauthorized operation changed the grant")
                accepted = submit(plan)
                self.assertTrue(accepted["success"])
                verified = owner.run_cli(REPOSITORY, profile_path,
                    ["verify-owner", "--transaction", accepted["receipt"]["transactionHash"]], json.dumps(plan))
                self.assertTrue(verified["verified"])
                self.assertTrue(permitted())
                self.services(state, "stop")
                running = self.services(state, "start")
                endpoint = running["services"]["bundler"]["url"]
                self.assertTrue(key_path.read_bytes() == original, "restart changed the submitter")
                self.assertTrue(permitted())
                self.assertTrue(submit(prepare("revoke"))["success"])
                self.assertFalse(permitted())
                logs = b"".join(path.read_bytes() for path in (state / "services").glob("*.log"))
                self.assertTrue(original.removeprefix(b"0x") not in logs, "service logs exposed signing material")
            finally:
                self.services(state, "stop")
                self.invoke(state, "stop")


if __name__ == "__main__":
    unittest.main()
