"""Real actor key custody, owner-signed binding and atomic revocation."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from qualify_local_owner import LocalOwnerFixture
from qualify_local_chain import REPOSITORY, available_port
from terrier_local import chain, contracts, local_state


class LocalBindingTests(LocalOwnerFixture):
    def device(self, state, operator, label, kind, success=True):
        environment = contracts.tool_environment()
        environment["AGENT_TERRIER_STATE_DIR"] = str(state)
        result = subprocess.run([sys.executable, str(REPOSITORY / "terrier"), "device", "identity",
            "--name", label, "--operator-omni", operator, "--label", label, "--kind", kind],
            env=environment, capture_output=True, text=True, timeout=30)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0)
        return result

    def test_bind_proof_owner_scope_revocation_and_restart(self):
        with tempfile.TemporaryDirectory(prefix="terrier-binding-", dir="/tmp") as temporary:
            state = Path(temporary).resolve() / "state"
            port = available_port()
            try:
                running = self.invoke(state, "start", "--port", str(port))
                deployed = self.invoke(state, "deploy", "--offline")
                alice = self.owner(state, "register", "--name", "alice")
                bob = self.owner(state, "register", "--name", "bob")
                operator = alice["operator_omni"]
                profile = local_state.read_json(Path(deployed["profile"]))
                addresses = {item["name"]:item["address"] for item in profile["contracts"]}

                def cast(*arguments):
                    return subprocess.check_output([contracts.foundry_binary("cast"), *arguments],
                        env=contracts.tool_environment(), text=True).strip()

                def device_record(enrollment):
                    calldata = cast("calldata", "getDevice(bytes32)", enrollment["device_key_hash"])
                    raw = chain.rpc(running["rpc_http"], "eth_call", [{"to":addresses["SidecarRegistry"], "data":calldata}, "latest"])
                    words = [raw.removeprefix("0x")[offset:offset+64] for offset in range(0, 11*64, 64)]
                    return {"operator":"0x"+words[0], "actor":"0x"+words[1], "tier":int(words[6], 16),
                            "registered":int(words[8], 16) > 0, "revoked":int(words[10], 16) == 1}

                def permitted(enrollment, service):
                    return cast("call", addresses["AgentKeysScope"], "isServiceInScope(bytes32,bytes32,bytes32)(bool)",
                        operator, enrollment["actor_omni"], cast("keccak", service), "--rpc-url", running["rpc_http"]) == "true"

                def slots():
                    return int(cast("call", addresses["SidecarRegistry"], "agentSlotsUsed(bytes32)(uint16)",
                                    operator, "--rpc-url", running["rpc_http"]))

                for label, kind, service, tier in [("local-agent", "delegate", "knowledge:example", 2),
                                                   ("local-display", "device", "channel-sub:example", 3)]:
                    created = self.device(state, operator, label, kind)
                    enrollment = created["enrollment"]
                    artifact = Path(created["enrollment_file"])
                    key_path = state / "devices" / label / "device.key"
                    private_key = key_path.read_text()
                    self.assertNotIn(private_key.removeprefix("0x"), json.dumps(created))
                    self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(self.device(state, operator, label, kind)["enrollment"], enrollment)
                    self.device(state, bob["operator_omni"], label, kind, success=False)
                    self.assertEqual(key_path.read_text(), private_key)
                    before = chain.rpc(running["rpc_http"], "eth_blockNumber")
                    corrupted = dict(enrollment, device_key_hash="0x"+"56"*32)
                    local_state.write_json(artifact, corrupted)
                    denied = self.owner(state, "bind", "--name", "alice", "--enrollment-file", str(artifact),
                                        "--service", service, success=False)
                    self.assertIn("proof does not match", denied.stderr)
                    self.assertEqual(chain.rpc(running["rpc_http"], "eth_blockNumber"), before)
                    self.assertFalse(device_record(enrollment)["registered"])
                    self.assertFalse(permitted(enrollment, service))
                    local_state.write_json(artifact, enrollment)
                    denied = self.owner(state, "bind", "--name", "bob", "--enrollment-file", str(artifact),
                                        "--service", service, success=False)
                    self.assertIn("not this owner's child", denied.stderr)
                    self.assertEqual(chain.rpc(running["rpc_http"], "eth_blockNumber"), before)
                    if kind == "device":
                        denied = self.owner(state, "bind", "--name", "alice", "--enrollment-file", str(artifact),
                                            "--service", "knowledge:forbidden", success=False)
                        self.assertIn("only channel grants", denied.stderr)
                        self.assertFalse(permitted(enrollment, "knowledge:forbidden"))
                    bound = self.owner(state, "bind", "--name", "alice", "--enrollment-file", str(artifact), "--service", service)
                    self.assertTrue(bound["verified"])
                    self.assertEqual(device_record(enrollment), {"operator":operator, "actor":enrollment["actor_omni"],
                        "tier":tier, "registered":True, "revoked":False})
                    self.assertTrue(permitted(enrollment, service))
                    self.assertEqual(slots(), 1 if kind == "delegate" else 0)
                    before = chain.rpc(running["rpc_http"], "eth_blockNumber")
                    self.owner(state, "bind", "--name", "alice", "--enrollment-file", str(artifact), "--service", service, success=False)
                    self.owner(state, "unbind", "--name", "bob", "--enrollment-file", str(artifact), success=False)
                    self.assertEqual(chain.rpc(running["rpc_http"], "eth_blockNumber"), before)
                    self.assertTrue(permitted(enrollment, service))
                    if kind == "delegate":
                        self.owner(state, "revoke", "--name", "alice", "--actor-omni", enrollment["actor_omni"])
                        self.assertFalse(permitted(enrollment, service))
                    revoked = self.owner(state, "unbind", "--name", "alice", "--enrollment-file", str(artifact))
                    self.assertTrue(revoked["verified"])
                    self.assertTrue(device_record(enrollment)["revoked"])
                    self.assertFalse(permitted(enrollment, service))
                    self.assertEqual(slots(), 0)
                    self.assertEqual(key_path.read_text(), private_key)
                    self.invoke(state, "stop")
                    self.invoke(state, "start", "--port", str(port))
                    self.assertTrue(device_record(enrollment)["revoked"])
                    self.assertFalse(permitted(enrollment, service))
                    key_path.unlink()
                    missing = self.device(state, operator, label, kind, success=False)
                    self.assertIn("original key", missing.stderr)
                    self.assertFalse(key_path.exists())
            finally:
                self.invoke(state, "stop")


if __name__ == "__main__":
    unittest.main()
