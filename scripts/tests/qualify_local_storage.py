"""Explicit qualification of the local object service against real contracts."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from qualify_local_owner import LocalOwnerFixture
from qualify_local_chain import REPOSITORY, available_port
import qualify_local_binding
from terrier_local import contracts


class LocalStorageTests(LocalOwnerFixture):
    device = qualify_local_binding.LocalBindingTests.device

    def test_real_contract_authority_and_storage_persistence(self):
        build = subprocess.run(["cargo", "test", "--offline", "-p", "agentkeys-local-store",
            "--test", "local_chain", "--no-run", "--message-format=json"],
            cwd=REPOSITORY, env=contracts.tool_environment(), capture_output=True, text=True, timeout=900)
        self.assertEqual(build.returncode, 0, build.stderr)
        artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith("{")]
        binaries = [item["executable"] for item in artifacts if item.get("reason") == "compiler-artifact"
                    and item.get("target", {}).get("name") == "local_chain" and item.get("executable")]
        self.assertEqual(len(binaries), 1)
        with tempfile.TemporaryDirectory(prefix="terrier-storage-", dir="/tmp") as temporary:
            root = Path(temporary).resolve()
            state = root / "state"
            storage = root / "storage"
            storage.mkdir(mode=0o700)
            try:
                self.invoke(state, "start", "--port", str(available_port()))
                deployed = self.invoke(state, "deploy", "--offline")
                owner = self.owner(state, "register", "--name", "alice")
                identity = self.device(state, owner["operator_omni"], "writer", "delegate")
                enrollment_file = identity["enrollment_file"]
                self.owner(state, "bind", "--name", "alice", "--enrollment-file", enrollment_file,
                           "--service", "knowledge:notes")
                environment = contracts.tool_environment()
                environment.update({
                    "AGENT_TERRIER_QUALIFICATION_PROFILE": deployed["profile"],
                    "AGENT_TERRIER_QUALIFICATION_STORE": str(storage),
                    "AGENT_TERRIER_QUALIFICATION_DEVICE_KEY": str(state / "devices/writer/device.key"),
                    "AGENT_TERRIER_QUALIFICATION_ENROLLMENT": enrollment_file,
                    "AGENT_TERRIER_QUALIFICATION_OPERATOR": owner["operator_omni"],
                })

                def qualify(phase):
                    environment["AGENT_TERRIER_QUALIFICATION_PHASE"] = phase
                    result = subprocess.run([binaries[0], "--ignored", "--exact", "real_chain_storage_authority"],
                        env=environment, capture_output=True, text=True, timeout=120)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

                qualify("active")
                self.owner(state, "revoke", "--name", "alice", "--actor-omni", identity["enrollment"]["actor_omni"])
                qualify("scope_revoked")
                self.owner(state, "grant", "--name", "alice", "--actor-omni", identity["enrollment"]["actor_omni"],
                           "--service", "knowledge:notes")
                self.owner(state, "unbind", "--name", "alice", "--enrollment-file", enrollment_file)
                qualify("device_revoked")
                self.assertEqual(os.stat(storage / "memory.db").st_mode & 0o777, 0o600)
            finally:
                self.invoke(state, "stop")


if __name__ == "__main__":
    unittest.main()
