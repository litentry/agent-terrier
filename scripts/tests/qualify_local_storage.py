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
from terrier_local import contracts, test_lanes


class LocalStorageFixture(LocalOwnerFixture):
    device = qualify_local_binding.LocalBindingTests.device

    def qualify(self, package, target, test_name, service, database, worker_package=None):
        build = subprocess.run(["cargo", "test", "--offline", "-p", package,
            "--test", target, "--no-run", "--message-format=json"],
            cwd=REPOSITORY, env=contracts.tool_environment(), capture_output=True, text=True, timeout=900)
        self.assertEqual(build.returncode, 0, build.stderr)
        artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith("{")]
        binaries = [item["executable"] for item in artifacts if item.get("reason") == "compiler-artifact"
                    and item.get("target", {}).get("name") == target and item.get("executable")]
        self.assertEqual(len(binaries), 1)
        worker_binary = None
        if worker_package:
            build = subprocess.run(["cargo", "build", "--offline", "-p", worker_package, "--message-format=json"],
                cwd=REPOSITORY, env=contracts.tool_environment(), capture_output=True, text=True, timeout=900)
            self.assertEqual(build.returncode, 0, build.stderr)
            artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith("{")]
            workers = [item["executable"] for item in artifacts if item.get("reason") == "compiler-artifact"
                       and item.get("target", {}).get("name") == worker_package and item.get("executable")]
            self.assertEqual(len(workers), 1)
            worker_binary = workers[0]
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
                           "--service", service)
                environment = contracts.tool_environment()
                environment.update({
                    "AGENT_TERRIER_QUALIFICATION_PROFILE": deployed["profile"],
                    "AGENT_TERRIER_QUALIFICATION_STORE": str(storage),
                    "AGENT_TERRIER_QUALIFICATION_OWNER_KEY": str(state / "owners/alice/device.key"),
                    "AGENT_TERRIER_QUALIFICATION_DEVICE_KEY": str(state / "devices/writer/device.key"),
                    "AGENT_TERRIER_QUALIFICATION_ENROLLMENT": enrollment_file,
                    "AGENT_TERRIER_QUALIFICATION_OPERATOR": owner["operator_omni"],
                })

                if worker_binary:
                    environment["AGENT_TERRIER_QUALIFICATION_WORKER"] = worker_binary

                def qualify(phase):
                    environment["AGENT_TERRIER_QUALIFICATION_PHASE"] = phase
                    result = subprocess.run([binaries[0], "--ignored", "--exact", test_name],
                        env=environment, capture_output=True, text=True, timeout=120)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    counted = test_lanes.rust_counts({"status": "passed"}, result.stdout + result.stderr)
                    self.assertEqual(counted["status"], "passed", "selected real-chain test did not execute")

                qualify("active")
                self.owner(state, "revoke", "--name", "alice", "--actor-omni", identity["enrollment"]["actor_omni"])
                qualify("scope_revoked")
                self.owner(state, "grant", "--name", "alice", "--actor-omni", identity["enrollment"]["actor_omni"],
                           "--service", service)
                self.owner(state, "unbind", "--name", "alice", "--enrollment-file", enrollment_file)
                qualify("device_revoked")
                if database is not None:
                    self.assertEqual(os.stat(storage / database).st_mode & 0o777, 0o600)
            finally:
                self.invoke(state, "stop")


class LocalStorageTests(LocalStorageFixture):
    def test_real_contract_authority_and_storage_persistence(self):
        self.qualify("agentkeys-local-store", "local_chain", "real_chain_storage_authority", "knowledge:notes", "memory.db")


if __name__ == "__main__":
    unittest.main()
