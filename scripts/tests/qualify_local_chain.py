"""Real local chain acceptance; run explicitly with Foundry installed."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local import chain, contracts, deployment, local_state

REPOSITORY = Path(__file__).resolve().parents[2]


def available_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class RealChainTests(unittest.TestCase):
    def invoke(self, state, *arguments, success=True, forge=None):
        environment = contracts.tool_environment()
        environment["AGENT_TERRIER_STATE_DIR"] = str(state)
        if os.environ.get("AGENT_TERRIER_CACHE_DIR"):
            environment["AGENT_TERRIER_CACHE_DIR"] = os.environ["AGENT_TERRIER_CACHE_DIR"]
        if forge:
            environment["AGENT_TERRIER_FORGE"] = str(forge)
        result = subprocess.run([sys.executable, str(REPOSITORY / "terrier"), "chain", *arguments],
                                env=environment, capture_output=True, text=True, timeout=200)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0)
        return result

    def test_real_node_restart_preserves_state_and_other_nodes_are_untouched(self):
        with tempfile.TemporaryDirectory(prefix="terrier-chain-", dir="/tmp") as directory:
            state = Path(directory).resolve() / "state"
            other_state = Path(directory).resolve() / "other"
            port = available_port()
            try:
                started = self.invoke(state, "start", "--port", str(port))
                self.assertTrue(started["running"])
                self.assertEqual(chain.rpc(started["rpc_http"], "eth_accounts"), [])
                reused = self.invoke(state, "start")
                self.assertEqual(started["instance_id"], reused["instance_id"])
                chain.rpc(started["rpc_http"], "evm_mine")
                block_number = chain.rpc(started["rpc_http"], "eth_blockNumber")
                self.invoke(other_state, "start", "--port", str(port), success=False)
                self.assertFalse(self.invoke(other_state, "stop")["running"])
                self.assertEqual(self.invoke(state, "status")["instance_id"], started["instance_id"])
                stopped = self.invoke(state, "stop")
                self.assertTrue(stopped["state_saved"])
                self.assertEqual((state / "chain/state.json").stat().st_mode & 0o777, 0o600)
                restarted = self.invoke(state, "start", "--port", str(port))
                self.assertNotEqual(started["instance_id"], restarted["instance_id"])
                self.assertEqual(chain.rpc(restarted["rpc_http"], "eth_blockNumber"), block_number)
                self.assertEqual(chain.rpc(restarted["rpc_http"], "eth_accounts"), [])
            finally:
                self.invoke(state, "stop")
                self.invoke(other_state, "stop")

    def test_completed_transactions_resume_after_process_failure_without_redeploying(self):
        with tempfile.TemporaryDirectory(prefix="terrier-resume-", dir="/tmp") as directory:
            state = Path(directory).resolve() / "state"
            wrapper = Path(directory) / "forge-failure"
            wrapper.write_text(f"#!{sys.executable}\nimport subprocess, sys\n"
                               f"result = subprocess.run([{contracts.foundry_binary('forge')!r}, *sys.argv[1:]])\n"
                               "sys.exit(result.returncode or 23)\n")
            wrapper.chmod(0o700)
            try:
                started = self.invoke(state, "start", "--port", str(available_port()))
                failed = self.invoke(state, "deploy", "--offline", success=False, forge=wrapper)
                self.assertIn("explicitly resume", failed.stderr)
                self.assertFalse((state / "chain-profile.json").exists())
                before = chain.rpc(started["rpc_http"], "eth_blockNumber")
                self.invoke(state, "deploy", "--offline", success=False)
                resumed = self.invoke(state, "deploy", "--offline", "--resume")
                self.assertTrue(resumed["verified"])
                self.assertFalse((state / "deployment/pending.json").exists())
                self.assertEqual(chain.rpc(started["rpc_http"], "eth_blockNumber"), before)
            except AssertionError:
                chain.logs(state)
                raise
            finally:
                self.invoke(state, "stop")

    def test_real_deployment_is_signed_versioned_and_idempotent(self):
        with tempfile.TemporaryDirectory(prefix="terrier-deploy-", dir="/tmp") as directory:
            state = Path(directory).resolve() / "state"
            port = available_port()
            try:
                started = self.invoke(state, "start", "--port", str(port))
                deployed = self.invoke(state, "deploy", "--offline")
                self.assertTrue(deployed["deployed"])
                profile = local_state.read_json(Path(deployed["profile"]))
                fixture = json.loads((REPOSITORY / "e2e/fixtures/chain-profiles/local-test.json").read_text())
                self.assertEqual({item["name"] for item in profile["contracts"]},
                                 {item["name"] for item in fixture["contracts"]})
                self.assertEqual(chain.rpc(started["rpc_http"], "eth_accounts"), [])
                self.verify_contract_wiring_and_signed_authority(state, started["rpc_http"], profile)
                block_number = chain.rpc(started["rpc_http"], "eth_blockNumber")
                self.assertFalse(self.invoke(state, "deploy", "--offline")["deployed"])
                self.assertEqual(chain.rpc(started["rpc_http"], "eth_blockNumber"), block_number)
                for path in (state / "deployer").iterdir():
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                with os.fdopen(local_state.open_private(state / "deployer/password")) as secret_file:
                    passphrase = secret_file.read()
                logs = b"".join(path.read_bytes() for path in state.glob("*.log"))
                self.assertNotIn(passphrase.encode(), logs)
                profile["contract_set_version"] = "different-version"
                local_state.write_json(Path(deployed["profile"]), profile)
                self.invoke(state, "deploy", "--offline", success=False)
                self.assertEqual(chain.rpc(started["rpc_http"], "eth_blockNumber"), block_number)
                profile["contract_set_version"] = deployed["version"]
                local_state.write_json(Path(deployed["profile"]), profile)
                self.invoke(state, "stop")
                self.invoke(state, "start", "--port", str(port))
                self.assertFalse(self.invoke(state, "deploy", "--offline")["deployed"])
            except AssertionError:
                chain.logs(state)
                raise
            finally:
                self.invoke(state, "stop")

    def verify_contract_wiring_and_signed_authority(self, state, endpoint, profile):
        registry = {item["name"]: item["address"] for item in profile["contracts"]}

        def cast(*arguments):
            return subprocess.run([contracts.foundry_binary("cast"), *arguments, "--rpc-url", endpoint],
                                  env=contracts.tool_environment(), capture_output=True, text=True, timeout=30)

        for source, getter, target in [
            ("P256Router", "fallbackVerifier", "P256Verifier"),
            ("K11Verifier", "p256", "P256Router"),
            ("SidecarRegistry", "k11Verifier", "K11Verifier"),
            ("AgentKeysScope", "registry", "SidecarRegistry"),
            ("CredentialAudit", "registry", "SidecarRegistry"),
            ("P256AccountFactory", "entryPoint", "EntryPoint"),
            ("P256AccountFactory", "k11Verifier", "K11Verifier"),
            ("VerifyingPaymaster", "entryPoint", "EntryPoint"),
        ]:
            result = cast("call", registry[source], f"{getter}()(address)")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip().lower(), registry[target].lower())
        counter = registry["K3EpochCounter"]
        _, owner_key, owner_password = deployment.developer_wallet(state)
        authorized = cast("send", counter, "advanceEpoch()", "--keystore", str(owner_key),
                          "--password-file", str(owner_password), "--json")
        self.assertEqual(authorized.returncode, 0, authorized.stderr)
        self.assertEqual(json.loads(authorized.stdout)["status"], "0x1")
        unauthorized_state = local_state.private_directory(state / "unauthorized-test-actor")
        outsider, outsider_key, outsider_password = deployment.developer_wallet(unauthorized_state)
        chain.rpc(endpoint, "anvil_setBalance", [outsider, hex(deployment.DEPLOYMENT_BALANCE_WEI)])
        before = cast("call", counter, "currentEpoch()(uint256)")
        denied = cast("send", counter, "advanceEpoch()", "--keystore", str(outsider_key),
                      "--password-file", str(outsider_password), "--gas-limit", "200000", "--json")
        self.assertEqual(json.loads(denied.stdout)["status"], "0x0")
        latest = chain.rpc(endpoint, "eth_getBlockByNumber", ["latest", False])
        receipt = chain.rpc(endpoint, "eth_getTransactionReceipt", [latest["transactions"][0]])
        self.assertEqual(receipt["from"].lower(), outsider.lower())
        self.assertEqual(receipt["to"].lower(), counter.lower())
        self.assertEqual(receipt["status"], "0x0")
        self.assertEqual(cast("call", counter, "currentEpoch()(uint256)").stdout, before.stdout)


if __name__ == "__main__":
    unittest.main()
