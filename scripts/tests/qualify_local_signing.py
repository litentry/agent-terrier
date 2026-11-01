"""Real P-256 CLI assertions verified by the deployed local contracts."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import qualify_local_chain as chain_suite
from terrier_local import chain, contracts, local_state


class RealSigningTests(chain_suite.LocalChainFixture):
    def test_cli_assertion_is_accepted_and_wrong_key_or_challenge_is_rejected_on_chain(self):
        executable = Path(os.environ.get("AGENT_TERRIER_CLI", chain_suite.REPOSITORY / "target/debug/agentkeys"))
        self.assertTrue(executable.is_file(), "Build agentkeys-cli or set AGENT_TERRIER_CLI first")
        with tempfile.TemporaryDirectory(prefix="terrier-sign-", dir="/tmp") as directory:
            state = Path(directory).resolve() / "state"
            try:
                running = self.invoke(state, "start", "--port", str(chain_suite.available_port()))
                deployed = self.invoke(state, "deploy", "--offline")
                profile = local_state.read_json(Path(deployed["profile"]))
                verifier = next(item["address"] for item in profile["contracts"] if item["name"] == "K11Verifier")
                environment = contracts.tool_environment()
                environment.update({"AGENT_TERRIER_LOCAL_DEV": "1", "AGENTKEYS_CHAIN_PROFILE_FILE": deployed["profile"]})
                key_path = state / "passkey.pem"

                def cli(*arguments):
                    result = subprocess.run([str(executable), "k11", *arguments], env=environment,
                                            capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotIn("PRIVATE KEY", result.stdout + result.stderr)
                    return dict(line.split("=", 1) for line in result.stdout.splitlines())

                public = cli("software-keygen", "--key-file", str(key_path))
                challenge = "0x" + hashlib.sha256(b"local signing acceptance").hexdigest()
                assertion = cli("software-sign", "--key-file", str(key_path), "--userop-hash", challenge)
                signature = "verifyAssertion(bytes32,bytes32,bytes,bytes,uint256,uint256,uint256,uint256,uint256)(bool)"

                def verify(expected_challenge, key):
                    return subprocess.run([
                        contracts.foundry_binary("cast"), "call", verifier, signature, expected_challenge,
                        public["RPIDHASH"], assertion["AUTHDATA"], assertion["CDJ"], assertion["CHALLENGE_LOC"],
                        assertion["R"], assertion["S"], key["PUBX"], key["PUBY"], "--rpc-url", running["rpc_http"],
                    ], env=contracts.tool_environment(), capture_output=True, text=True, timeout=15)

                before = chain.rpc(running["rpc_http"], "eth_blockNumber")
                accepted = verify(challenge, public)
                self.assertEqual(accepted.returncode, 0, accepted.stderr)
                self.assertEqual(accepted.stdout.strip(), "true")
                wrong_key = cli("software-keygen", "--key-file", str(state / "other-passkey.pem"))
                rejected = verify(challenge, wrong_key)
                self.assertEqual(rejected.returncode, 0, rejected.stderr)
                self.assertEqual(rejected.stdout.strip(), "false")
                wrong_challenge = "0x" + hashlib.sha256(b"tampered signing challenge").hexdigest()
                self.assertNotEqual(verify(wrong_challenge, public).returncode, 0)
                self.assertEqual(chain.rpc(running["rpc_http"], "eth_blockNumber"), before)
                self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
            finally:
                self.invoke(state, "stop")


if __name__ == "__main__":
    unittest.main()
