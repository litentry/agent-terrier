import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local import chain, local_state


class LocalStateTests(unittest.TestCase):
    def test_owner_only_state_roundtrip_and_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            state = local_state.private_directory(Path(directory) / "state")
            record = state / "record.json"
            local_state.write_json(record, {"development_only": True})
            self.assertEqual(record.stat().st_mode & 0o777, 0o600)
            self.assertEqual(local_state.read_json(record), {"development_only": True})
            with local_state.exclusive_lock(state / "lock"):
                with self.assertRaisesRegex(RuntimeError, "Another local operation"):
                    with local_state.exclusive_lock(state / "lock"):
                        self.fail("Concurrent writer acquired state")

    def test_insecure_files_and_links_fail_without_modification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = root / "record"
            record.write_text("preserve")
            record.chmod(0o644)
            with self.assertRaises(ValueError):
                local_state.write_private(record, b"changed")
            record.chmod(0o600)
            link = root / "link"
            link.symlink_to(record)
            with self.assertRaises(OSError):
                local_state.write_private(link, b"changed")
            link.unlink()
            os.link(record, link)
            with self.assertRaises(ValueError):
                local_state.write_private(record, b"changed")
            self.assertEqual(record.read_text(), "preserve")
            pipe = root / "pipe"
            os.mkfifo(pipe, 0o600)
            with self.assertRaises(ValueError):
                local_state.open_private(pipe)

    def test_state_cannot_live_in_the_source_or_an_insecure_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "source"
            repository.mkdir()
            with mock.patch.dict(os.environ, {"AGENT_TERRIER_STATE_DIR": str(repository / "runtime")}):
                with self.assertRaisesRegex(ValueError, "outside"):
                    local_state.state_directory(repository)
            insecure = Path(directory) / "insecure"
            insecure.mkdir(mode=0o755)
            with self.assertRaisesRegex(ValueError, "owner-only"):
                local_state.private_directory(insecure)


class ChainBoundaryTests(unittest.TestCase):
    def test_node_handshake_requires_matching_instance_chain_and_no_accounts(self):
        metadata = {"chainId": 31337, "clientVersion": "anvil/test", "instanceId": "0x" + "a" * 64}
        with mock.patch.object(chain, "rpc", side_effect=[metadata, "0x7a69", []]):
            self.assertEqual(chain.node_identity("endpoint", 31337), metadata["instanceId"])
        invalid_metadata = [
            {**metadata, "chainId": 1}, {**metadata, "clientVersion": "unrelated/test"},
            {**metadata, "instanceId": "0x" + "b" * 64},
            {**metadata, "forkedNetwork": {"chainId": 1}},
        ]
        for invalid in invalid_metadata:
            with mock.patch.object(chain, "rpc", return_value=invalid) as request:
                with self.assertRaisesRegex(ValueError, "identity"):
                    chain.node_identity("endpoint", 31337, metadata["instanceId"])
                self.assertEqual(request.call_count, 1)
        for chain_id, accounts in [("0x1", []), ("0x7a69", ["unlocked-account"])]:
            with mock.patch.object(chain, "rpc", side_effect=[metadata, chain_id, accounts]):
                with self.assertRaisesRegex(ValueError, "no unlocked accounts"):
                    chain.node_identity("endpoint", 31337)

    def test_nonlocal_rpc_is_rejected_before_network_access(self):
        for endpoint in ["https://example.test:8545", "http://127.0.0.1.example.test:8545",
                         "http://user:password@127.0.0.1:8545", "http://127.0.0.1:8545?rpc=remote",
                         "http://localhost:8545", "http://127.0.0.1:8545/remote"]:
            with mock.patch.object(chain.urllib.request, "build_opener") as opener:
                with self.assertRaises(ValueError):
                    chain.rpc(endpoint, "eth_chainId")
                opener.assert_not_called()

    def test_control_never_signals_a_pid_or_removes_foreign_socket_files(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            self.assertEqual(chain.stop(state), {"running": False})
            control_path = state / chain.SOCKET_NAME
            control_path.write_text("preserve")
            with self.assertRaises(ValueError):
                chain.stop(state)
            self.assertEqual(control_path.read_text(), "preserve")

    def test_existing_chain_reuse_and_port_mismatch(self):
        current = {"running": True, "rpc_http": "http://127.0.0.1:12345"}
        with mock.patch.object(chain, "default_profile", return_value={"rpc": {"http": "http://localhost:8545"}}):
            with mock.patch.object(chain, "status", return_value=current):
                with mock.patch.object(chain.subprocess, "Popen") as spawn:
                    self.assertEqual(chain.start(Path("."), Path(".")), current)
                    with self.assertRaisesRegex(ValueError, "different port"):
                        chain.start(Path("."), Path("."), 12346)
                    spawn.assert_not_called()
