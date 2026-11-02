import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local import chain, deployment, local_state, reset, services

REPOSITORY = Path(__file__).resolve().parents[2]


class ResetTests(unittest.TestCase):
    def prepare(self, directory):
        state = local_state.private_directory(Path(directory).resolve() / "state")
        profile = chain.default_profile(REPOSITORY)
        profile["rpc"]["http"] = "http://127.0.0.1:12345"
        profile["contracts"] = []
        local_state.write_json(state / "chain-profile.json", profile)
        local_state.private_directory(state / "owners")
        local_state.write_private(state / "owners/synthetic.key", b"synthetic-private-state")
        return state

    def test_exact_confirmation_and_validated_tree_precede_shutdown_or_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.prepare(directory)
            original = (state / "owners/synthetic.key").read_bytes()
            with mock.patch.object(reset.stack, "stop") as stop:
                for confirmation in [None, Path("state"), state.parent, state / "other"]:
                    with self.assertRaisesRegex(ValueError, "confirm-state"):
                        reset.execute(REPOSITORY, state, confirmation)
                (state / "unexpected").write_text("unrelated")
                with self.assertRaisesRegex(ValueError, "unrecognized"):
                    reset.execute(REPOSITORY, state, state)
                (state / "unexpected").unlink()
                foreign = Path(directory) / "foreign"
                foreign.write_text("unrelated")
                for link in ["symbolic", "hard"]:
                    path = state / "owners/linked"
                    path.symlink_to(foreign) if link == "symbolic" else os.link(foreign, path)
                    with self.assertRaises(ValueError):
                        reset.execute(REPOSITORY, state, state)
                    self.assertEqual(foreign.read_text(), "unrelated")
                    path.unlink()
                stop.assert_not_called()
                self.assertEqual((state / "owners/synthetic.key").read_bytes(), original)

    def test_uncertain_shutdown_preserves_keys_and_success_preserves_other_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.prepare(directory)
            foreign = Path(directory) / "other-state"
            foreign.mkdir()
            (foreign / "sentinel").write_text("keep")
            with mock.patch.object(reset.stack, "stop", side_effect=RuntimeError("unconfirmed shutdown")):
                with self.assertRaisesRegex(RuntimeError, "unconfirmed"):
                    reset.execute(REPOSITORY, state, state)
            self.assertTrue((state / "owners/synthetic.key").exists())
            with mock.patch.object(reset.stack, "stop", return_value={"success":True}):
                with local_state.exclusive_lock(state / "operation.lock"):
                    receipt = reset.execute(REPOSITORY, state, state)
                self.assertTrue(receipt["success"])
                self.assertFalse(receipt["state_preserved"])
                self.assertEqual({path.name for path in state.iterdir()}, reset.LOCKS)
                self.assertTrue(reset.execute(REPOSITORY, state, state)["success"])
            self.assertEqual((foreign / "sentinel").read_text(), "keep")

    def test_existing_controller_lock_prevents_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.prepare(directory)
            with mock.patch.object(reset.stack, "stop"), mock.patch.object(reset.services, "STOP_TIMEOUT", 0), \
                    local_state.exclusive_lock(state / "chain.lock"):
                with self.assertRaisesRegex(RuntimeError, "owns this state"):
                    reset.execute(REPOSITORY, state, state)
                self.assertTrue((state / "owners/synthetic.key").exists())

    def test_nonlocal_profile_is_refused_before_shutdown(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.prepare(directory)
            profile = local_state.read_json(state / "chain-profile.json")
            profile["rpc"]["http"] = "https://unrelated.example"
            local_state.write_json(state / "chain-profile.json", profile)
            with mock.patch.object(reset.stack, "stop") as stop:
                with self.assertRaisesRegex(ValueError, "loopback"):
                    reset.execute(REPOSITORY, state, state)
                stop.assert_not_called()
            self.assertTrue((state / "owners/synthetic.key").exists())

    def test_nested_models_and_failed_runtime_cleanup_preserve_host_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.prepare(directory)
            local_state.private_directory(state / "services")
            profile = local_state.read_json(state / "chain-profile.json")
            manifest = {"development_only":True, "version":services.MANIFEST_VERSION,
                "initialized":True, "broker_port":12345, "profile_identity":deployment.profile_identity(profile),
                "runtime":None, "model_runner":{"directory":str(state / "services/models"), "binary":"/synthetic/ollama"}}
            local_state.write_json(state / "services/manifest.json", manifest)
            with mock.patch.object(reset.stack, "stop") as stop:
                with self.assertRaisesRegex(ValueError, "models outside"):
                    reset.execute(REPOSITORY, state, state)
                stop.assert_not_called()
            manifest["model_runner"] = None
            manifest["runtime"] = {"image":"local:fixture", "socket":"/synthetic/docker.sock", "namespace":"terrier-reset-test"}
            local_state.write_json(state / "services/manifest.json", manifest)
            with mock.patch.object(reset.stack, "stop"), mock.patch.object(Path, "is_file", return_value=True), \
                    mock.patch.object(reset.subprocess, "run", return_value=mock.Mock(returncode=1, stderr="synthetic engine failure")):
                with self.assertRaisesRegex(RuntimeError, "host state|local state is retained"):
                    reset.execute(REPOSITORY, state, state)
            self.assertTrue((state / "owners/synthetic.key").exists())
            self.assertTrue((state / "services/manifest.json").exists())
            self.assertTrue((state / "chain-profile.json").exists())


if __name__ == "__main__":
    unittest.main()
