from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local import deployment, local_state, services


class LocalServicesTests(unittest.TestCase):
    def test_missing_existing_keys_and_changed_deployment_never_generate_replacements(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = local_state.private_directory(root / "services")
            manifest = {"version":1, "development_only":True, "profile_identity":"test-deployment",
                        "broker_port":12345, "initialized":True}
            local_state.write_json(directory / "manifest.json", manifest)
            with mock.patch.object(deployment, "active_profile", return_value=({}, {}, "test-deployment")):
                with mock.patch.object(services.subprocess, "run") as generate:
                    with self.assertRaisesRegex(ValueError, "signing key is missing"):
                        services.prepare(root, root, root, None)
                    with self.assertRaisesRegex(ValueError, "port is bound"):
                        services.prepare(root, root, root, 12346)
                    generate.assert_not_called()
            before = (directory / "manifest.json").read_bytes()
            with mock.patch.object(deployment, "active_profile", return_value=({}, {}, "different-deployment")):
                with self.assertRaisesRegex(ValueError, "another deployment"):
                    services.prepare(root, root, root, None)
            self.assertEqual((directory / "manifest.json").read_bytes(), before)

    def test_services_control_preserves_foreign_files_and_uses_its_own_socket(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            (state / "chain.sock").write_text("unrelated-chain-marker")
            self.assertEqual(services.stop(state), {"running":False})
            control = state / services.SOCKET_NAME
            control.write_text("preserve")
            with self.assertRaises(ValueError):
                services.stop(state)
            self.assertEqual(control.read_text(), "preserve")
            self.assertEqual((state / "chain.sock").read_text(), "unrelated-chain-marker")

    def test_reuse_is_idempotent_but_unhealthy_or_different_ports_are_refused(self):
        current = {"running":True, "ready":True, "broker_port":12345}
        with mock.patch.object(services, "status", return_value=current):
            with mock.patch.object(services.subprocess, "Popen") as spawn:
                self.assertEqual(services.start(Path("."), Path(".")), current)
                with self.assertRaisesRegex(ValueError, "different port"):
                    services.start(Path("."), Path("."), port=12346)
                current["ready"] = False
                with self.assertRaisesRegex(RuntimeError, "unhealthy"):
                    services.start(Path("."), Path("."))
                spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
