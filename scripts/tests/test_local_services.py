from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local import deployment, local_state, services


class LocalServicesTests(unittest.TestCase):
    def test_runtime_configuration_is_explicit_persistent_and_engine_bound(self):
        manifest = {"version":4, "initialized":True}
        self.assertIsNone(services.runtime_configuration(manifest))
        for image, endpoint in (("image", None), (None, "/tmp/test.sock"), ("image", "tcp://remote:1"),
                                ("bad image", "/tmp/test.sock")):
            with self.assertRaises(ValueError):
                services.runtime_configuration(manifest, image, endpoint)
        configured = services.runtime_configuration(manifest, "fixture-image", "/tmp/test.sock")
        current = {"version":services.MANIFEST_VERSION, "initialized":True, "runtime":configured}
        self.assertEqual(services.runtime_configuration(current), configured)
        updated = services.runtime_configuration(current, "updated-image", "/tmp/test.sock")
        self.assertEqual(updated["namespace"], configured["namespace"])
        with self.assertRaisesRegex(ValueError, "another Docker socket"):
            services.runtime_configuration(current, "fixture-image", "/tmp/another.sock")
        current.pop("runtime")
        with self.assertRaisesRegex(ValueError, "configuration is missing"):
            services.runtime_configuration(current)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            environment = services.runtime_environment(directory, directory, configured)
            self.assertEqual(environment["AGENT_TERRIER_RUNTIME_NAMESPACE"], configured["namespace"])
            client_config = directory / "docker-client/config.json"
            self.assertEqual(client_config.stat().st_mode & 0o777, 0o600)
            local_state.write_json(client_config, {"credsStore":"must-not-use"})
            with self.assertRaisesRegex(ValueError, "isolated configuration"):
                services.runtime_environment(directory, directory, configured)

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
        current = {"running":True, "ready":True, "broker_port":12345, "service_schema":services.MANIFEST_VERSION}
        with mock.patch.object(services, "status", return_value=current):
            with mock.patch.object(services.subprocess, "Popen") as spawn:
                self.assertEqual(services.start(Path("."), Path(".")), current)
                with self.assertRaisesRegex(ValueError, "different port"):
                    services.start(Path("."), Path("."), port=12346)
                current["ready"] = False
                with self.assertRaisesRegex(RuntimeError, "unhealthy"):
                    services.start(Path("."), Path("."))
                current.pop("service_schema")
                with self.assertRaisesRegex(RuntimeError, "older schema"):
                    services.start(Path("."), Path("."))
                spawn.assert_not_called()

    def test_signer_migration_is_once_only_and_never_replaces_existing_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = local_state.private_directory(root / "services")
            broker = local_state.private_directory(directory / "broker")
            for name in ("oidc", "session"):
                local_state.write_private(broker / f"{name}.json", b"synthetic-original")
            for name in services.WORKERS:
                worker = local_state.private_directory(directory / name)
                local_state.write_private(worker / "development.key", b"synthetic-original")
            local_state.write_json(directory / "manifest.json", {"version":1, "development_only":True,
                "profile_identity":"test-deployment", "broker_port":12345, "initialized":True})
            with mock.patch.object(deployment, "active_profile", return_value=({}, {}, "test-deployment")), mock.patch.object(services, "prepare_submitter"):
                manifest = services.prepare(root, root, root, None)
                self.assertEqual(manifest["version"], services.MANIFEST_VERSION)
                secret = directory / "signer/master.key"
                original = secret.read_bytes()
                self.assertEqual(len(original), 64)
                self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
                services.prepare(root, root, root, None)
                self.assertTrue(secret.read_bytes() == original, "signer key was replaced")
                self.assertEqual((broker / "session.json").read_bytes(), b"synthetic-original")
                for name in ("admin.key", "keys.json"):
                    relay_file = directory / "relay" / name
                    original_relay = relay_file.read_bytes()
                    self.assertEqual(relay_file.stat().st_mode & 0o777, 0o600)
                    relay_file.unlink()
                    with self.assertRaisesRegex(ValueError, "relay state is missing"):
                        services.prepare(root, root, root, None)
                    self.assertFalse(relay_file.exists())
                    local_state.write_private(relay_file, original_relay)
                secret.unlink()
                with self.assertRaisesRegex(ValueError, "signer key is missing"):
                    services.prepare(root, root, root, None)
                self.assertFalse(secret.exists())
                previous = dict(manifest, version=2)
                local_state.write_json(directory / "manifest.json", previous)
                with self.assertRaisesRegex(ValueError, "signer key is missing"):
                    services.prepare(root, root, root, None)
                self.assertFalse(secret.exists())


if __name__ == "__main__":
    unittest.main()
