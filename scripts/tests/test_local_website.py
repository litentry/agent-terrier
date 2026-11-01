from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local import website


class WebsiteTests(unittest.TestCase):
    def test_port_is_explicitly_enabled_persisted_and_not_silently_migrated(self):
        self.assertIsNone(website.configuration({}))
        configured = website.configuration({}, True, 12345)
        manifest = {"version":7, "initialized":True, "website":configured}
        self.assertEqual(website.configuration(manifest), configured)
        self.assertEqual(website.configuration(manifest, True), configured)
        self.assertEqual(website.endpoint(configured), "http://127.0.0.1:12345")
        with self.assertRaisesRegex(ValueError, "bound to browser storage"):
            website.configuration(manifest, True, 12346)
        with self.assertRaisesRegex(ValueError, "requires --website"):
            website.configuration({}, port=12345)
        with self.assertRaisesRegex(ValueError, "configuration is missing"):
            website.configuration({"version":7, "initialized":True})
        for port in (True, 0, -1, 65536, "12345"):
            with self.assertRaises(ValueError):
                website.configuration({}, True, port)

    def test_managed_launch_refuses_environment_files_and_missing_build_before_spawning(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = root / "apps/parent-control"
            application.mkdir(parents=True)
            with patch.object(website.subprocess, "run") as resolve:
                with self.assertRaisesRegex(ValueError, "Build the public console"):
                    website.prepared_application(root)
                for directory in (root, application):
                    path = directory / ".env.local"
                    path.write_text("synthetic-marker")
                    with self.assertRaisesRegex(ValueError, "refuses local environment"):
                        website.prepared_application(root)
                    self.assertEqual(path.read_text(), "synthetic-marker")
                    path.unlink()
                resolve.assert_not_called()

    def test_website_receives_only_selected_runtime_settings_and_private_home(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(website.contracts, "tool_environment", return_value={
                "PATH":"synthetic-tools", "HOME":"/example/host-home", "PRIVATE_CANARY":"synthetic"}):
                environment = website.environment(directory, "http://127.0.0.1:12345", "synthetic-instance")
            self.assertEqual(environment["HOME"], str(directory / "website-home"))
            self.assertEqual((directory / "website-home").stat().st_mode & 0o777, 0o700)
            self.assertNotIn("PRIVATE_CANARY", environment)
            self.assertEqual(environment["AGENT_TERRIER_WEB_BROKER_URL"], "http://127.0.0.1:12345")
            self.assertEqual(environment["AGENT_TERRIER_WEB_BACKEND"], "core")
