import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local import test_lanes


class TestLaneExecutionTests(unittest.TestCase):
    def test_reports_cannot_overwrite_files_or_enter_source_through_an_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            repository = root / "source"
            repository.mkdir()
            alias = root / "alias"
            alias.symlink_to(repository, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "outside"):
                test_lanes.run(repository, "source", [], report_path=alias / "report.json")
            original = root / "original.json"
            original.write_text("unchanged")
            for path in [original, root / "link.json"]:
                if path != original:
                    path.symlink_to(original)
                with self.assertRaises(ValueError):
                    test_lanes.run(repository, "source", [], report_path=path)
                self.assertEqual(original.read_text(), "unchanged")
            self.assertEqual(list(repository.iterdir()), [])

    def test_command_failure_and_missing_tool_are_never_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            success = test_lanes.execute([sys.executable, "-c", "pass"], root, root / "success.log")
            self.assertEqual(success["status"], "passed")
            failure = test_lanes.execute([sys.executable, "-c", "raise SystemExit(23)"], root, root / "failure.log")
            self.assertEqual((failure["status"], failure["exit_code"]), ("failed", 23))
            missing = test_lanes.execute([str(root / "absent")], root, root / "missing.log")
            self.assertEqual(missing["status"], "unavailable")

    def test_timeout_kills_the_owned_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pid_file = root / "child.pid"
            child_code = "import time; time.sleep(30)"
            parent_code = ("import subprocess,sys,time; from pathlib import Path; "
                           f"child=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
                           f"Path({str(pid_file)!r}).write_text(str(child.pid)); time.sleep(30)")
            result = test_lanes.execute([sys.executable, "-c", parent_code], root, root / "timeout.log", 1)
            self.assertEqual(result["status"], "timeout")
            self.assertTrue(pid_file.is_file())
            status = subprocess.run(["ps", "-o", "stat=", "-p", pid_file.read_text()], capture_output=True, text=True)
            self.assertTrue(status.returncode != 0 or status.stdout.strip().startswith("Z"))

    def test_empty_or_ignored_rust_suite_is_not_a_pass(self):
        for output in ["", "test result: ok. 0 passed; 0 failed; 1 ignored;"]:
            result = test_lanes.rust_counts({"status": "passed"}, output)
            self.assertEqual(result["status"], "empty-or-failed-suite")
        result = test_lanes.rust_counts({"status": "passed"}, "test result: ok. 2 passed; 0 failed; 1 ignored;")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["tests"], {"passed": 2, "failed": 0, "ignored": 1})

    def test_qualification_selection_is_explicit_and_reuses_canonical_scenarios(self):
        for components in ([], ["cli"], ["storage", "cli"]):
            with self.assertRaises(ValueError):
                test_lanes.selection("qualification", components)
        plan, status = test_lanes.run(Path("."), "qualification", ["storage"], plan=True)
        self.assertEqual(status, 0)
        self.assertIn("qualify_public_web", test_lanes.run(Path("."), "qualification", ["ui"], plan=True)[0]["selected"])
        self.assertIn("worker-authority", plan["selected"])
        self.assertIn("qualify_local_broker_storage", plan["selected"])
        self.assertIn("qualify_local_channel", plan["selected"])
        self.assertNotIn("qualify_local_broker_storage", test_lanes.run(Path("."), "core", ["storage"], plan=True)[0]["selected"])

    def test_empty_or_skipped_python_qualification_is_not_a_pass(self):
        for output in ("", "Ran 0 tests in 0.000s\n\nOK\n", "Ran 1 test in 0.000s\n\nOK (skipped=1)\n"):
            self.assertEqual(test_lanes.python_counts({"status": "passed"}, output)["status"], "empty-or-failed-suite")
        result = test_lanes.python_counts({"status": "passed"}, "Ran 2 tests in 0.100s\n\nOK (skipped=1)\n")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["tests"], {"passed": 1, "ignored": 1})
        self.assertEqual(test_lanes.python_counts({"status": "failed"}, "Ran 1 test in 0.1s\nFAILED\n")["status"], "failed")

    def test_child_does_not_inherit_host_provider_credentials(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"BROKER_PRIVATE_CANARY": "synthetic"}):
            root = Path(directory)
            result = test_lanes.execute([sys.executable, "-c", "import os; assert 'BROKER_PRIVATE_CANARY' not in os.environ"], root, root / "environment.log")
            self.assertEqual(result["status"], "passed")


if __name__ == "__main__":
    unittest.main()
