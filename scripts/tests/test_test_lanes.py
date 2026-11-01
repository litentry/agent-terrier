import errno
import io
import json
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

    def test_contract_counts_refuse_empty_skipped_and_failed_suites(self):
        for output in ("", "Suite result: ok. 0 passed; 0 failed; 2 skipped;", "Suite result: FAILED. 1 passed; 1 failed; 0 skipped;"):
            self.assertEqual(test_lanes.contract_counts({"status": "passed"}, output)["status"], "empty-or-failed-suite")
        result = test_lanes.contract_counts({"status": "passed"}, "Suite result: ok. 3 passed; 0 failed; 1 skipped;")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["tests"], {"passed": 3, "failed": 0, "ignored": 1})

    def test_real_qualification_scenarios_cannot_enter_ordinary_lanes(self):
        for component in ("chain", "services", "agents"):
            for lane in ("focused", "core"):
                with self.assertRaises(ValueError):
                    test_lanes.selection(lane, [component])
            plan, status = test_lanes.run(Path("."), "qualification", [component], plan=True)
            self.assertEqual(status, 0)
            self.assertTrue(any(name.startswith("qualify_local_") for name in plan["selected"]))

    def test_regression_is_explicit_and_cannot_be_narrowed_to_components(self):
        plan, status = test_lanes.run(Path("."), "regression", [], plan=True)
        self.assertEqual(status, 0)
        self.assertIn("workspace-native", plan["selected"])
        self.assertIn("privacy", plan["selected"])
        with self.assertRaises(ValueError):
            test_lanes.run(Path("."), "regression", ["cli"], plan=True)

    def test_report_disk_failure_still_identifies_private_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            repository = root / "source"
            repository.mkdir()
            diagnostics = root / "diagnostics"
            diagnostics.mkdir()
            output = io.StringIO()
            def execute(command, directory, log_path, **options):
                log_path.write_text("synthetic diagnostic")
                return {"status": "passed", "exit_code": 0, "seconds": 0}
            with patch.object(test_lanes, "SOURCE_COMMANDS", (("probe", ["synthetic"]),)), \
                    patch.object(test_lanes, "execute", side_effect=execute), \
                    patch.object(test_lanes.tempfile, "mkdtemp", return_value=str(diagnostics)), \
                    patch.object(test_lanes.sys, "stderr", output), \
                    patch.object(test_lanes.os, "open", side_effect=OSError(errno.ENOSPC, "synthetic disk full")):
                with self.assertRaises(OSError):
                    test_lanes.run(repository, "source", [], report_path=root / "report.json")
            self.assertIn(f"Private diagnostic logs: {diagnostics}", output.getvalue())
            self.assertEqual((diagnostics / "00-probe.log").read_text(), "synthetic diagnostic")
            self.assertFalse((root / "report.json").exists())

    def test_batched_targets_bind_package_manifest_kind_and_name(self):
        repository = Path("/synthetic/source")
        packages = [{"id": name + "-id", "name": name, "manifest_path": str(repository / name / "Cargo.toml")}
                    for name in ("first", "second")]
        metadata = {"workspace_members": [package["id"] for package in packages], "packages": packages}
        def artifact(package, kind, name):
            return {"reason": "compiler-artifact", "package_id": package["id"],
                    "manifest_path": package["manifest_path"], "profile": {"test": True},
                    "target": {"kind": [kind], "name": name}, "executable": "/synthetic/" + package["name"] + "-" + kind}
        first = artifact(packages[0], "test", "same-name")
        second = artifact(packages[1], "test", "same-name")
        library = artifact(packages[0], "lib", "custom-library-name")
        suites = [("selected", "first", "--test", "same-name", "one_test"),
                  ("library", "first", "--lib", None, "")]
        output = lambda values: "\n".join(json.dumps(value) for value in values)
        selected = test_lanes.rust_test_executables(repository, metadata, output([first, second, library]), suites)
        self.assertEqual(selected, {"selected": ("/synthetic/first-test", repository / "first"),
                                    "library": ("/synthetic/first-lib", repository / "first")})
        for artifacts in ([second, library], [first, first, library],
                          [dict(first, manifest_path="/outside/Cargo.toml"), library],
                          [dict(first, profile={"test": False}), library]):
            with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
                test_lanes.rust_test_executables(repository, metadata, output(artifacts), suites)

    def test_batch_executes_only_selected_suites_and_preserves_filters(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            manifest = str(repository / "package/Cargo.toml")
            package = {"name": "package", "id": "package-id", "manifest_path": manifest}
            metadata = {"workspace_members": ["package-id"], "packages": [package]}
            suites = [("filtered", "package", "--lib", None, "boundary::"),
                      ("integration", "package", "--test", "boundary", "")]
            commands = []
            def execute(command, directory, log_path, **options):
                commands.append((command, directory))
                if command[:2] == ["cargo", "metadata"]:
                    output = json.dumps(metadata)
                elif command[:2] == ["cargo", "test"]:
                    output = "\n".join(json.dumps({"reason": "compiler-artifact", "package_id": "package-id",
                        "manifest_path": manifest, "profile": {"test": True}, "target": {"name": name, "kind": [kind]},
                        "executable": str(repository / name)}) for kind, name in
                        [("lib", "library"), ("test", "boundary"), ("test", "unselected")])
                else:
                    output = "test result: ok. 1 passed; 0 failed; 0 ignored;"
                log_path.write_text(output)
                return {"status": "passed", "exit_code": 0, "seconds": 0}
            with patch.object(test_lanes, "selection", return_value=suites), \
                    patch.object(test_lanes, "execute", side_effect=execute):
                report, status = test_lanes.run(repository, "focused", ["protocol"])
            self.assertEqual(status, 0)
            builds = [command for command, _ in commands if command[:2] == ["cargo", "test"]]
            self.assertEqual(len(builds), 1)
            self.assertIn("--lib", builds[0])
            self.assertEqual(builds[0][-2:], ["--test", "boundary"])
            executed = [(command, directory) for command, directory in commands if command[0] != "cargo"]
            self.assertEqual(executed, [([str(repository / "library"), "boundary::"], repository / "package"),
                                       ([str(repository / "boundary"), ""], repository / "package")])
            self.assertEqual(sum(check.get("tests", {}).get("passed", 0) for check in report["checks"]), 2)
            commands.clear()
            plan = {"components": [], "rust_suites": [], "rust_builds": [], "qualification_only": ["integration"]}
            with patch.object(test_lanes, "selection", return_value=suites), \
                    patch.object(test_lanes, "SOURCE_COMMANDS", ()), \
                    patch.object(test_lanes.affected, "select", return_value=plan), \
                    patch.object(test_lanes, "execute", side_effect=execute):
                report, status = test_lanes.run(repository, "affected", [], changed_files=["synthetic"])
            self.assertEqual(status, 0)
            self.assertIn("integration-compile", report["selected"])
            self.assertEqual([command for command, _ in commands if command[0] != "cargo"],
                             [[str(repository / "library"), "boundary::"]])

    def test_child_does_not_inherit_host_provider_credentials(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"BROKER_PRIVATE_CANARY": "synthetic"}):
            root = Path(directory)
            result = test_lanes.execute([sys.executable, "-c", "import os; assert 'BROKER_PRIVATE_CANARY' not in os.environ"], root, root / "environment.log")
            self.assertEqual(result["status"], "passed")


if __name__ == "__main__":
    unittest.main()
