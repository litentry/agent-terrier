from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local import security_qualification as security, test_lanes


class SecurityQualificationTests(unittest.TestCase):
    def test_detection_requires_the_exact_assertion_and_one_executed_failure(self):
        guard = security.GUARDS[2]
        output = (f"test {security.TEST_PREFIX}{guard[4]} ... FAILED\n{guard[5]}\n"
                  "test result: FAILED. 0 passed; 1 failed; 0 ignored;\n")
        failed = {"status": "failed", "exit_code": 101}
        self.assertTrue(security.detected(failed, output, guard[4], guard[5]))
        for result, changed in [
            ({"status": "timeout", "exit_code": 101}, output),
            ({"status": "failed", "exit_code": 1}, output),
            ({"status": "passed", "exit_code": 0}, output),
            (failed, output.replace("0 ignored", "1 ignored")),
            (failed, output.replace("1 failed", "0 failed")),
            (failed, output.replace(guard[5], "unexpected panic")),
            (failed, output.replace(guard[4], "another_test")),
            (failed, "error: could not compile crate"),
            (failed, output + output),
        ]:
            self.assertFalse(security.detected(result, changed, guard[4], guard[5]))

    def test_mutations_never_edit_tests_and_refuse_source_drift(self):
        guard = security.GUARDS[0]
        tests = "#[cfg(test)]\n" + guard[1]
        source = guard[1] + "\n" + tests
        self.assertEqual(security.apply_guard(source, guard), guard[2] + "\n" + tests)
        for changed in (tests, guard[1], guard[1] + source, source.replace(guard[1], "different")):
            with self.assertRaises(ValueError):
                security.apply_guard(changed, guard)

    def test_qualification_is_explicit_and_bound_to_a_reviewed_revision(self):
        revision = "a" * 40
        for lane in ("source", "core", "focused"):
            with self.assertRaises(ValueError):
                test_lanes.run(Path("."), lane, ["security"], plan=True)
        for invalid in (None, "main", "a" * 39):
            with self.assertRaises(ValueError):
                test_lanes.run(Path("."), "qualification", ["security"], plan=True, source_revision=invalid)
        with self.assertRaises(ValueError):
            test_lanes.run(Path("."), "focused", ["protocol"], plan=True, source_revision=revision)
        plan, result = test_lanes.run(Path("."), "qualification", ["security"], plan=True, source_revision=revision)
        self.assertEqual(result, 0)
        self.assertEqual(plan["selected"], ["isolated-security-guards"])

    def test_export_rejects_links_and_path_escape_before_writing(self):
        revision = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for entry in ("../outside\tfile", "/outside\tfile", "link\tsymlink", "a/../b\tfile"):
                outputs = [revision.encode(), (entry + "\n").encode()]
                with patch.object(security.subprocess, "run", side_effect=[subprocess.CompletedProcess([], 0, value) for value in outputs]):
                    with self.assertRaises(ValueError):
                        security.export_revision(root, revision, root)
                self.assertEqual(list(root.iterdir()), [])

    def test_failed_export_removes_only_its_disposable_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            original = repository / "keep"
            original.write_text("unchanged")
            isolation = root / "isolated"
            isolation.mkdir()
            alias = root / "alias"
            alias.symlink_to(root, target_is_directory=True)
            def refuse(repository, revision, destination):
                self.assertEqual(destination, destination.resolve())
                raise ValueError("synthetic refusal")
            with patch.object(security.tempfile, "mkdtemp", return_value=str(alias / "isolated")), \
                    patch.object(security, "export_revision", side_effect=refuse):
                checks, provenance = security.run(repository, "a" * 40, root)
            self.assertFalse(isolation.exists())
            self.assertEqual(original.read_text(), "unchanged")
            self.assertTrue(any(check["status"] == "failed" for check in checks))
            self.assertEqual(checks[-1]["phase"], "cleanup")
            self.assertEqual(provenance["source_revision"], "a" * 40)


if __name__ == "__main__":
    unittest.main()
