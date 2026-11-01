import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local import ci_changes


class ChangedFileTests(unittest.TestCase):
    def fixture(self, count=2):
        base, head, merge = "a" * 40, "b" * 40, "c" * 40
        request = {"base": {"sha": base, "repo": {"full_name": "example/public"}},
                   "head": {"sha": head}, "changed_files": count}
        event = {"number": 7, "pull_request": copy.deepcopy(request)}
        entries = [{"filename": f"docs/{index}.md", "status": "modified"} for index in range(count)]
        calls = []

        def read(path):
            calls.append(path)
            if "/git/commits/" in path:
                return {"sha": merge, "parents": [{"sha": base}, {"sha": head}]}
            if "/files?" in path:
                page = int(path.rsplit("=", 1)[1])
                return entries[(page - 1) * 100:page * 100]
            return copy.deepcopy(request)

        return event, merge, request, entries, calls, read

    def test_complete_pagination_retains_deleted_and_both_renamed_paths(self):
        event, merge, request, entries, calls, read = self.fixture(102)
        entries[0] = {"filename": "docs/deleted.md", "status": "removed"}
        entries[100] = {"filename": "docs/new.md", "status": "renamed", "previous_filename": "docs/old.md"}
        paths = ci_changes.collect(event, "example/public", merge, read)
        self.assertEqual(len(paths), 103)
        self.assertTrue({"docs/deleted.md", "docs/new.md", "docs/old.md"} <= set(paths))
        self.assertEqual(sum("/files?" in path for path in calls), 2)

    def test_stale_merge_and_mid_collection_changes_refuse(self):
        for failure in ("base", "head", "merge", "after"):
            with self.subTest(failure=failure):
                event, merge, request, entries, calls, read = self.fixture()
                if failure in ("base", "head"):
                    request[failure]["sha"] = "d" * 40
                if failure == "merge":
                    merge = "d" * 40

                def changed(path):
                    result = read(path)
                    if failure == "after" and len(calls) == 4:
                        result["head"]["sha"] = "d" * 40
                    return result

                with self.assertRaises(ValueError):
                    ci_changes.collect(event, "example/public", merge, changed)

    def test_incomplete_duplicate_oversized_and_malformed_files_refuse(self):
        for failure in ("short", "duplicate", "limit", "path", "rename", "status"):
            with self.subTest(failure=failure):
                event, merge, request, entries, calls, read = self.fixture()
                if failure == "short":
                    entries.pop()
                elif failure == "duplicate":
                    entries[1] = entries[0]
                elif failure == "limit":
                    request["changed_files"] = ci_changes.MAX_FILES + 1
                elif failure == "path":
                    entries[0]["filename"] = "../outside"
                elif failure == "rename":
                    entries[0].update(status="renamed", previous_filename="docs/../outside")
                else:
                    entries[0]["status"] = "unknown"
                with self.assertRaises(ValueError):
                    ci_changes.collect(event, "example/public", merge, read)

    def test_output_is_private_and_cannot_overwrite_or_enter_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            repository = root / "source"
            repository.mkdir()
            output = root / "paths.json"
            ci_changes.write_paths(output, ["README.md"], repository)
            self.assertEqual(json.loads(output.read_text()), ["README.md"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                ci_changes.write_paths(output, ["replacement"], repository)
            alias = root / "alias"
            alias.symlink_to(repository, target_is_directory=True)
            with self.assertRaises(ValueError):
                ci_changes.write_paths(alias / "paths.json", ["README.md"], repository)
            self.assertEqual(list(repository.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
