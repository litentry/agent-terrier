import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local.browser import open_public_request


class BrowserRequestTests(unittest.TestCase):
    def test_public_readable_request_is_allowed_without_changing_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            request = Path(temporary) / "request.json"
            request.write_bytes(b'{"public":"proof"}')
            request.chmod(0o644)
            with open_public_request(request) as source:
                self.assertEqual(source.read(), request.read_bytes())
            self.assertEqual(request.stat().st_mode & 0o777, 0o644)

    def test_links_special_files_and_shared_writes_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request = root / "request.json"
            request.write_bytes(b"public-proof")
            linked = root / "linked"
            linked.symlink_to(request)
            with self.assertRaises(OSError):
                open_public_request(linked)
            linked.unlink()
            os.link(request, linked)
            with self.assertRaises(ValueError):
                open_public_request(linked)
            linked.unlink()
            os.mkfifo(linked)
            with self.assertRaises(ValueError):
                open_public_request(linked)
            request.chmod(0o666)
            with self.assertRaises(ValueError):
                open_public_request(request)
            self.assertEqual(request.read_bytes(), b"public-proof")


if __name__ == "__main__":
    unittest.main()
