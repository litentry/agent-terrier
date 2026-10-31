import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

scanner_path = Path(__file__).resolve().parents[1] / "check-public.py"
module_spec = importlib.util.spec_from_file_location("public_check", scanner_path)
public_check = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(public_check)

class PublicContentsTests(unittest.TestCase):
    def check_text(self, text, filename="example.txt"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            return public_check.inspect_tree(root)

    def test_accepts_public_synthetic_example(self):
        report = self.check_text("http://localhost:8080\nhttps://github.com/litentry/agent-terrier/issues/1\n")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["scanned_files"], 1)

    def test_captured_deployment_inventory_is_denied_without_echoing_values(self):
        inventory = {
            "ResponseMetadata": {"RequestId": "synthetic-request", "Service": "synthetic-service", "Region": "synthetic-region"},
            "Result": {"Images": [{"ImageId": "synthetic-instance", "ImageUrl": "synthetic-private-image"}]},
        }
        report = self.check_text(json.dumps(inventory), "captured-response.json")
        self.assertEqual(report["findings"], [{
            "path": "captured-response.json", "rule": "deployment-inventory", "line": 0,
        }])
        self.assertNotIn("synthetic-private-image", json.dumps(report))
        self.assertEqual(self.check_text(json.dumps({"image": "example/local-agent:dev"}), "recipe.json")["findings"], [])

    def test_private_domain_hash_blocks_subdomains_without_echoing_names(self):
        domain = "synthetic-private.example"
        digest = hashlib.sha256(domain.encode()).hexdigest()
        with mock.patch.object(public_check, "PRIVATE_DOMAIN_HASHES", {digest}, create=True):
            for spelling in (domain, "broker." + domain, "GATE." + domain.upper()):
                report = self.check_text("https://" + spelling + "/v1")
                self.assertEqual(report["findings"], [{
                    "path":"example.txt", "rule":"private-deployment-domain", "line":1,
                }])
                self.assertNotIn(domain, json.dumps(report))
            for spelling in ("broker.public.example", domain + ".public.example", "x" + domain):
                self.assertEqual(self.check_text("https://" + spelling)["findings"], [])

    def test_rejects_private_key_without_printing_it(self):
        canary = "-----BEGIN " + "PRIVATE KEY-----\n" + "synthetic-test-material"
        report = self.check_text(canary)
        self.assertEqual(report["findings"][0]["rule"], "private-key")
        self.assertNotIn("synthetic-test-material", json.dumps(report))

    def test_rejects_literal_secret_and_personal_path(self):
        secret = "test-only-" + "x" * 30
        report = self.check_text('api_' + 'key = "' + secret + '"\n/' + "Users/example-person/file")
        self.assertEqual({item["rule"] for item in report["findings"]}, {"credential-literal", "personal-path"})
        self.assertNotIn(secret, json.dumps(report))

    def test_rejects_profile_signing_material_without_echoing_values(self):
        canary = "synthetic-only-" + "z" * 32
        for field in ["default_test_key", "sudoer_seed_phrase"]:
            report = self.check_text(json.dumps({field: canary}))
            self.assertEqual(report["findings"][0]["rule"], "credential-literal")
            self.assertNotIn(canary, json.dumps(report))

    def test_rejects_credential_file_and_firmware(self):
        self.assertTrue(self.check_text("placeholder", ".env")["findings"])
        self.assertTrue(self.check_text("placeholder", "firmware/main.c")["findings"])
        self.assertEqual(self.check_text("MODEL_URL=http://localhost", ".env.example")["findings"], [])

    def test_rejects_unapproved_project_link(self):
        report = self.check_text("https://github.com/litentry/" + "example-internal-project/issues/1")
        self.assertEqual(report["findings"][0]["rule"], "unapproved-project-link")

    def test_rejects_symlink_instead_of_following_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "outside").symlink_to(root.parent)
            report = public_check.inspect_tree(root)
            self.assertEqual(report["findings"][0]["rule"], "symlink")

    def test_changed_fixture_loses_its_exact_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "negative-test.txt"
            line = "-----BEGIN " + "PRIVATE KEY-----"
            fixture.write_text(line)
            exception = {
                "path": fixture.name, "rule": "private-key",
                "line_sha256": hashlib.sha256(line.encode()).hexdigest(),
                "reason": "Header-only negative test; contains no key material.",
            }
            (root / ".public-test-fixtures.json").write_text(json.dumps([exception]))
            self.assertEqual(public_check.inspect_tree(root)["findings"], [])
            fixture.write_text(line + " changed")
            self.assertTrue(public_check.inspect_tree(root)["findings"])

    def test_manifest_cannot_except_a_secret_file_or_source_directory(self):
        for rule in ["credential-or-state-file", "excluded-source", "symlink"]:
            with self.subTest(rule=rule), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / ".env").write_text("placeholder")
                (root / ".public-test-fixtures.json").write_text(json.dumps([{
                    "path": ".env", "rule": rule, "line_sha256": "a" * 64,
                    "reason": "Attempted whole-file exception",
                }]))
                rules = {item["rule"] for item in public_check.inspect_tree(root)["findings"]}
                self.assertIn("invalid-exceptions", rules)
                self.assertIn("credential-or-state-file", rules)

    def test_malformed_manifest_fails_without_echoing_its_contents(self):
        canary = "synthetic-sensitive-canary"
        report = self.check_text(canary, ".public-test-fixtures.json")
        self.assertEqual(report["findings"][0]["rule"], "invalid-exceptions")
        self.assertNotIn(canary, json.dumps(report))

    def test_public_surface_does_not_allow_an_unlisted_application(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "apps/operator").mkdir(parents=True)
            (root / "apps/operator/main.py").write_text("placeholder")
            (root / ".public-source.json").write_text(json.dumps({
                "files": [".public-source.json"], "directories": ["apps/console"],
            }))
            report = public_check.inspect_tree(root)
            self.assertEqual(report["findings"], [{
                "path": "apps/operator/main.py", "rule": "outside-public-surface", "line": 0,
            }])

if __name__ == "__main__":
    unittest.main()
