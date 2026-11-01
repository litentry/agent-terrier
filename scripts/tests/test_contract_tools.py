import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local import contracts


def archive(extra=None):
    contents = io.BytesIO()
    with tarfile.open(fileobj=contents, mode="w:gz") as package:
        for name in ["source/src/Test.sol", "source/src/Script.sol"]:
            member = tarfile.TarInfo(name)
            payload = b"pragma solidity ^0.8.20;"
            member.size = len(payload)
            package.addfile(member, io.BytesIO(payload))
        if extra:
            package.addfile(extra, io.BytesIO(b""))
    return contents.getvalue()


class ContractToolsTests(unittest.TestCase):
    def test_valid_archive_and_checksum(self):
        payload = archive()
        contracts.verify_checksum(payload, hashlib.sha256(payload).hexdigest())
        files = contracts.archive_files(payload)
        self.assertEqual(set(files), {Path("src/Test.sol"), Path("src/Script.sol")})

    def test_tampered_archive_is_rejected(self):
        payload = archive()
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            contracts.verify_checksum(payload + b"changed", hashlib.sha256(payload).hexdigest())

    def test_archive_cannot_escape_or_link_to_another_file(self):
        for name in ["source/../outside", "/outside", "other-root/payload"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                contracts.archive_files(archive(tarfile.TarInfo(name)))
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE]:
            member = tarfile.TarInfo("source/unsafe")
            member.type = kind
            member.linkname = "../../outside"
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                contracts.archive_files(archive(member))

    def source_fixture(self, root):
        source = root / "crates/agentkeys-chain"
        source.mkdir(parents=True)
        for name in contracts.SOURCE_FILES:
            (source / name).write_text("public fixture")
        for directory in contracts.SOURCE_DIRECTORIES:
            (source / directory).mkdir()
        (source / "src/Example.sol").write_text("contract Example {}")
        return source

    def test_build_staging_copies_only_source_and_removes_stale_owned_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            source = self.source_fixture(root)
            (source / "src/local.env").write_text("sensitive-canary")
            cache = Path(directory) / "cache"
            project = contracts.prepare_project(root, cache, contracts.archive_files(archive()))
            self.assertTrue((project / "src/Example.sol").is_file())
            self.assertFalse((project / "src/local.env").exists())
            (source / "src/Example.sol").unlink()
            contracts.prepare_project(root, cache, contracts.archive_files(archive()))
            self.assertFalse((project / "src/Example.sol").exists())

    def test_unowned_cache_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            self.source_fixture(root)
            cache = Path(directory) / "cache"
            checkout_id = hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:16]
            target = cache / "contracts" / checkout_id
            target.mkdir(parents=True)
            canary = target / "keep.txt"
            canary.write_text("keep")
            with self.assertRaisesRegex(ValueError, "unowned"):
                contracts.prepare_project(root, cache, {})
            self.assertEqual(canary.read_text(), "keep")

    def test_symlink_cache_cannot_delete_an_outside_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            self.source_fixture(root)
            cache = Path(directory) / "cache"
            outside = Path(directory) / "outside"
            outside.mkdir()
            canary = outside / "keep.sol"
            canary.write_text("keep")
            cache.mkdir()
            (cache / "contracts").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                contracts.prepare_project(root, cache, {})
            self.assertEqual(canary.read_text(), "keep")

    def test_offline_missing_dependency_does_not_attempt_a_download(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(contracts, "dependency_spec", return_value=("a" * 40, "b" * 64)):
                with mock.patch.object(contracts.urllib.request, "urlopen") as download:
                    with self.assertRaisesRegex(RuntimeError, "not downloaded"):
                        contracts.verified_archive(Path(directory), Path(directory) / "cache", True)
                    download.assert_not_called()

    def test_concurrent_build_refuses_before_modifying_the_owned_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            cache = Path(directory) / "cache"
            with contracts.build_lock(root, cache):
                with self.assertRaisesRegex(RuntimeError, "Another contract build"):
                    with contracts.build_lock(root, cache):
                        self.fail("A second build acquired the same lock")
            with contracts.build_lock(root, cache):
                pass

    def test_build_does_not_inherit_wallet_or_deployment_settings(self):
        with mock.patch.dict(contracts.os.environ, {
            "AGENT_TERRIER_FORGE": "forge", "PRIVATE_KEY": "test-sensitive-canary",
            "AGENTKEYS_CHAIN": "remote-example", "FOUNDRY_PROFILE": "remote-example",
        }):
            with mock.patch.object(contracts.subprocess, "run") as execute:
                execute.return_value.returncode = 0
                self.assertEqual(contracts.run_forge(Path("."), "test", True, None), 0)
                command = execute.call_args.args[0]
                environment = execute.call_args.kwargs["env"]
                self.assertIn("--offline", command)
                self.assertNotIn("test-sensitive-canary", str(command))
                self.assertNotIn("PRIVATE_KEY", environment)
                self.assertNotIn("AGENTKEYS_CHAIN", environment)
                self.assertNotIn("FOUNDRY_PROFILE", environment)

    def test_explicit_compiler_is_shared_by_builds_and_matches_the_source_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            (project / "foundry.toml").write_text('[profile.default]\nsolc_version = "0.8.20"\n')
            compiler = project / "local-solc"
            compiler.write_text("synthetic compiler fixture")
            compiler.chmod(0o700)
            with mock.patch.dict(contracts.os.environ, {"AGENT_TERRIER_SOLC": str(compiler)}):
                with mock.patch.object(contracts.subprocess, "run") as execute:
                    execute.return_value.returncode = 0
                    execute.return_value.stdout = "solc compiler\nVersion: 0.8.20+synthetic\n"
                    self.assertEqual(contracts.compiler_arguments(project), ["--use", str(compiler.resolve())])
                    self.assertEqual(contracts.run_forge(project, "test", True, None), 0)
                    command = execute.call_args.args[0]
                    self.assertEqual(command[command.index("--use") + 1], str(compiler.resolve()))
                    execute.reset_mock()
                    execute.return_value.stdout = "Version: 0.8.21+synthetic\n"
                    with self.assertRaisesRegex(ValueError, "differs from the version pinned"):
                        contracts.run_forge(project, "test", True, None)
                    self.assertEqual(execute.call_count, 1, "mismatched compiler reached the build")
                    execute.return_value.stdout = "Version: 0.8.20+synthetic\n"
                    execute.return_value.returncode = 1
                    with self.assertRaises(ValueError):
                        contracts.compiler_arguments(project)
                    execute.return_value.returncode = 0
                    (project / "foundry.toml").write_text('[profile.default]\n')
                    with self.assertRaises(ValueError):
                        contracts.compiler_arguments(project)
