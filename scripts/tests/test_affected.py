from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local import affected, test_lanes


def workspace(repository):
    packages = []
    for name, dependencies in (("primitive", []), ("shared", ["primitive"]),
                               ("agentkeys-cli", ["shared"]), ("independent", [])):
        packages.append({"id": name, "name": name, "manifest_path": str(repository / "crates" / name / "Cargo.toml"),
                         "dependencies": [{"name": dependency, "path": str(repository / "crates" / dependency)} for dependency in dependencies],
                         "metadata": None, "targets": [{"kind": ["lib"]}]})
    return {"workspace_members": [package["id"] for package in packages], "packages": packages}


class AffectedTests(unittest.TestCase):
    def test_transitive_consumers_and_deleted_files_are_included_without_unrelated_packages(self):
        root = Path("/synthetic/source")
        result = affected.select(root, ["crates/primitive/src/deleted.rs"], workspace(root))
        self.assertEqual(result["packages"], ["agentkeys-cli", "primitive", "shared"])
        self.assertEqual(result["components"], ["cli"])
        self.assertEqual([suite[0] for suite in result["rust_suites"]], ["primitive", "shared"])

    def test_manifest_changes_expand_to_every_workspace_member(self):
        root = Path("/synthetic/source")
        result = affected.select(root, ["Cargo.lock"], workspace(root))
        self.assertEqual(len(result["packages"]), 4)
        self.assertEqual(len(result["rust_suites"]), 3)

    def test_ui_and_runtime_paths_select_canonical_components(self):
        root = Path("/synthetic/source")
        result = affected.select(root, ["apps/parent-control/lib/example.ts", "apps/device-display/src/old.ts",
                                       "packages/agent-terrier-runtime/runtime.mjs"], workspace(root))
        self.assertEqual(result["components"], ["display", "dsh", "managed", "ui"])
        self.assertEqual(result["packages"], [])

    def test_docs_keep_core_without_starting_any_browser_or_runtime(self):
        root = Path("/synthetic/source")
        metadata = workspace(root)
        original = affected.select
        with patch.object(affected, "select", side_effect=lambda repository, paths: original(repository, paths, metadata)):
            result, status = test_lanes.run(root, "affected", [], plan=True, changed_files=["docs/wiki/Home.md"])
        self.assertEqual(status, 0)
        self.assertIn("capability", result["selected"])
        self.assertIn("privacy", result["selected"])
        self.assertNotIn("ui", result["selected"])
        self.assertEqual(result["affected"]["components"], [])

    def test_unknown_or_invalid_inputs_never_produce_an_empty_pass(self):
        root = Path("/synthetic/source")
        for paths in ([], ["unknown"], ["../README.md"], ["/README.md"], ["./README.md"],
                      ["docs//page.md"], ["docs/../README.md"], [None], ["docs/page\n.md"]):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                affected.select(root, paths, workspace(root))
        with self.assertRaises(ValueError):
            test_lanes.run(root, "affected", ["ui"], plan=True, changed_files=["README.md"])
        with self.assertRaises(ValueError):
            test_lanes.run(root, "core", [], plan=True, changed_files=["README.md"])

    def test_contract_and_provisioner_paths_select_fast_canonical_components(self):
        root = Path("/synthetic/source")
        plan = affected.select(root, ["crates/agentkeys-chain/src/Example.sol", "provisioner-scripts/new.js"], workspace(root))
        self.assertEqual(plan["components"], ["contracts", "provisioner"])
        self.assertEqual(plan["rust_suites"], [])

    def test_json_input_has_a_required_array_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "paths.json"
            path.write_text('["README.md"]')
            self.assertEqual(affected.paths_from_json(path), ["README.md"])
            path.write_text('{}')
            with self.assertRaises(ValueError):
                affected.paths_from_json(path)

    def test_changed_integration_tests_run_in_addition_to_the_library(self):
        root = Path("/synthetic/source")
        metadata = workspace(root)
        metadata["packages"][0]["targets"].append({"name": "http_boundary", "kind": ["test"]})
        result = affected.select(root, ["crates/primitive/tests/http_boundary.rs"], metadata)
        self.assertIn(("primitive-http_boundary", "primitive", "--test", "http_boundary", ""), result["rust_suites"])

    def test_qualification_only_targets_are_compiled_without_claiming_execution(self):
        root = Path("/synthetic/source")
        metadata = workspace(root)
        package = metadata["packages"][0]
        package["targets"].extend([{"name":"live_engine", "kind":["test"]}, {"name":"ordinary", "kind":["test"]}])
        package["metadata"] = {"terrier":{"qualification-only-tests":["live_engine"]}}
        original = affected.select
        with patch.object(affected, "select", side_effect=lambda repository, paths: original(repository, paths, metadata)):
            plan, status = test_lanes.run(root, "affected", [], plan=True, changed_files=["crates/primitive/tests/live_engine.rs"])
        self.assertEqual(status, 0)
        self.assertIn("primitive-live_engine-compile", plan["selected"])
        self.assertNotIn("primitive-live_engine", plan["selected"])
        self.assertIn("primitive-ordinary", plan["selected"])
        self.assertEqual(plan["affected"]["qualification_only"], ["primitive-live_engine"])
        package["metadata"]["terrier"]["qualification-only-tests"] = ["missing"]
        with self.assertRaisesRegex(ValueError, "invalid qualification-only"):
            original(root, ["crates/primitive/tests/live_engine.rs"], metadata)

    def test_curated_integration_targets_do_not_run_twice(self):
        root = Path("/synthetic/source")
        metadata = workspace(root)
        metadata["packages"][2]["targets"].append({"name": "agent_admin_mock", "kind": ["test"]})
        original = affected.select
        with patch.object(affected, "select", side_effect=lambda repository, paths: original(repository, paths, metadata)):
            result, status = test_lanes.run(root, "affected", [], plan=True, changed_files=["crates/agentkeys-cli/tests/agent_admin_mock.rs"])
        self.assertEqual(status, 0)
        self.assertEqual(result["selected"].count("cli-agent-ceremony"), 1)
        self.assertNotIn("agentkeys-cli-agent_admin_mock", result["selected"])

    def test_browser_rlib_runs_native_library_tests_and_selects_both_apps(self):
        root = Path("/synthetic/source")
        metadata = workspace(root)
        package = metadata["packages"][3]
        package.update(id="agentkeys-web-core", name="agentkeys-web-core",
                       manifest_path=str(root / "crates/agentkeys-web-core/Cargo.toml"),
                       targets=[{"kind": ["cdylib", "rlib"], "name": "agentkeys_web_core"}])
        metadata["workspace_members"][3] = package["id"]
        plan = affected.select(root, ["crates/agentkeys-web-core/src/lib.rs"], metadata)
        self.assertEqual(plan["components"], ["display", "ui"])
        self.assertEqual(plan["rust_suites"], [("agentkeys-web-core", "agentkeys-web-core", "--lib", None, "")])

    def test_known_testless_binary_has_a_compile_check_without_claiming_tests(self):
        root = Path("/synthetic/source")
        metadata = workspace(root)
        package = metadata["packages"][3]
        package.update(id="agentkeys-classify-dataset", name="agentkeys-classify-dataset",
                       manifest_path=str(root / "crates/agentkeys-classify-dataset/Cargo.toml"),
                       targets=[{"kind": ["bin"], "name": "classify-dataset"}])
        metadata["workspace_members"][3] = package["id"]
        plan = affected.select(root, ["Cargo.lock"], metadata)
        self.assertEqual(plan["rust_builds"], [("agentkeys-classify-dataset", "classify-dataset")])
        self.assertNotIn("agentkeys-classify-dataset", [suite[0] for suite in plan["rust_suites"]])

    def test_dependency_cycle_terminates_and_covers_both_members(self):
        root = Path("/synthetic/source")
        metadata = workspace(root)
        metadata["packages"][0]["dependencies"] = [{"name": "shared", "path": str(root / "crates/shared")}]
        self.assertEqual(affected.select(root, ["crates/shared/src/lib.rs"], metadata)["packages"],
                         ["agentkeys-cli", "primitive", "shared"])


if __name__ == "__main__":
    unittest.main()
