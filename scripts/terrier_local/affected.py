import json
from pathlib import Path, PurePosixPath
import subprocess

from . import contracts


PACKAGE_COMPONENTS = {
    "agentkeys-protocol": "protocol", "agentkeys-runtime": "runtime",
    "agentkeys-broker-server": "broker", "agentkeys-mock-server": "signer",
    "agentkeys-gate": "relay", "agentkeys-bundler": "bundler",
    "agentkeys-daemon": "daemon", "agentkeys-local-store": "storage", "agentkeys-cli": "cli",
}
GLOBAL_RUST = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml"}
ROOT_SOURCE = {"AGENTS.md", "CLAUDE.md", "README.md", "CONTRIBUTING.md", "LICENSE", "NOTICE",
               ".gitignore", ".public-source.json", ".public-test-fixtures.json", "terrier"}


def paths_from_json(path):
    with path.open() as source:
        payload = source.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024:
        raise ValueError("Changed-file input is too large")
    paths = json.loads(payload)
    if not isinstance(paths, list):
        raise ValueError("Changed files must be a JSON array of repository-relative paths")
    return paths


def select(repository, changed_files, metadata=None):
    if not changed_files or len(changed_files) > 10000:
        raise ValueError("Affected checks require a nonempty, bounded changed-file list")
    for path in changed_files:
        if (not isinstance(path, str) or not path or path != str(PurePosixPath(path))
                or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts
                or "\\" in path or any(ord(character) < 32 for character in path)):
            raise ValueError("Changed-file paths must be normalized repository-relative paths")
    if metadata is None:
        result = subprocess.run(["cargo", "metadata", "--offline", "--locked", "--no-deps", "--format-version", "1"],
            cwd=repository, env=contracts.tool_environment(), capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError("Could not resolve workspace dependencies for affected checks")
        metadata = json.loads(result.stdout)
    members = set(metadata["workspace_members"])
    packages = {package["name"]: package for package in metadata["packages"] if package["id"] in members}
    directories = {name: Path(package["manifest_path"]).parent.relative_to(repository).as_posix()
                   for name, package in packages.items()}
    affected_packages, components, reasons = set(), set(), {}
    for path in sorted(set(changed_files)):
        owners = {name for name, directory in directories.items() if path.startswith(directory + "/")}
        if path in GLOBAL_RUST:
            owners = set(packages)
        if owners:
            affected_packages.update(owners)
            reasons[path] = sorted(owners)
        elif path.startswith("crates/agentkeys-chain/"):
            raise ValueError("Contract changes require the explicit contract and real-chain qualification lanes")
        elif path == "scripts/build-browser-core.py":
            affected_packages.add("agentkeys-web-core")
            components.update(("ui", "display"))
            reasons[path] = ["browser library", "ui", "display"]
        elif path in ("scripts/web-ssr-server.mjs", "scripts/tests/web-ssr-server.test.mjs"):
            components.add("display")
            reasons[path] = ["display", "source"]
        elif path in ("package.json", "package-lock.json") or path.startswith("design-system/"):
            components.update(("ui", "display"))
            reasons[path] = ["ui", "display"]
        elif path.startswith("apps/parent-control/"):
            components.add("ui")
            reasons[path] = ["ui"]
        elif path.startswith("apps/device-display/"):
            components.add("display")
            reasons[path] = ["display"]
        elif path.startswith("packages/"):
            components.update(("dsh", "managed"))
            reasons[path] = ["dsh", "managed"]
        elif path.startswith(("e2e/fixtures/", "presets/")):
            affected_packages.update(packages)
            components.update(("ui", "display", "dsh", "managed"))
            reasons[path] = ["all product consumers"]
        elif path.startswith("provisioner-scripts/"):
            raise ValueError("Provisioner changes require explicit provisioner qualification")
        elif path in ROOT_SOURCE or path.startswith(("docs/", "LICENSES/", ".github/", "scripts/")):
            reasons[path] = ["source", "core"]
            if path.startswith(("scripts/terrier_local/", "scripts/tests/test_test_lanes", "scripts/tests/test_affected")):
                components.add("cli")
        else:
            raise ValueError("No affected-check owner for a changed path; add a reviewed mapping")
    while True:
        consumers = {name for name, package in packages.items()
                     if any(dependency.get("path") and dependency["name"] in affected_packages
                            for dependency in package.get("dependencies", []))}
        expanded = affected_packages | consumers
        if expanded == affected_packages:
            break
        affected_packages = expanded
    suites = []
    for name in sorted(affected_packages):
        component = PACKAGE_COMPONENTS.get(name)
        if component:
            components.add(component)
        elif any("lib" in target["kind"] for target in packages[name]["targets"]):
            suites.append((name, name, "--lib", None, ""))
        else:
            raise ValueError(f"Package {name} needs an explicit test target mapping")
        for target in packages[name]["targets"]:
            if "test" in target["kind"] and any(path.startswith(directories[name] + "/tests/") for path in changed_files):
                suites.append((name + "-" + target["name"], name, "--test", target["name"], ""))
        if name == "agentkeys-web-core":
            components.update(("ui", "display"))
    return {"components": sorted(components), "packages": sorted(affected_packages),
            "rust_suites": suites, "reasons": reasons}
