"""CLI test selection and timing; qualification scenarios retain their owners."""
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time

from . import contracts, affected

COMPONENTS = ("protocol", "runtime", "broker", "signer", "relay", "bundler", "daemon", "storage", "cli", "ui", "display", "dsh", "managed", "contracts", "provisioner", "chain", "services", "agents", "website", "security")
REGRESSION_TIMEOUT_SECONDS = 3600
RUNTIME_SUITE = ("runtime", "agentkeys-runtime", "--lib", None, "")
CORE = (
    ("protocol", "agentkeys-protocol", "--lib", None, ""),
    ("capability", "agentkeys-core", "--lib", None, "capability_verify::tests"),
    ("atomic-files", "agentkeys-core", "--test", "atomic_secret", ""),
    ("device-custody", "agentkeys-core", "--test", "device_key_custody", ""),
    RUNTIME_SUITE,
)
RUST_COMPONENTS = {
    "protocol": [CORE[0]],
    "runtime": [RUNTIME_SUITE],
    "bundler": [("bundler", "agentkeys-bundler", "--lib", None, "")],
    "relay": [("relay", "agentkeys-gate", "--lib", None, ""),
              ("relay-configuration", "agentkeys-gate", "--test", "local_configuration", ""),
              ("relay-flow", "agentkeys-gate", "--test", "relay_flow", "")],
    "broker": [("broker", "agentkeys-broker-server", "--lib", None, "")],
    "signer": [("signer", "agentkeys-mock-server", "--lib", None, ""),
               ("signer-routes", "agentkeys-mock-server", "--test", "dev_key_service_routes", ""),
               ("signer-startup", "agentkeys-mock-server", "--test", "local_signer_startup", "")],
    "daemon": [("daemon", "agentkeys-daemon", "--bin", "agentkeys-daemon", "")],
    "storage": [("storage", "agentkeys-local-store", "--lib", None, "")],
    "cli": [("cli", "agentkeys-cli", "--lib", None, ""),
            ("cli-agent-ceremony", "agentkeys-cli", "--test", "agent_admin_mock", ""),
            ("cli-agent-transport", "agentkeys-cli", "--test", "local_agent_transport", "")],
}
QUALIFICATIONS = {
    "security": (),
    "contracts": (),
    "provisioner": (),
    "chain": ("qualify_local_chain.py", "qualify_local_signing.py", "qualify_local_binding.py", "qualify_local_owner.py", "qualify_local_login.py", "qualify_local_bundler.py"),
    "services": ("qualify_local_services.py", "qualify_local_classify.py"),
    "agents": ("qualify_local_agents.py",),
    "website": ("qualify_local_website.py",),
    "ui": ("qualify_public_web.py",),
    "storage": (
        "qualify_local_storage.py", "qualify_local_credentials.py", "qualify_local_config.py",
        "qualify_local_memory.py", "qualify_local_channel.py", "qualify_local_broker_storage.py",
        "qualify_local_credential_cli.py",
    ),
}
QUALIFICATION_RUST = {
    "security": [],
    "contracts": [], "provisioner": [], "chain": [], "services": [], "agents": [], "website": [],
    "ui": [],
    "storage": [*RUST_COMPONENTS["storage"],
                ("worker-authority", "agentkeys-worker-creds", "--test", "local_storage", "")],
}
SOURCE_COMMANDS = (
    ("privacy", ["python3", "scripts/check-public.py"]),
    ("cli-reference", ["python3", "scripts/generate-cli-reference.py", "--check"]),
    ("python", ["python3", "-m", "unittest", "discover", "-s", "scripts/tests"]),
    ("web-server", ["node", "--test", "scripts/tests/web-ssr-server.test.mjs"]),
    ("closure", ["cargo", "metadata", "--offline", "--locked", "--no-deps", "--format-version", "1"]),
)
RUST_RESULT = re.compile(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;")


def execute(command, directory, log_path, timeout_seconds=600, extra_environment=None):
    started = time.monotonic()
    status = "passed"
    with log_path.open("xb") as output:
        try:
            environment = contracts.tool_environment()
            environment.update(extra_environment or {})
            process = subprocess.Popen(command, cwd=directory, env=environment,
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        except OSError:
            return {"status": "unavailable", "exit_code": None, "seconds": round(time.monotonic() - started, 3)}
        try:
            exit_code = process.wait(timeout=timeout_seconds)
            if exit_code:
                status = "failed"
        except subprocess.TimeoutExpired:
            status = "timeout"
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            exit_code = process.returncode
    return {"status": status, "exit_code": exit_code, "seconds": round(time.monotonic() - started, 3)}


def rust_counts(result, output):
    matches = RUST_RESULT.findall(output)
    counts = {name: sum(int(row[index]) for row in matches)
              for index, name in enumerate(("passed", "failed", "ignored"))}
    result["tests"] = counts
    if result["status"] == "passed" and (counts["passed"] == 0 or counts["failed"]):
        result["status"] = "empty-or-failed-suite"
    return result


def contract_counts(result, output):
    matches = re.findall(r"^Suite result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) skipped;", output, re.MULTILINE)
    counts = {name: sum(int(row[index]) for row in matches)
              for index, name in enumerate(("passed", "failed", "ignored"))}
    result["tests"] = counts
    if result["status"] == "passed" and (not counts["passed"] or counts["failed"]):
        result["status"] = "empty-or-failed-suite"
    return result


def python_counts(result, output):
    totals = re.findall(r"^Ran (\d+) tests? in ", output, re.MULTILINE)
    skipped = re.findall(r"^OK \(skipped=(\d+)\)", output, re.MULTILINE)
    total = sum(map(int, totals))
    ignored = sum(map(int, skipped))
    result["tests"] = {"passed": total - ignored if result["status"] == "passed" else 0, "ignored": ignored}
    if result["status"] == "passed" and (total - ignored <= 0 or not re.search(r"^OK(?:$| \()", output, re.MULTILINE)):
        result["status"] = "empty-or-failed-suite"
    return result


def selection(lane, components):
    if lane != "qualification" and set(components) & {"chain", "services", "agents", "website", "security"}:
        raise ValueError("chain, services, agents, website and security require explicit qualification")
    if lane == "regression" and components:
        raise ValueError("regression runs the full native workspace; select component lanes separately")
    if lane == "qualification":
        if not components or any(component not in QUALIFICATIONS for component in components):
            raise ValueError("qualification requires a supported component: " + ", ".join(QUALIFICATIONS))
        return list(dict.fromkeys(suite for component in components for suite in QUALIFICATION_RUST[component]))
    if lane == "source" and components:
        raise ValueError("source lane has no component selection; use focused or core")
    if lane == "focused" and not components:
        raise ValueError("focused lane requires at least one --component")
    rust = list(CORE if lane == "core" else ())
    for component in components:
        for suite in RUST_COMPONENTS.get(component, []):
            if suite not in rust:
                rust.append(suite)
    return rust



def rust_build_command(suites):
    command = ["cargo", "test", "--offline", "--locked", "--no-run", "--message-format=json"]
    for package in dict.fromkeys(suite[1] for suite in suites):
        command.extend(["-p", package])
    for target, target_name in dict.fromkeys((suite[2], suite[3]) for suite in suites):
        command.append(target)
        if target_name:
            command.append(target_name)
    return command


def rust_test_executables(repository, metadata, output, suites):
    members = set(metadata["workspace_members"])
    packages = {package["name"]: package for package in metadata["packages"] if package["id"] in members}
    artifacts = []
    for line in output.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if (isinstance(message, dict) and message.get("reason") == "compiler-artifact"
                and message.get("profile", {}).get("test") and message.get("executable")):
            artifacts.append(message)
    selected = {}
    for name, package, target, target_name, _ in suites:
        owner = packages.get(package)
        if not owner:
            raise ValueError("Selected test package is not a workspace member")
        manifest = Path(owner["manifest_path"])
        if not manifest.is_absolute() or repository not in manifest.parents:
            raise ValueError("Selected test manifest is outside the repository")
        kinds = {"lib", "rlib", "cdylib", "staticlib", "dylib", "proc-macro"} if target == "--lib" else {target.removeprefix("--")}
        matches = [artifact for artifact in artifacts
                   if artifact.get("package_id") == owner["id"]
                   and artifact.get("manifest_path") == str(manifest)
                   and kinds & set(artifact.get("target", {}).get("kind", []))
                   and (target_name is None or artifact.get("target", {}).get("name") == target_name)]
        if len(matches) != 1:
            raise ValueError("Selected test executable is missing or ambiguous: " + name)
        selected[name] = (matches[0]["executable"], manifest.parent)
    return selected


def run(repository, lane, components, online=False, report_path=None, plan=False, changed_files=None, source_revision=None):
    security_selected = lane == "qualification" and "security" in components
    if security_selected and (components != ["security"] or online):
        raise ValueError("Security qualification runs alone using downloaded dependencies")
    if security_selected and not re.fullmatch(r"[0-9a-f]{40}", source_revision or ""):
        raise ValueError("Security qualification requires an exact reviewed --revision")
    if source_revision and not security_selected:
        raise ValueError("--revision is only accepted by security qualification")
    affected_plan = None
    if lane == "affected":
        if components:
            raise ValueError("affected selects its own components; use core for explicit selection")
        affected_plan = affected.select(repository, changed_files or [])
        components = affected_plan["components"]
    elif changed_files:
        raise ValueError("Changed files are only accepted by the affected lane")
    components = list(dict.fromkeys(components))
    rust = selection("core" if affected_plan else lane, components)
    if affected_plan:
        for suite in affected_plan["rust_suites"]:
            if not any(existing[1:] == suite[1:] for existing in rust):
                rust.append(suite)
    builds = affected_plan["rust_builds"] if affected_plan else []
    qualification_only = affected_plan["qualification_only"] if affected_plan else []
    selected = [name + "-compile" for name, _ in builds] + [name + "-compile" if name in qualification_only else name for name, *_ in rust] + [value for value in components if value in ("ui", "display", "dsh", "managed", "contracts", "provisioner")]
    if lane in ("source", "core", "affected", "regression"):
        selected = [name for name, _ in SOURCE_COMMANDS] + selected
    qualification_scripts = list(dict.fromkeys(script for component in components for script in QUALIFICATIONS.get(component, ()))) if lane == "qualification" else []
    selected += [Path(script).stem for script in qualification_scripts]
    if security_selected:
        selected.append("isolated-security-guards")
    if lane == "regression":
        selected.append("workspace-native")
    if lane == "qualification" and "provisioner" in components:
        selected.append("provisioner-browser")
    if plan:
        return {"lane": lane, "selected": selected, "downloads": online, "affected": affected_plan}, 0
    if report_path:
        report_path = report_path.expanduser().absolute()
        if report_path.is_symlink():
            raise ValueError("report destination must not be a link")
        report_path = report_path.parent.resolve(strict=True) / report_path.name
        if report_path == repository or repository in report_path.parents:
            raise ValueError("test reports must be outside the source checkout")
        if report_path.exists() or report_path.is_symlink():
            raise ValueError("report already exists; choose a new path")
    started = time.monotonic()
    diagnostics = Path(tempfile.mkdtemp(prefix="terrier-tests-"))
    checks = []

    def check(name, phase, command, directory=repository, rust_test=False, extra_environment=None, python_test=False, contract_test=False, timeout_seconds=600):
        log_path = diagnostics / f"{len(checks):02d}-{name}.log"
        result = execute(command, directory, log_path, timeout_seconds=timeout_seconds, extra_environment=extra_environment)
        if rust_test:
            rust_counts(result, log_path.read_text(errors="replace"))
        if contract_test:
            contract_counts(result, log_path.read_text(errors="replace"))
        if python_test:
            python_counts(result, log_path.read_text(errors="replace"))
        result.update(name=name, phase=phase, log=log_path.name)
        checks.append(result)
        print(f"{name}: {result['status']} ({result['seconds']:.3f}s)", file=sys.stderr)
        return result, log_path

    if online and (rust or builds or "managed" in components or lane == "regression"):
        setup, _ = check("dependencies", "setup", ["cargo", "fetch", "--locked"])
        if setup["status"] != "passed":
            rust, builds = [], []
    metadata = None
    if lane in ("source", "core", "affected", "regression"):
        for name, command in SOURCE_COMMANDS:
            result, log_path = check(name, "execution", command, python_test=name == "python")
            if name == "closure" and result["status"] == "passed":
                metadata = json.loads(log_path.read_text())
    if lane == "regression" and all(result["status"] == "passed" for result in checks):
        command = ["cargo", "test", "--offline", "--locked", "--workspace", "--all-targets"]
        built, _ = check("workspace-native-build", "build", command + ["--no-run"], timeout_seconds=REGRESSION_TIMEOUT_SECONDS)
        if built["status"] == "passed":
            check("workspace-native", "execution", command, rust_test=True, timeout_seconds=REGRESSION_TIMEOUT_SECONDS)
    for package, binary in builds:
        check(package + "-compile", "build", ["cargo", "check", "--offline", "--locked", "-p", package, "--bin", binary])
    if rust:
        if metadata is None:
            resolved, log_path = check("native-metadata", "build",
                ["cargo", "metadata", "--offline", "--locked", "--no-deps", "--format-version", "1"])
            if resolved["status"] == "passed":
                metadata = json.loads(log_path.read_text())
        if metadata is not None:
            built, log_path = check("selected-native-build", "build", rust_build_command(rust))
            if built["status"] == "passed":
                try:
                    executables = rust_test_executables(repository, metadata, log_path.read_text(errors="replace"), rust)
                except ValueError as error:
                    built["status"] = "missing-test-executable"
                    built["error"] = str(error)
                else:
                    for name, _, _, _, test_filter in rust:
                        if name not in qualification_only:
                            executable, directory = executables[name]
                            check(name, "execution", [executable, test_filter], directory, rust_test=True)
    qualification_environment = {name: os.environ[name] for name in ("AGENT_TERRIER_CACHE_DIR", "AGENT_TERRIER_SOLC", "AGENT_TERRIER_FORGE") if name in os.environ}
    for component in dict.fromkeys(components):
        if component == "contracts":
            build_command = [sys.executable, "terrier", "contracts", "build"]
            if not online:
                build_command.append("--offline")
            built, _ = check("contracts-build", "build", build_command, extra_environment=qualification_environment)
            if built["status"] == "passed":
                check("contracts", "execution", [sys.executable, "terrier", "contracts", "test", "--offline"],
                      extra_environment=qualification_environment, contract_test=True)
        if component == "managed":
            build, log_path = check("managed-binaries", "build", ["cargo", "build", "--offline", "--locked",
                "-p", "agentkeys-runtime", "-p", "agentkeys-daemon", "--bins", "--message-format=json"])
            if build["status"] != "passed":
                continue
            executables = {}
            for line in log_path.read_text(errors="replace").splitlines():
                try:
                    message = json.loads(line)
                except ValueError:
                    continue
                if isinstance(message, dict) and message.get("reason") == "compiler-artifact" and message.get("executable"):
                    manifest = Path(message.get("manifest_path", "")).parent
                    if manifest.is_absolute() and repository in manifest.parents:
                        executables[message["target"]["name"]] = message["executable"]
            if not all(name in executables for name in ("agent-terrier-runtime", "agentkeys-daemon")):
                build["status"] = "missing-runtime-executable"
                continue
            plugins, _ = check("managed-plugins", "build", ["npm", "run", "build"], repository / "packages")
            if plugins["status"] == "passed":
                check("managed", "execution", ["node", "--test", "packages/agent-terrier-runtime/managed.test.mjs"],
                    extra_environment={"AGENT_TERRIER_TEST_RUNTIME_BINARY": executables["agent-terrier-runtime"],
                        "AGENT_TERRIER_TEST_DAEMON_BINARY": executables["agentkeys-daemon"]})
        if component in ("ui", "display", "dsh", "provisioner"):
            directory = repository / {"ui": "apps/parent-control", "display": "apps/device-display", "dsh": "packages", "provisioner": "provisioner-scripts"}[component]
            if component == "display":
                check("display-routes", "build", ["npm", "run", "generate-routes"], directory)
            check(component + "-types", "build", ["npm", "run", "typecheck"], directory)
            if component == "dsh":
                check(component + "-build", "build", ["npm", "run", "build"], directory)
            check(component, "execution", ["npm", "test"], directory)
            if component == "provisioner" and lane == "qualification":
                check("provisioner-browser", "execution", ["npm", "run", "test:browser"], directory)
    if lane == "qualification" and "agents" in components:
        qualification_environment.update({name: os.environ[name] for name in ("AGENT_TERRIER_TEST_AGENT_IMAGE", "AGENT_TERRIER_TEST_DOCKER_SOCKET") if name in os.environ})
    for script in qualification_scripts:
        check(Path(script).stem, "execution", [sys.executable, "scripts/tests/" + script],
              extra_environment=qualification_environment, python_test=True)
    security_provenance = None
    if security_selected:
        from . import security_qualification
        security_checks, security_provenance = security_qualification.run(repository, source_revision, diagnostics)
        checks.extend(security_checks)
    elapsed = round(time.monotonic() - started, 3)
    target = None if lane in ("qualification", "regression") else (30 if lane == "focused" else 180)
    success = bool(checks) and all(check["status"] == "passed" for check in checks)
    revision = os.environ.get("GITHUB_SHA", "") if os.environ.get("GITHUB_ACTIONS") == "true" else ""
    report = {
        "schema_version": 1, "lane": lane, "selected": selected, "success": success, "affected": affected_plan,
        "revision": revision if re.fullmatch(r"[0-9a-f]{40}", revision) else None,
        "security_qualification": security_provenance,
        "runner": {"system": platform.system(), "architecture": platform.machine()},
        "seconds": elapsed, "warm_target_seconds": target, "target_exceeded": elapsed > target if target is not None else None,
        "phase_seconds": {phase: round(sum(check["seconds"] for check in checks if check["phase"] == phase), 3)
                          for phase in ("setup", "build", "execution")},
        "queue_seconds": None, "cleanup_seconds": round(sum(check["seconds"] for check in checks if check["phase"] == "cleanup"), 3) if security_selected else None,
        "checks": checks,
    }
    print(f"Private diagnostic logs: {diagnostics}", file=sys.stderr)
    if report_path:
        descriptor = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    return report, 0 if success else 1
