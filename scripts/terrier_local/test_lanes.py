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

from . import contracts

COMPONENTS = ("protocol", "runtime", "broker", "signer", "daemon", "storage", "cli", "ui", "dsh")
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
    "broker": [("broker", "agentkeys-broker-server", "--lib", None, "")],
    "signer": [("signer", "agentkeys-mock-server", "--lib", None, ""),
               ("signer-routes", "agentkeys-mock-server", "--test", "dev_key_service_routes", ""),
               ("signer-startup", "agentkeys-mock-server", "--test", "local_signer_startup", "")],
    "daemon": [("daemon", "agentkeys-daemon", "--bin", "agentkeys-daemon", "")],
    "storage": [("storage", "agentkeys-local-store", "--lib", None, "")],
    "cli": [("cli", "agentkeys-cli", "--lib", None, "")],
}
SOURCE_COMMANDS = (
    ("privacy", ["python3", "scripts/check-public.py"]),
    ("python", ["python3", "-m", "unittest", "discover", "-s", "scripts/tests"]),
    ("web-server", ["node", "--test", "scripts/tests/web-ssr-server.test.mjs"]),
    ("closure", ["cargo", "metadata", "--offline", "--locked", "--no-deps", "--format-version", "1"]),
)
RUST_RESULT = re.compile(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;")


def execute(command, directory, log_path, timeout_seconds=600):
    started = time.monotonic()
    status = "passed"
    with log_path.open("xb") as output:
        try:
            process = subprocess.Popen(command, cwd=directory, env=contracts.tool_environment(),
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


def selection(lane, components):
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


def run(repository, lane, components, online=False, report_path=None, plan=False):
    components = list(dict.fromkeys(components))
    rust = selection(lane, components)
    selected = [name for name, *_ in rust] + [value for value in components if value in ("ui", "dsh")]
    if lane != "focused":
        selected = [name for name, _ in SOURCE_COMMANDS] + selected
    if plan:
        return {"lane": lane, "selected": selected, "downloads": online}, 0
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

    def check(name, phase, command, directory=repository, rust_test=False):
        log_path = diagnostics / f"{len(checks):02d}-{name}.log"
        result = execute(command, directory, log_path)
        if rust_test:
            rust_counts(result, log_path.read_text(errors="replace"))
        result.update(name=name, phase=phase, log=log_path.name)
        checks.append(result)
        print(f"{name}: {result['status']} ({result['seconds']:.3f}s)", file=sys.stderr)
        return result, log_path

    if online and rust:
        setup, _ = check("dependencies", "setup", ["cargo", "fetch", "--locked"])
        if setup["status"] != "passed":
            rust = []
    if lane != "focused":
        for name, command in SOURCE_COMMANDS:
            check(name, "execution", command)
    for name, package, target, target_name, test_filter in rust:
        command = ["cargo", "test", "--offline", "--locked", "-p", package, target]
        if target_name:
            command.append(target_name)
        build, log_path = check(name + "-build", "build", command + ["--no-run", "--message-format=json"])
        if build["status"] != "passed":
            continue
        executables = []
        for line in log_path.read_text(errors="replace").splitlines():
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if (isinstance(message, dict) and message.get("reason") == "compiler-artifact" and message.get("profile", {}).get("test")
                    and message.get("executable")):
                manifest = Path(message.get("manifest_path", "")).parent
                if manifest.is_absolute() and repository in manifest.parents:
                    executables.append((message["executable"], manifest))
        if len(executables) != 1:
            build["status"] = "missing-test-executable"
            continue
        executable, directory = executables[0]
        check(name, "execution", [executable, test_filter], directory, rust_test=True)
    for component in dict.fromkeys(components):
        if component in ("ui", "dsh"):
            directory = repository / ("apps/parent-control" if component == "ui" else "packages")
            check(component + "-types", "build", ["npm", "run", "typecheck"], directory)
            if component == "dsh":
                check(component + "-build", "build", ["npm", "run", "build"], directory)
            check(component, "execution", ["npm", "test"], directory)
    elapsed = round(time.monotonic() - started, 3)
    target = 30 if lane == "focused" else 180
    success = bool(checks) and all(check["status"] == "passed" for check in checks)
    revision = os.environ.get("GITHUB_SHA", "") if os.environ.get("GITHUB_ACTIONS") == "true" else ""
    report = {
        "schema_version": 1, "lane": lane, "selected": selected, "success": success,
        "revision": revision if re.fullmatch(r"[0-9a-f]{40}", revision) else None,
        "runner": {"system": platform.system(), "architecture": platform.machine()},
        "seconds": elapsed, "warm_target_seconds": target, "target_exceeded": elapsed > target,
        "phase_seconds": {phase: round(sum(check["seconds"] for check in checks if check["phase"] == phase), 3)
                          for phase in ("setup", "build", "execution")},
        "queue_seconds": None, "cleanup_seconds": None,
        "checks": checks,
    }
    if report_path:
        descriptor = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    print(f"Private diagnostic logs: {diagnostics}", file=sys.stderr)
    return report, 0 if success else 1
