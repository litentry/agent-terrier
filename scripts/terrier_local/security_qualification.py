"""Explicit, disposable mutations of reviewed public authorization guards."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import time

from . import contracts

SOURCE_PATH = "crates/agentkeys-core/src/capability_verify.rs"
TEST_PREFIX = "capability_verify::tests::"
GUARDS = (
    ("operation", "if token.payload.op != expected {", "if false && token.payload.op != expected {",
     "check_op_accepts_match", "check_op_rejects_mismatch", "assertion failed"),
    ("data-class", "if token.payload.data_class != expected {", "if false && token.payload.data_class != expected {",
     "check_data_class_accepts_match", "check_data_class_rejects_cross_class", "expected DataClassMismatch, got Ok(())"),
    ("chain-scope", "if !parse_bool(&raw)? {", "if false && !parse_bool(&raw)? {",
     "check_chain_scope_ok_when_chain_grants", "check_chain_scope_rejects_when_chain_denies",
     "ungranted cross-actor scope must be NotInScope (got Ok(()))"),
    ("actor-proof", "check_client_pop(token, CAP_POP_MAX_AGE_SECS)",
     "if token.client_sig.is_none() { Ok(()) } else { check_client_pop(token, CAP_POP_MAX_AGE_SECS) }",
     "check_client_pop_accepts_valid", "missing_actor_proof_is_rejected_without_a_rollout_flag", "assertion failed"),
)


def apply_guard(source, guard):
    production, boundary, tests = source.partition("#[cfg(test)]")
    original, replacement = guard[1:3]
    if not boundary or production.count(original) != 1 or replacement in production:
        raise ValueError("Guard source changed; review the mutation recipe")
    return production.replace(original, replacement, 1) + boundary + tests


def detected(result, output, test_name, assertion):
    from .test_lanes import RUST_RESULT
    return (result["status"] == "failed" and result["exit_code"] == 101
            and RUST_RESULT.findall(output) == [("0", "1", "0")]
            and f"test {TEST_PREFIX}{test_name} ... FAILED" in output
            and assertion in output)


def export_revision(repository, revision, destination):
    if not re.fullmatch(r"[0-9a-f]{40}", revision or ""):
        raise ValueError("Security qualification requires an exact reviewed --revision")

    def read(*arguments):
        result = subprocess.run(["jj", "--ignore-working-copy", *arguments], cwd=repository,
            env=contracts.tool_environment(), capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError("Could not read the selected public revision with jj")
        return result.stdout

    if read("log", "-r", revision, "--no-graph", "-T", "commit_id").decode().strip() != revision:
        raise ValueError("Revision did not resolve exactly")
    entries = read("file", "list", "-r", revision, "-T", 'path ++ "\\t" ++ file_type ++ "\\n"').decode().splitlines()
    paths = []
    for entry in entries:
        path, kind = entry.split("\t")
        relative = PurePosixPath(path)
        if (kind != "file" or relative.is_absolute() or ".." in relative.parts
                or path != relative.as_posix() or any(ord(character) < 32 for character in path)):
            raise ValueError("Only normalized regular public source files can be exported")
        paths.append(path)
    if SOURCE_PATH not in paths or len(set(paths)) != len(paths):
        raise ValueError("Public revision has missing or duplicated source paths")

    def copy(path):
        contents = read("file", "show", "-r", revision, path)
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents)
        return path, hashlib.sha256(contents).hexdigest()

    with ThreadPoolExecutor(max_workers=4) as executor:
        manifest = dict(executor.map(copy, paths))
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(), len(paths)


def run(repository, revision, diagnostics):
    from . import test_lanes
    checks = []
    isolation = Path(tempfile.mkdtemp(prefix="terrier-guard-copy-")).resolve()
    source = isolation / "source"
    source.mkdir()
    environment = {"CARGO_TARGET_DIR": str(isolation / "target"), "CARGO_INCREMENTAL": "0"}
    provenance = {"source_revision": revision, "guards": [guard[0] for guard in GUARDS],
                  "recipe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}

    def check(name, phase, command, rust=False):
        log = diagnostics / f"security-{len(checks):02d}-{name}.log"
        result = test_lanes.execute(command, source, log, timeout_seconds=1800 if phase == "build" else 60,
            extra_environment=environment)
        output = log.read_text(errors="replace") if log.exists() else ""
        if rust:
            test_lanes.rust_counts(result, output)
            if result["status"] == "passed" and result["tests"] != {"passed": 1, "failed": 0, "ignored": 0}:
                result["status"] = "wrong-test-count"
        result.update(name="security-" + name, phase=phase, log=log.name)
        checks.append(result)
        print(f"{result['name']}: {result['status']} ({result['seconds']:.3f}s)", file=sys.stderr)
        return result, output

    try:
        started = time.monotonic()
        digest, count = export_revision(repository, revision, source)
        provenance.update(source_tree_sha256=digest, source_files=count)
        specification = importlib.util.spec_from_file_location("security_public_scan", repository / "scripts/check-public.py")
        scanner = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(scanner)
        if scanner.inspect_tree(source)["findings"]:
            raise ValueError("Selected source failed the public privacy boundary; nothing was built")
        checks.append({"name": "security-source", "phase": "setup", "status": "passed",
                       "seconds": round(time.monotonic() - started, 3)})
        metadata_result, metadata_output = check("metadata", "build",
            ["cargo", "metadata", "--offline", "--locked", "--no-deps", "--format-version", "1"])
        if metadata_result["status"] != "passed":
            return checks, provenance
        metadata = json.loads(metadata_output)
        suites = [("guard", "agentkeys-core", "--lib", None, "")]

        def build(name):
            result, output = check(name, "build", test_lanes.rust_build_command(suites))
            if result["status"] != "passed":
                return None
            executable, _ = test_lanes.rust_test_executables(source, metadata, output, suites)["guard"]
            return executable

        executable = build("baseline-build")
        if not executable:
            return checks, provenance
        for guard in GUARDS:
            for test in guard[3:5]:
                result, _ = check("baseline-" + test, "execution",
                    [executable, TEST_PREFIX + test, "--exact", "--nocapture"], rust=True)
                if result["status"] != "passed":
                    return checks, provenance
        target = source / SOURCE_PATH
        original = target.read_text()
        for guard in GUARDS:
            name, _, _, positive, negative, assertion = guard
            try:
                target.write_text(apply_guard(original, guard))
                executable = build(name + "-build")
                if not executable:
                    return checks, provenance
                control, _ = check(name + "-positive", "execution",
                    [executable, TEST_PREFIX + positive, "--exact", "--nocapture"], rust=True)
                if control["status"] != "passed":
                    return checks, provenance
                result, output = check(name + "-negative", "execution",
                    [executable, TEST_PREFIX + negative, "--exact", "--nocapture"])
                if detected(result, output, negative, assertion):
                    result.update(status="passed", outcome="guard-detected", expected_test_exit_code=101)
                else:
                    result.update(status="guard-not-proven", outcome="invalid-or-survived")
                    return checks, provenance
            finally:
                target.write_text(original)
        return checks, provenance
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        log = diagnostics / "security-infrastructure.log"
        log.write_text(f"{type(error).__name__}: {error}\n")
        checks.append({"name": "security-infrastructure", "phase": "setup", "status": "failed", "seconds": 0, "log": log.name})
        return checks, provenance
    finally:
        started = time.monotonic()
        shutil.rmtree(isolation)
        checks.append({"name": "security-cleanup", "phase": "cleanup", "status": "passed",
                       "seconds": round(time.monotonic() - started, 3)})
