from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

from . import chain, contracts, deployment, local_state, services, stack

LOCKS = {"operation.lock", "chain.lock", "services.lock"}
DIRECTORIES = {"owners", "devices", "deployer", "deployment", "chain", "services"}
FILES = {"chain-profile.json", "chain.log", "chain-supervisor.log", "services-supervisor.log", "deployment.log"}
SOCKETS = {chain.SOCKET_NAME, services.SOCKET_NAME}


def validate_tree(state):
    def check(path, root=False):
        metadata = path.lstat()
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
            raise ValueError("Reset refuses state owned or writable by another user")
        if stat.S_ISDIR(metadata.st_mode):
            for child in path.iterdir():
                if root and child.name not in DIRECTORIES | FILES | LOCKS | SOCKETS:
                    raise ValueError("Reset refuses an unrecognized entry in the state directory")
                check(child)
        elif stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise ValueError("Reset refuses hard-linked state files")
        elif not (path.parent == state and path.name in SOCKETS and stat.S_ISSOCK(metadata.st_mode)):
            raise ValueError("Reset refuses symlinks and unexpected special files")
    check(state, True)
    for path in state.iterdir():
        if path.name in DIRECTORIES and not path.is_dir():
            raise ValueError("Reset state directory has an unexpected type")


def execute(repository, state, confirmation):
    if state != state.resolve() or confirmation is None or not Path(confirmation).is_absolute() or str(state) != str(confirmation):
        raise ValueError("Reset deletes local keys, chain state and data; --confirm-state must exactly match the selected absolute state directory")
    if state == Path.home().resolve() or state in repository.resolve().parents or len(state.parts) < 3:
        raise ValueError("Reset refuses a home, repository ancestor or filesystem root")
    if not shutil.rmtree.avoids_symlink_attacks:
        raise ValueError("This platform cannot safely remove local state directories")
    validate_tree(state)
    profile_path = state / "chain-profile.json"
    contents = {path.name for path in state.iterdir()} - LOCKS
    if not contents:
        return {"development_only":True, "success":True, "action":"reset", "state_preserved":False, "reset_actors":0}
    profile = local_state.read_json(profile_path)
    expected = chain.default_profile(repository)
    if (not isinstance(profile, dict) or not isinstance(profile.get("contracts"), list)
            or profile.get("name") != expected["name"] or profile.get("chain_id") != expected["chain_id"]
            or profile.get("dev_environment", {}).get("is_development_default") is not True):
        raise ValueError("Reset requires an explicit local development profile")
    chain.rpc_location(profile.get("rpc", {}).get("http", ""))
    manifest_path = state / "services/manifest.json"
    configuration = None
    if (state / "services").exists():
        manifest = local_state.read_json(manifest_path)
        services.validate_manifest(manifest, deployment.profile_identity(profile))
        configuration = services.runtime_configuration(manifest)
        model_runner = manifest.get("model_runner")
        if model_runner is not None:
            if (not isinstance(model_runner, dict) or set(model_runner) != {"directory", "binary"}
                    or not isinstance(model_runner["directory"], str) or not Path(model_runner["directory"]).is_absolute()):
                raise ValueError("Reset requires valid model directory metadata")
            model_directory = Path(model_runner["directory"]).resolve()
            if model_directory == state or state in model_directory.parents:
                raise ValueError("Move downloaded models outside the selected state before reset")
        if configuration is not None:
            services.validate_runtime_configuration(configuration)
    reset_binary = Path(os.environ.get("AGENT_TERRIER_BIN_DIR", repository / "target/debug")) / "agent-terrier-reset-runtime"
    if configuration is not None and not reset_binary.is_file():
        raise ValueError("Build agent-terrier-reset-runtime before resetting a configured runtime")
    stack.stop(state)
    with ExitStack() as locks:
        for name in sorted(LOCKS - {"operation.lock"}):
            locks.enter_context(local_state.exclusive_lock(state / name, timeout=services.STOP_TIMEOUT))
        validate_tree(state)
        actors = 0
        if configuration is not None:
            environment = contracts.tool_environment()
            environment.update(services.runtime_environment(repository, state / "services", configuration))
            result = subprocess.run([str(reset_binary), "--development", "--profile", str(profile_path),
                "--namespace", configuration["namespace"], "--confirm-namespace", configuration["namespace"],
                "--socket", configuration["socket"], "--image", configuration["image"]],
                env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180)
            if result.returncode:
                raise RuntimeError("Runtime reset failed; local state is retained. " + result.stderr.strip())
            receipt = json.loads(result.stdout)
            if receipt.get("development_only") is not True or type(receipt.get("reset_actors")) is not int:
                raise ValueError("Runtime reset returned an invalid receipt; local state is retained")
            actors = receipt["reset_actors"]
        for name in sorted(DIRECTORIES - {"services"}) + ["services"]:
            path = state / name
            if path.exists():
                shutil.rmtree(path)
        for name in sorted((FILES | SOCKETS) - {"chain-profile.json"}):
            (state / name).unlink(missing_ok=True)
        if {path.name for path in state.iterdir()} - LOCKS - {"chain-profile.json"}:
            raise ValueError("Unexpected state remains after reset; it was preserved")
        profile_path.unlink()
    return {"development_only":True, "success":True, "action":"reset", "state_preserved":False, "reset_actors":actors}
