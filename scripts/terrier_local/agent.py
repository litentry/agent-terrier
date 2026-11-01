import subprocess

from . import contracts, deployment, local_state, owner, services


def execute(repository, state, arguments):
    owner.validate_name(arguments.name)
    _, _, fingerprint = deployment.active_profile(repository, state)
    directory = state / "owners" / arguments.name
    identity = owner.read_identity(directory, fingerprint)
    running = services.status(state)
    if not running.get("ready"):
        raise RuntimeError("Start healthy local services before agent operations")
    if arguments.action == "spawn" and not running.get("runtime"):
        raise ValueError("Configure a preloaded runtime image and Docker socket before creating an agent")
    operations = directory / "operations"
    if arguments.action != "bridge":
        operations = local_state.private_directory(operations)
    command = [str(owner.executable(repository)), "local", "agent",
        "--operator-omni", identity["operator_omni"], "--device-key-file", str(directory / "device.key"),
        "--session-file", str(directory / "session.json"), "--key-file", str(directory / "passkey.pem"),
        "--broker-url", running["services"]["broker"]["url"], "--operations-dir", str(operations), arguments.action]
    if arguments.action in ("spawn", "archive"):
        command.extend(["--memory-ns", arguments.memory_ns])
    if arguments.action == "spawn":
        command.extend(["--label", arguments.label, "--preset-id", arguments.preset_id])
        if arguments.memory_inherited:
            command.append("--memory-inherited")
    elif arguments.action == "bridge":
        command.extend(["--device-key-hash", arguments.device_key_hash, "--path", arguments.path,
            "--method", arguments.method])
        if arguments.sandbox_id:
            command.extend(["--sandbox-id", arguments.sandbox_id])
        if arguments.json_stdin:
            command.append("--json-stdin")
        if arguments.timeout_seconds is not None:
            command.extend(["--timeout-seconds", str(arguments.timeout_seconds)])
    elif arguments.action == "archive":
        command.extend(["--device-key-hash", arguments.device_key_hash])
    else:
        operation_hash = arguments.user_op_hash
        if (not operation_hash.startswith("0x") or len(operation_hash) != 66
                or any(character not in "0123456789abcdefABCDEF" for character in operation_hash[2:])):
            raise ValueError("Operation hash must be a prefixed 32-byte hash")
        command.extend(["--operation-file", str(operations / (operation_hash.lower() + ".json"))])
    environment = contracts.tool_environment()
    environment.update(AGENT_TERRIER_LOCAL_DEV="1", AGENTKEYS_CHAIN_PROFILE_FILE=str(state / "chain-profile.json"))
    stdin = None if arguments.action == "bridge" and arguments.json_stdin else subprocess.DEVNULL
    timeout = None if arguments.action == "bridge" else 150
    return subprocess.run(command, stdin=stdin, env=environment, timeout=timeout, umask=0o077).returncode
