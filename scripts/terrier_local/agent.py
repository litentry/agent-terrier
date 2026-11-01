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
    operations = local_state.private_directory(directory / "operations")
    command = [str(owner.executable(repository)), "local", "agent",
        "--operator-omni", identity["operator_omni"], "--device-key-file", str(directory / "device.key"),
        "--session-file", str(directory / "session.json"), "--key-file", str(directory / "passkey.pem"),
        "--broker-url", running["services"]["broker"]["url"], "--operations-dir", str(operations), arguments.action]
    if arguments.action != "receipt":
        command.extend(["--memory-ns", arguments.memory_ns])
    if arguments.action == "spawn":
        command.extend(["--label", arguments.label, "--preset-id", arguments.preset_id])
        if arguments.memory_inherited:
            command.append("--memory-inherited")
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
    return subprocess.run(command, stdin=subprocess.DEVNULL, env=environment, timeout=150, umask=0o077).returncode
