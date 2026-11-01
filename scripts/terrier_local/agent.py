import subprocess

from . import contracts, deployment, owner, services


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
    command = [str(owner.executable(repository)), "local", "agent",
        "--operator-omni", identity["operator_omni"], "--device-key-file", str(directory / "device.key"),
        "--session-file", str(directory / "session.json"), "--key-file", str(directory / "passkey.pem"),
        "--broker-url", running["services"]["broker"]["url"], arguments.action,
        "--memory-ns", arguments.memory_ns]
    if arguments.action == "spawn":
        command.extend(["--label", arguments.label, "--preset-id", arguments.preset_id])
        if arguments.memory_inherited:
            command.append("--memory-inherited")
    else:
        command.extend(["--device-key-hash", arguments.device_key_hash])
    environment = contracts.tool_environment()
    environment.update(AGENT_TERRIER_LOCAL_DEV="1", AGENTKEYS_CHAIN_PROFILE_FILE=str(state / "chain-profile.json"))
    return subprocess.run(command, stdin=subprocess.DEVNULL, env=environment, timeout=150, umask=0o077).returncode
