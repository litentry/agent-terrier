import subprocess
import sys

from . import contracts, deployment, owner, services


def credential(repository, state, action, name, service, secret_stdin):
    owner.validate_name(name)
    if action not in ("store", "fetch") or (action == "store") != secret_stdin:
        raise ValueError("Only credential store requires --secret-stdin")
    _, _, fingerprint = deployment.active_profile(repository, state)
    directory = state / "owners" / name
    identity = owner.read_identity(directory, fingerprint)
    running = services.status(state)
    if not running.get("ready"):
        raise RuntimeError("Start healthy local services before credential operations")
    arguments = [str(owner.executable(repository)), "local", "credential", action, service,
        "--operator-omni", identity["operator_omni"], "--device-key-file", str(directory / "device.key"),
        "--session-file", str(directory / "session.json"),
        "--broker-url", running["services"]["broker"]["url"],
        "--cred-url", running["services"]["credentials"]["url"]]
    if secret_stdin:
        arguments.append("--secret-stdin")
    environment = contracts.tool_environment()
    environment.update(AGENT_TERRIER_LOCAL_DEV="1", AGENTKEYS_CHAIN_PROFILE_FILE=str(state / "chain-profile.json"))
    return subprocess.run(arguments, stdin=sys.stdin if secret_stdin else subprocess.DEVNULL,
        env=environment, timeout=45, umask=0o077).returncode
