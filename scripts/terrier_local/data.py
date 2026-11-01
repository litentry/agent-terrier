import subprocess
import sys

from . import contracts, deployment, owner, services


def command_context(repository, state, name):
    owner.validate_name(name)
    _, _, fingerprint = deployment.active_profile(repository, state)
    directory = state / "owners" / name
    identity = owner.read_identity(directory, fingerprint)
    running = services.status(state)
    if not running.get("ready"):
        raise RuntimeError("Start healthy local services before local data operations")
    identity_arguments = ["--operator-omni", identity["operator_omni"],
        "--device-key-file", str(directory / "device.key"), "--session-file", str(directory / "session.json"),
        "--broker-url", running["services"]["broker"]["url"]]
    environment = contracts.tool_environment()
    environment.update(AGENT_TERRIER_LOCAL_DEV="1", AGENTKEYS_CHAIN_PROFILE_FILE=str(state / "chain-profile.json"))
    return identity_arguments, running, environment


def credential(repository, state, action, name, service, secret_stdin):
    if action not in ("store", "fetch") or (action == "store") != secret_stdin:
        raise ValueError("Only credential store requires --secret-stdin")
    identity, running, environment = command_context(repository, state, name)
    arguments = [str(owner.executable(repository)), "local", "credential", action, service,
                 *identity, "--cred-url", running["services"]["credentials"]["url"]]
    if secret_stdin:
        arguments.append("--secret-stdin")
    return subprocess.run(arguments, stdin=sys.stdin if secret_stdin else subprocess.DEVNULL,
        env=environment, timeout=45, umask=0o077).returncode


def channel(repository, state, options):
    if (options.action == "publish") != options.text_stdin:
        raise ValueError("Only channel publish requires --text-stdin")
    if options.action != "poll" and (options.after or options.wait_seconds):
        raise ValueError("Cursor and wait options require channel poll")
    identity, running, environment = command_context(repository, state, options.name)
    arguments = [str(owner.executable(repository)), "local", "channel", options.action, options.channel,
        *identity, "--channel-url", running["services"]["channel"]["url"],
        "--after", options.after, "--wait-seconds", str(options.wait_seconds)]
    if options.text_stdin:
        arguments.append("--text-stdin")
    return subprocess.run(arguments, stdin=sys.stdin if options.text_stdin else subprocess.DEVNULL,
        env=environment, timeout=45, umask=0o077).returncode
