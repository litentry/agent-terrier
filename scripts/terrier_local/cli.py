import argparse
import json
from pathlib import Path
import subprocess
import sys

from . import agent, chain, contracts, data, deployment, local_state, models, owner, services, stack, manager, test_lanes, affected


def build_parser():
    parser = argparse.ArgumentParser(prog="terrier", description="Agent Terrier local development tools")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("manage", help="Open the lightweight terminal manager for the local backend stack")
    stack_parser = commands.add_parser("stack", help="Compose the existing local chain and service controllers")
    stack_parser.add_argument("action", choices=["start", "status", "doctor", "logs", "stop", "restart"])
    stack_parser.add_argument("--chain-port", type=int, help="Loopback RPC port; defaults to the saved profile")
    stack_parser.add_argument("--bin-dir", type=Path)
    stack_parser.add_argument("--broker-port", type=int)
    stack_parser.add_argument("--runtime-image")
    stack_parser.add_argument("--docker-socket", type=Path)
    test_parser = commands.add_parser("test", help="Run measured source, core, focused or explicit qualification lanes")
    test_parser.add_argument("lane", choices=["source", "core", "focused", "affected", "qualification"])
    test_parser.add_argument("--component", action="append", default=[], choices=test_lanes.COMPONENTS)
    test_parser.add_argument("--changed-file", action="append", default=[], help="Changed repository-relative path; include old and new paths for renames")
    test_parser.add_argument("--changed-files-json", type=Path, help="JSON array of changed repository-relative paths")
    test_parser.add_argument("--online", action="store_true", help="Explicitly fetch Cargo dependencies before Rust tests")
    test_parser.add_argument("--report", type=Path, help="New JSON report path outside the checkout")
    test_parser.add_argument("--plan", action="store_true", help="Print selection without running tools")
    model_parser = commands.add_parser("models", help="Qualify actual local model capabilities")
    model_parser.add_argument("action", choices=["config", "probe"])
    model_parser.add_argument("--base-url")
    model_parser.add_argument("--chat-model")
    model_parser.add_argument("--embedding-model")
    contract_parser = commands.add_parser("contracts", help="Prepare, build and test public contracts")
    contract_parser.add_argument("action", choices=["setup", "build", "test"])
    contract_parser.add_argument("--offline", action="store_true", help="Use downloaded dependencies only")
    contract_parser.add_argument("--match-test", help="Run matching contract tests")
    chain_parser = commands.add_parser("chain", help="Manage an owned local development chain")
    chain_parser.add_argument("action", choices=["start", "status", "stop", "logs", "deploy"])
    chain_parser.add_argument("--port", type=int, help="Loopback RPC port for chain start")
    chain_parser.add_argument("--offline", action="store_true", help="Deploy using downloaded dependencies only")
    chain_parser.add_argument("--resume", action="store_true", help="Explicitly resume an interrupted deployment")
    service_parser = commands.add_parser("services", help="Manage the local broker and storage services")
    service_parser.add_argument("action", choices=["start", "status", "doctor", "logs", "stop"])
    service_parser.add_argument("--bin-dir", type=Path, help="Directory containing built public service binaries")
    service_parser.add_argument("--broker-port", type=int, help="Broker port for the first service startup")
    service_parser.add_argument("--runtime-image", help="Enable the managed runtime with a reviewed preloaded local image")
    service_parser.add_argument("--docker-socket", type=Path, help="Explicit local Docker Unix socket; required with --runtime-image")
    credential_parser = commands.add_parser("cred", help="Use an existing local owner session for credentials")
    credential_parser.add_argument("action", choices=["store", "fetch"])
    credential_parser.add_argument("service")
    credential_parser.add_argument("--name", required=True, help="Local owner name")
    credential_parser.add_argument("--secret-stdin", action="store_true", help="Read exact UTF-8 input for store")
    agent_parser = commands.add_parser("agent", help="Manage local agents and call their authenticated bridge")
    agent_commands = agent_parser.add_subparsers(dest="action", required=True)
    for action in ("spawn", "archive", "receipt", "bridge"):
        operation = agent_commands.add_parser(action)
        operation.add_argument("--name", required=True, help="Existing local owner name")
        if action in ("spawn", "archive"):
            operation.add_argument("--memory-ns", default="")
        if action == "spawn":
            operation.add_argument("--label", required=True)
            operation.add_argument("--preset-id", default="")
            operation.add_argument("--memory-inherited", action="store_true")
        elif action == "bridge":
            operation.add_argument("--device-key-hash", required=True)
            operation.add_argument("--sandbox-id")
            operation.add_argument("--path", required=True, help="Existing broker-allowlisted route")
            operation.add_argument("--method", choices=["GET", "POST"], default="POST")
            operation.add_argument("--json-stdin", action="store_true")
            operation.add_argument("--timeout-seconds", type=int)
        elif action == "archive":
            operation.add_argument("--device-key-hash", required=True)
        else:
            operation.add_argument("--user-op-hash", required=True)
    owner_parser = commands.add_parser("owner", help="Real local owner registration and scope operations")
    owner_parser.add_argument("action", choices=["register", "grant", "revoke", "bind", "unbind", "login"])
    owner_parser.add_argument("--name", required=True, help="Local owner name")
    owner_parser.add_argument("--actor-omni")
    owner_parser.add_argument("--service", action="append", default=[])
    owner_parser.add_argument("--read-only", action="store_true")
    owner_parser.add_argument("--enrollment-file", type=Path)
    owner_parser.add_argument("--broker-url", help="Loopback broker endpoint for owner login")
    device_parser = commands.add_parser("device", help="Create a local actor-owned identity and public proof")
    device_parser.add_argument("action", choices=["identity"])
    device_parser.add_argument("--name", required=True)
    device_parser.add_argument("--operator-omni", required=True)
    device_parser.add_argument("--label", required=True)
    device_parser.add_argument("--kind", required=True, choices=["device", "delegate"])
    supervisor = commands.add_parser("_serve-chain", help=argparse.SUPPRESS)
    supervisor.add_argument("--port", type=int, required=True)
    supervisor.add_argument("--anvil", required=True)
    service_supervisor = commands.add_parser("_serve-services", help=argparse.SUPPRESS)
    service_supervisor.add_argument("--bin-dir", type=Path, required=True)
    return parser


def main(argv=None):
    arguments = build_parser().parse_args(argv)
    repository = Path(__file__).resolve().parents[2]
    try:
        if arguments.command == "manage":
            print(f"Local state: {local_state.state_directory(repository)}")
            return manager.run(main)
        if arguments.command == "test":
            changed_files = arguments.changed_file
            if arguments.changed_files_json:
                changed_files.extend(affected.paths_from_json(arguments.changed_files_json))
            report, exit_code = test_lanes.run(repository, arguments.lane, arguments.component,
                arguments.online, arguments.report, arguments.plan, changed_files)
            print(json.dumps(report, indent=2))
            return exit_code
        if arguments.command == "contracts":
            return contracts.run(repository, arguments.action, arguments.offline, arguments.match_test)
        if arguments.command == "models":
            result = models.run(repository, arguments.action, arguments.base_url, arguments.chat_model, arguments.embedding_model)
            print(json.dumps(result, indent=2))
            return 0
        state = local_state.state_directory(repository)
        if arguments.command == "stack":
            configuration = (arguments.chain_port, arguments.bin_dir, arguments.broker_port,
                             arguments.runtime_image, arguments.docker_socket)
            if arguments.action not in ("start", "restart") and any(value is not None for value in configuration):
                raise ValueError("Stack configuration options require start or restart")
            if arguments.action == "logs":
                return stack.logs(state)
            if arguments.action in ("status", "doctor"):
                result = stack.execute(repository, state, arguments.action)
            else:
                with local_state.exclusive_lock(state / "operation.lock"):
                    result = stack.execute(repository, state, arguments.action, *configuration)
            print(json.dumps(result, indent=2))
            return 0 if result["success"] else 1
        if arguments.command == "agent":
            with local_state.exclusive_lock(state / "operation.lock"):
                return agent.execute(repository, state, arguments)
        if arguments.command == "cred":
            with local_state.exclusive_lock(state / "operation.lock"):
                return data.credential(repository, state, arguments.action, arguments.name,
                                       arguments.service, arguments.secret_stdin)
        if arguments.command == "_serve-services":
            return services.serve(repository, state, arguments.bin_dir)
        if arguments.command == "services":
            if arguments.action != "start" and (arguments.bin_dir is not None or arguments.broker_port is not None or arguments.runtime_image is not None or arguments.docker_socket is not None):
                raise ValueError("Service configuration options are only valid for services start")
            if arguments.action == "logs":
                return services.logs(state)
            if arguments.action in ("status", "doctor"):
                result = services.status(state)
            else:
                with local_state.exclusive_lock(state / "operation.lock"):
                    result = (services.start(repository, state, arguments.bin_dir, arguments.broker_port, arguments.runtime_image, arguments.docker_socket)
                              if arguments.action == "start" else services.stop(state))
            print(json.dumps(result, indent=2))
            return 1 if arguments.action == "doctor" and not result.get("ready") else 0
        if arguments.command == "device":
            with local_state.exclusive_lock(state / "operation.lock"):
                result = owner.device_identity(repository, state, arguments.name, arguments.operator_omni,
                                               arguments.label, arguments.kind)
            print(json.dumps(result, indent=2))
            return 0
        if arguments.command == "owner":
            with local_state.exclusive_lock(state / "operation.lock"):
                result = owner.execute(repository, state, arguments.action, arguments.name,
                                       arguments.actor_omni, arguments.service, arguments.read_only,
                                       arguments.enrollment_file, arguments.broker_url)
            print(json.dumps(result, indent=2))
            return 0
        if arguments.command == "_serve-chain":
            return chain.serve(repository, state, arguments.port, arguments.anvil)
        if arguments.port is not None and arguments.action != "start":
            raise ValueError("--port is only valid for chain start")
        if (arguments.offline or arguments.resume) and arguments.action != "deploy":
            raise ValueError("--offline and --resume are only valid for chain deploy")
        if arguments.action == "logs":
            return chain.logs(state)
        if arguments.action == "status":
            result = chain.status(state)
        else:
            with local_state.exclusive_lock(state / "operation.lock"):
                if arguments.action == "deploy":
                    result = deployment.deploy(repository, state, arguments.offline, arguments.resume)
                elif arguments.action == "start":
                    result = chain.start(repository, state, arguments.port)
                else:
                    result = chain.stop(state)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"terrier: {error}", file=sys.stderr)
        return 1
