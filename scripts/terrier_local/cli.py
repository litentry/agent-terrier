import argparse
import json
from pathlib import Path
import subprocess
import sys

from . import chain, contracts, deployment, local_state, models, owner


def main():
    parser = argparse.ArgumentParser(description="Agent Terrier local development tools")
    commands = parser.add_subparsers(dest="command", required=True)
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
    owner_parser = commands.add_parser("owner", help="Real local owner registration and scope operations")
    owner_parser.add_argument("action", choices=["register", "grant", "revoke", "bind", "unbind"])
    owner_parser.add_argument("--name", required=True, help="Local owner name")
    owner_parser.add_argument("--actor-omni")
    owner_parser.add_argument("--service", action="append", default=[])
    owner_parser.add_argument("--read-only", action="store_true")
    owner_parser.add_argument("--enrollment-file", type=Path)
    device_parser = commands.add_parser("device", help="Create a local actor-owned identity and public proof")
    device_parser.add_argument("action", choices=["identity"])
    device_parser.add_argument("--name", required=True)
    device_parser.add_argument("--operator-omni", required=True)
    device_parser.add_argument("--label", required=True)
    device_parser.add_argument("--kind", required=True, choices=["device", "delegate"])
    supervisor = commands.add_parser("_serve-chain", help=argparse.SUPPRESS)
    supervisor.add_argument("--port", type=int, required=True)
    supervisor.add_argument("--anvil", required=True)
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    try:
        if arguments.command == "contracts":
            return contracts.run(repository, arguments.action, arguments.offline, arguments.match_test)
        if arguments.command == "models":
            result = models.run(repository, arguments.action, arguments.base_url, arguments.chat_model, arguments.embedding_model)
            print(json.dumps(result, indent=2))
            return 0
        state = local_state.state_directory(repository)
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
                                       arguments.enrollment_file)
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
