import argparse
import json
from pathlib import Path
import subprocess
import sys

from . import chain, contracts, deployment, local_state


def main():
    parser = argparse.ArgumentParser(description="Agent Terrier local development tools")
    commands = parser.add_subparsers(dest="command", required=True)
    contract_parser = commands.add_parser("contracts", help="Prepare, build and test public contracts")
    contract_parser.add_argument("action", choices=["setup", "build", "test"])
    contract_parser.add_argument("--offline", action="store_true", help="Use downloaded dependencies only")
    contract_parser.add_argument("--match-test", help="Run matching contract tests")
    chain_parser = commands.add_parser("chain", help="Manage an owned local development chain")
    chain_parser.add_argument("action", choices=["start", "status", "stop", "logs", "deploy"])
    chain_parser.add_argument("--port", type=int, help="Loopback RPC port for chain start")
    chain_parser.add_argument("--offline", action="store_true", help="Deploy using downloaded dependencies only")
    chain_parser.add_argument("--resume", action="store_true", help="Explicitly resume an interrupted deployment")
    supervisor = commands.add_parser("_serve-chain", help=argparse.SUPPRESS)
    supervisor.add_argument("--port", type=int, required=True)
    supervisor.add_argument("--anvil", required=True)
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    try:
        if arguments.command == "contracts":
            return contracts.run(repository, arguments.action, arguments.offline, arguments.match_test)
        state = local_state.state_directory(repository)
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
