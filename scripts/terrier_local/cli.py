import argparse
from pathlib import Path
import sys

from . import contracts


def main():
    parser = argparse.ArgumentParser(description="Agent Terrier local development tools")
    commands = parser.add_subparsers(dest="command", required=True)
    contract_parser = commands.add_parser("contracts", help="Prepare, build and test public contracts")
    contract_parser.add_argument("action", choices=["setup", "build", "test"])
    contract_parser.add_argument("--offline", action="store_true", help="Use downloaded dependencies only")
    contract_parser.add_argument("--match-test", help="Run matching contract tests")
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    try:
        return contracts.run(repository, arguments.action, arguments.offline, arguments.match_test)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"terrier: {error}", file=sys.stderr)
        return 1
