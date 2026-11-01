#!/usr/bin/env python3
"""Render the public CLI reference from the parser used by the executable."""
import argparse
from pathlib import Path
import sys

from terrier_local.cli import build_parser


def render():
    introduction = """This reference is generated from the public `terrier` command parser. Run commands locally from the repository root. Regenerate it with `python3 scripts/generate-cli-reference.py`; the source test lane rejects stale output.

See [local services](./local-services.md), [local agents](./local-agents.md) and [test lanes](./test-lanes.md) for prerequisites, state effects and measured qualification. Every signing identity is development-only. Command availability does not imply complete browser or release acceptance.

"""
    sections = [introduction]

    def cell(value):
        return str(value).replace("|", "\\|").replace("\n", " ")

    def visit(parser, command):
        sections.append("## " + command + "\n\n")
        if parser.description:
            sections.append(parser.description + "\n\n")
        sections.append("| Argument | Required | Choices | Description |\n| --- | --- | --- | --- |\n")
        children = []
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                children.extend((name, child) for name, child in action.choices.items() if not name.startswith("_"))
                values = ", ".join(name for name, _ in children)
                sections.append("| subcommand | yes | " + cell(values) + " | Select a command below. |\n")
                continue
            if action.help == argparse.SUPPRESS:
                continue
            name = ", ".join(action.option_strings) if action.option_strings else action.dest
            choices = ", ".join(map(str, action.choices)) if action.choices else ""
            description = action.help or ""
            sections.append("| " + " | ".join(map(cell, (name, "yes" if action.required else "no", choices, description))) + " |\n")
        sections.append("\n")
        for name, child in children:
            visit(child, command + " " + name)

    visit(build_parser(), "terrier")
    return "".join(sections)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    destination = Path(__file__).resolve().parents[1] / "docs/wiki/cli-reference.md"
    rendered = render()
    if arguments.check:
        current = destination.read_text() if destination.exists() else ""
        if current != rendered:
            print("CLI reference is stale; run python3 scripts/generate-cli-reference.py", file=sys.stderr)
            return 1
    else:
        destination.write_text(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
