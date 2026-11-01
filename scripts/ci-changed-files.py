#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path

from terrier_local import ci_changes

parser = argparse.ArgumentParser(description="Collect complete PR paths bound to an exact tested merge revision")
parser.add_argument("--output", required=True, type=Path)
arguments = parser.parse_args()
try:
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        raise ValueError("Changed-file collection requires a pull_request event")
    event_path = Path(os.environ["GITHUB_EVENT_PATH"])
    with event_path.open("rb") as source:
        contents = source.read(ci_changes.RESPONSE_LIMIT + 1)
    if len(contents) > ci_changes.RESPONSE_LIMIT:
        raise ValueError("Event input exceeds its size bound")
    paths = ci_changes.collect(json.loads(contents), os.environ["GITHUB_REPOSITORY"],
        os.environ["GITHUB_SHA"], ci_changes.api_reader(os.environ.get("GH_TOKEN")))
    ci_changes.write_paths(arguments.output, paths, Path(__file__).resolve().parents[1])
    print(json.dumps({"complete": True, "paths": len(paths), "revision": os.environ["GITHUB_SHA"]}))
except (OSError, KeyError, TypeError, ValueError, RuntimeError):
    parser.exit(1, "changed files: incomplete or stale PR input; refresh the PR branch and start a new run, or split an oversized change\n")
