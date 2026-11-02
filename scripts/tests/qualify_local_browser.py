"""Explicit real-chain browser-approval CLI qualification; no browser automation."""
from pathlib import Path
import subprocess


if __name__ == "__main__":
    repository = Path(__file__).resolve().parents[2]
    raise SystemExit(subprocess.run([
        "cargo", "test", "--offline", "--locked", "-p", "agentkeys-cli",
        "--test", "local_browser_qualification", "--", "--ignored", "--nocapture",
    ], cwd=repository, timeout=300).returncode)
