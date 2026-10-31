#!/usr/bin/env python3
import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import re
import sys

IGNORED_DIRECTORIES = {
    ".git", ".jj", "node_modules", "target", ".next", ".venv",
    "__pycache__", ".omc", ".claude", ".pytest_cache",
}
FORBIDDEN_DIRECTORIES = {
    "firmware", "operator-docs", "infra", "wallets", "keystores",
}
FORBIDDEN_SUFFIXES = {".pem", ".key", ".p12", ".keystore", ".sqlite", ".sqlite3"}
RULES = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "access-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    "cloud-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "credential-literal": re.compile(
        r"""(?i)(?:private[_-]?key|secret[_-]?key|api[_-]?key|password|mnemonic|seed[_-]?phrase|default[_-]?test[_-]?key|access[_-]?token)\s*["']?\s*[:=]\s*["']([A-Za-z0-9+/=_ -]{24,})["']"""
    ),
    "personal-path": re.compile(r"/(?:Users|home)/(?!runner(?:/|$)|example(?:/|$))[A-Za-z0-9._-]+/"),
    "unapproved-project-link": re.compile(
        r"github\.com/litentry/(?!agent-terrier(?:[/#?\s\"')]|$))[A-Za-z0-9_.-]+"
    ),
}
EXCEPTION_RULES = {"private-key", "cloud-access-key", "credential-literal", "personal-path"}

def load_exceptions(root):
    path = root / ".public-test-fixtures.json"
    if not path.exists():
        return []
    if path.is_symlink():
        raise ValueError("Exception manifest must be a regular file")
    entries = json.loads(path.read_text())
    if not isinstance(entries, list):
        raise ValueError("Exception manifest must be a list")
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "rule", "line_sha256", "reason"}:
            raise ValueError("Invalid exception fields")
        if not all(isinstance(value, str) for value in entry.values()):
            raise ValueError("Exception fields must be strings")
        relative = Path(entry["path"])
        if (relative.is_absolute() or ".." in relative.parts or
                relative.as_posix() != entry["path"] or not relative.parts):
            raise ValueError("Exception paths must be repository-relative")
        if entry["rule"] not in EXCEPTION_RULES:
            raise ValueError("Only synthetic content findings may be excepted")
        if not re.fullmatch(r"[0-9a-f]{64}", entry["line_sha256"]) or not entry["reason"].strip():
            raise ValueError("Exceptions need an exact line hash and review reason")
    return entries

def inspect_file(root, path):
    relative = path.relative_to(root)
    findings = []
    if path.is_symlink():
        return [{"path": str(relative), "rule": "symlink", "line": 0}]
    if set(relative.parts) & FORBIDDEN_DIRECTORIES:
        findings.append({"path": str(relative), "rule": "excluded-source", "line": 0})
    if path.suffix in FORBIDDEN_SUFFIXES or (
        path.name.startswith(".env") and path.name != ".env.example"
    ):
        findings.append({"path": str(relative), "rule": "credential-or-state-file", "line": 0})
    contents = path.read_bytes().decode("utf-8", errors="replace")
    newline_offsets = [match.start() for match in re.finditer("\n", contents)]
    for rule_name, pattern in RULES.items():
        found_lines = set()
        for match in pattern.finditer(contents):
            line_number = bisect_right(newline_offsets, match.start()) + 1
            if line_number in found_lines:
                continue
            found_lines.add(line_number)
            findings.append({
                "path": str(relative), "rule": rule_name,
                "line": line_number,
            })
    return findings

def inspect_tree(root):
    findings = []
    scanned_files = 0
    surface_path = root / ".public-source.json"
    surface = None
    if surface_path.exists() and not surface_path.is_symlink():
        try:
            surface = json.loads(surface_path.read_text())
            if set(surface) != {"files", "directories"} or not all(
                isinstance(entries, list) and all(isinstance(entry, str) for entry in entries)
                for entries in surface.values()
            ):
                raise ValueError("Invalid source manifest")
        except (ValueError, TypeError):
            findings.append({"path": ".public-source.json", "rule": "invalid-source-manifest", "line": 0})
            surface = None
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            if path.is_symlink():
                findings.extend(inspect_file(root, path))
            elif path.is_dir():
                if path.name not in IGNORED_DIRECTORIES:
                    pending.append(path)
            elif path.is_file():
                findings.extend(inspect_file(root, path))
                relative = path.relative_to(root).as_posix()
                if surface and relative not in surface["files"] and not any(
                    relative.startswith(directory + "/") for directory in surface["directories"]
                ):
                    findings.append({"path": relative, "rule": "outside-public-surface", "line": 0})
                scanned_files += 1
    try:
        exceptions = load_exceptions(root)
    except (ValueError, OSError):
        exceptions = []
        findings.append({"path": ".public-test-fixtures.json", "rule": "invalid-exceptions", "line": 0})
    reviewed_findings = []
    for finding in findings:
        path = root / finding["path"]
        line_number = finding["line"]
        line_digest = ""
        if line_number:
            line = path.read_bytes().decode("utf-8", errors="replace").splitlines()[line_number - 1]
            line_digest = hashlib.sha256(line.encode()).hexdigest()
        reviewed = any(
            entry["path"] == finding["path"]
            and entry["rule"] == finding["rule"]
            and entry["line_sha256"] == line_digest
            and entry.get("reason")
            for entry in exceptions
        )
        if not reviewed:
            reviewed_findings.append(finding)
    return {"scanned_files": scanned_files, "findings": reviewed_findings}

def main():
    parser = argparse.ArgumentParser(description="Check a public source or artifact tree without printing secret values.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    report = inspect_tree(arguments.root.resolve())
    print(json.dumps(report, indent=2))
    return 1 if report["findings"] else 0

if __name__ == "__main__":
    sys.exit(main())
