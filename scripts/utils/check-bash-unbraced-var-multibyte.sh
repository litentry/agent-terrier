#!/usr/bin/env bash
# check-bash-unbraced-var-multibyte.sh — the bash-3.2 + UTF-8 `$var…` name-glom trap.
#
# THE BUG (real, 2026-08-12): macOS **bash 3.2** (the operator laptop) lexes
# variable NAMES with the locale's single-byte ctype, so under any UTF-8 locale
# the LEAD BYTE of a multibyte character written directly after an unbraced
# expansion is glued onto the name: `"$fn_id…"` parses as the (unbound)
# variable `fn_id\xe2` and dies under `set -u` as `fn_id�: unbound variable`.
# bash >= 4 (CI + every Linux host) lexes names multibyte-aware, so the bug is
# invisible everywhere EXCEPT the machine that runs the deploy/ceremony
# scripts — exactly how seed-base-images.sh's env-template drift check killed
# the #578 ship ceremony's seed leg mid-run.
#
#   measured (bash 3.2.57, macOS 15):
#     LC_ALL=en_US.UTF-8 /bin/bash -c 'set -u; v=x; echo "$v…"'
#       → "v�: unbound variable"
#     LC_ALL=C is unaffected; bash >= 4 is unaffected in any locale.
#
# THE FIX: brace the expansion — `"${fn_id}…"` — braces end the name
# unambiguously in every bash. The usual carriers are the … / — / – characters
# in step()/log strings. Bracing is always correct, so there is no allowlist.
# Full-line comments are SKIPPED (they can't execute, and doc examples of the
# trap — like this header's — would self-flag); an inline-comment hit still
# flags, and bracing there is harmless.
set -euo pipefail

cd "$(dirname "$0")/../.."

python3 - <<'PYEOF'
import re, subprocess, sys

files = subprocess.run(["git", "ls-files", "*.sh"], capture_output=True, text=True).stdout.split()
pat = re.compile(rb"\$[A-Za-z_][A-Za-z0-9_]*[\x80-\xff]")
findings = []
for f in files:
    if "archived" in f:
        continue
    try:
        data = open(f, "rb").read()
    except OSError:
        continue
    for lineno, line in enumerate(data.splitlines(), 1):
        if line.lstrip().startswith(b"#"):
            continue
        if pat.search(line):
            findings.append((f, lineno, line.decode("utf-8", "replace").strip()))

for f, lineno, text in findings:
    print(f"FAIL {f}:{lineno} — unbraced $var directly before a multibyte char:", file=sys.stderr)
    print(f"     {text}", file=sys.stderr)

if findings:
    print("", file=sys.stderr)
    print(f"{len(findings)} unbraced-$var-before-multibyte site(s) — macOS bash 3.2 glues the", file=sys.stderr)
    print("lead byte onto the variable name and dies under `set -u` (CI/Linux bash >= 4", file=sys.stderr)
    print("is fine, so only the operator laptop breaks). Brace it: ${var}…", file=sys.stderr)
    sys.exit(1)
print("bash unbraced-var-before-multibyte: none (operator bash 3.2 safe)")
PYEOF
