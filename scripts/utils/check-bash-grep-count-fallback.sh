#!/usr/bin/env bash
# check-bash-grep-count-fallback.sh — the `grep -c` capture double-count trap.
#
# THE BUG (real, 2026-09-23): `grep -c` PRINTS its count and EXITS 1 when the
# count is zero, so a fallback INSIDE the capture fires on the zero case too and
# appends a second value:
#
#     n="$(grep -c pat file || echo 0)"     # no match → n = "0" newline "0"
#     [ "$n" -gt 1 ]                        # → "[: 0\n0: integer expression expected"
#
# `[` then returns 2, which an `if`/`||` reads as false, so the branch goes the
# right way by accident and the only symptom is log noise. That is how it sat in
# lib/host-common.sh's cargo-config guard, logging in the VE broker converge
# (PR #724's ve-e2e run), and how #728 re-introduced it in the dsh image smoke
# the next day. `docker exec … grep -c` passes grep's exit status through, so
# it is the same trap.
#
# THE FIX — make the capture a single value:
#
#     n="$(grep -c pat file)" || n=0        # assign first; fall back only on failure
#     "… $(grep -c pat file || true) …"     # in a message: the count, empty on a read error
#
# WHAT THIS GATE FLAGS — a `grep … -c`/`--count` whose `$(…)` capture carries an
# `|| echo` / `|| printf` fallback, in every tracked *.sh and workflow file. It
# reads one logical line (backslash continuations joined) and needs no `)`
# between the `$(` and the fallback, so it stays quiet on the fix above (whose
# fallback sits OUTSIDE the capture). Full-line comments are skipped (they can't
# run, and this header would self-flag). Moving the fallback out of the capture
# is always correct, so there is no allowlist.
#
#   bash scripts/utils/check-bash-grep-count-fallback.sh            # repo default set
#   bash scripts/utils/check-bash-grep-count-fallback.sh path.sh …  # explicit files (repo-relative or absolute)
set -euo pipefail

cd "$(dirname "$0")/../.."

python3 - "$@" <<'PYEOF'
import re, subprocess, sys

if sys.argv[1:]:
    files = sys.argv[1:]
else:
    listed = subprocess.run(
        ["git", "ls-files", "*.sh", ".github/workflows/*.yml", ".github/workflows/*.yaml"],
        capture_output=True, text=True,
    ).stdout.split()
    files = [f for f in listed if "archived" not in f]

pat = re.compile(
    r"\$\([^)]*\bgrep\b[^|;&)]*\s(?:-[A-Za-z]*c[A-Za-z]*|--count)(?=\s)[^)]*\|\|\s*(?:echo|printf)\b"
)
findings = []
for f in files:
    try:
        lines = open(f, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        continue
    i = 0
    while i < len(lines):
        start, text = i, lines[i]
        i += 1
        if text.lstrip().startswith("#"):
            continue
        while text.endswith("\\") and i < len(lines):
            text = text[:-1] + " " + lines[i].strip()
            i += 1
        if pat.search(text):
            findings.append((f, start + 1, text.strip()))

for f, lineno, text in findings:
    print(f"FAIL {f}:{lineno} — grep -c capture with an echo/printf fallback inside the $(...):", file=sys.stderr)
    print(f"     {text}", file=sys.stderr)

if findings:
    print("", file=sys.stderr)
    print(f"{len(findings)} grep-count capture(s) with an in-capture fallback — grep -c prints 0 AND", file=sys.stderr)
    print("exits 1 on no match, so the fallback appends a second value (0, newline, 0) and a", file=sys.stderr)
    print("later integer test logs 'integer expression expected'. Assign first and fall back", file=sys.stderr)
    print('outside the capture: n="$(grep -c ...)" || n=0   (in a message: || true inside).', file=sys.stderr)
    sys.exit(1)
print("bash grep-count fallback: none (every grep -c capture yields a single count)")
PYEOF
