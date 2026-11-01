#!/usr/bin/env bash
# Keep count fallbacks outside command substitutions so a zero count is not duplicated.
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
