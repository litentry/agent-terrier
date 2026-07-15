#!/usr/bin/env bash
# check-bash-empty-array-expansion.sh — the bash-3.2 + `set -u` empty-array trap.
#
# THE BUG (real, 2026-07-15): the operator laptop runs **bash 3.2** (the last
# GPLv2 bash Apple ships). There, under `set -u`, expanding an array that
# happens to be EMPTY is an *unbound variable* error, not an empty expansion:
#
#     args=()
#     cmd "${args[@]}"          # bash 3.2 + set -u → "args[@]: unbound variable"
#
# bash >= 4.4 (every Linux host we deploy to) expands it to nothing, so the bug
# is INVISIBLE on the broker hosts and in CI, and only ever fires on the
# operator's own machine — the one place a deploy script must not die. That is
# exactly how `setup-cloud.sh` step 18 (#440/#447) shipped broken: the array is
# seeded empty and only gets `--dry-run` appended *conditionally*, so the
# NORMAL (non-dry-run) path — the only one an operator actually runs — was the
# broken one. `setup-heima.sh` step 14 carried the same shape.
#
# THE FIX — the `${arr[@]+"${arr[@]}"}` idiom (already proven in this repo at
# setup-broker-host.sh's MCP_ARGS): expand only if the array is set, so an
# empty array expands to zero words instead of erroring. Note it is
# deliberately NOT wrapped in outer quotes; the inner quotes preserve
# word-splitting semantics per element.
#
#     cmd ${args[@]+"${args[@]}"}
#
# WHAT THIS GATE FLAGS — only the *decidable* shape, to stay non-noisy: an
# array that (a) is declared empty, (b) is appended to ONLY inside a
# conditional (so it can provably still be empty at the expansion), and (c) is
# then expanded UNGUARDED. Arrays seeded with elements, or appended to
# unconditionally, are not flagged. If this gate ever fires on code that is in
# fact safe, applying the idiom anyway costs nothing and is never wrong.
set -euo pipefail

cd "$(dirname "$0")/../.."

python3 - "$@" <<'PYEOF'
import re, subprocess, sys

files = subprocess.run(["git", "ls-files", "*.sh"], capture_output=True, text=True).stdout.split()
findings = []
for f in files:
    if "archived" in f:
        continue
    try:
        s = open(f).read()
    except OSError:
        continue
    if not re.search(r"set -[a-z]*u", s):
        continue  # no `set -u` → empty expansion is harmless
    empty_decls = set(re.findall(r"(?:local\s+|declare\s+-a\s+)?([A-Za-z_][A-Za-z0-9_]*)=\(\s*\)", s))
    for name in empty_decls:
        appends = list(re.finditer(re.escape(name) + r"\+=\(", s))
        if not appends:
            continue
        # Does ANY append run unconditionally? Then the array is never empty here.
        unconditional = False
        for m in appends:
            ls = s.rfind("\n", 0, m.start()) + 1
            le = s.find("\n", m.start())
            line = s[ls:le if le != -1 else len(s)]
            if "&&" not in line and not re.match(r"\s*(if|for|while|elif)\b", line):
                unconditional = True
        if unconditional:
            continue
        for m in re.finditer(r'"\$\{' + re.escape(name) + r'\[@\]\}"', s):
            window = s[max(0, m.start() - len(name) - 8): m.end() + len(name) + 8]
            if name + "[@]+" in window:
                continue  # already the guarded idiom
            findings.append((f, s[: m.start()].count("\n") + 1, name))

for f, line, name in sorted(set(findings)):
    print(f'FAIL {f}:{line} — "${{{name}[@]}}" can be EMPTY here and dies on bash 3.2 under `set -u`.', file=sys.stderr)
    print(f'     fix: ${{{name}[@]+"${{{name}[@]}}"}}   (expand-if-set; see this script\'s header)', file=sys.stderr)

if findings:
    print("", file=sys.stderr)
    print(f"{len(set(findings))} possibly-empty array expansion(s) — these break on the operator's", file=sys.stderr)
    print("macOS bash 3.2 while passing CI + the Linux hosts. Apply the idiom above.", file=sys.stderr)
    sys.exit(1)
print("bash empty-array expansion: no unguarded possibly-empty expansions under set -u")
PYEOF
