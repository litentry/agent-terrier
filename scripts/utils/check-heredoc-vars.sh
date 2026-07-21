#!/usr/bin/env bash
# Catch the "$VAR in a heredoc body that is not a shell variable" bug class.
#
# An EXPANDING heredoc (`<<EOF`, not `<<'EOF'`) interpolates every `$name` in
# its body — including on lines that LOOK like comments. Under `set -u` an
# undefined name aborts the script, and because these heredocs render env files
# and systemd units on a REMOTE host, the failure surfaces far from the typo.
#
# Real incidents this exists to prevent (both 2026-07-20):
#   • .github/workflows/e2e-ci.yml — an explanatory comment INSIDE the env-file
#     heredoc said "test-broker.$ZONE"; ZONE is not a step var → the whole e2e
#     suite died with `ZONE: unbound variable`.
#   • scripts/operator/setup-broker-host.sh — the channel worker env referenced
#     `$BROKER_URL`, which is a LINE OF THE MEMORY WORKER'S ENV FILE (heredoc
#     content), never a shell variable → broker deploy died after a 4-minute
#     build, three CI cycles burned before the cause was visible.
#
# THE CRITICAL DISTINCTION (and why the naive version of this check misses the
# second incident): assignments are only real when they occur OUTSIDE a heredoc.
# A `FOO=bar` line INSIDE a heredoc is generated file CONTENT, not a shell
# variable — treating it as one is the exact confusion being guarded against.
#
# A name is accepted when it is assigned outside any heredoc in the same script,
# guarded with a default (`${VAR:-…}` / `:?` / `:+`), backslash-escaped (`\$host`
# — how nginx vhosts pass their own variables through), supplied by a sourced
# operator env file, or a standard shell/environment name.
#
#   bash scripts/utils/check-heredoc-vars.sh            # repo default set
#   bash scripts/utils/check-heredoc-vars.sh path.sh …  # explicit files
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

if [ "$#" -gt 0 ]; then
  FILES=("$@")
else
  FILES=()
  while IFS= read -r f; do FILES+=("$f"); done < <(
    find scripts/operator -name '*.sh' -type f | sort
  )
fi

# Names the shell/environment always provides (or that bash sets itself).
# ONE LINE on purpose: `awk -v` cannot carry an embedded newline (BSD awk — the
# operator laptop — fails with "newline in string" and then evaluates NOTHING,
# which would make this check silently pass everything).
SHELL_BUILTINS='HOME PATH USER LOGNAME PWD OLDPWD SHELL TERM LANG LC_ALL TMPDIR HOSTNAME EDITOR VISUAL SUDO_USER SUDO_UID SUDO_GID DISPLAY XDG_RUNTIME_DIR BASH BASH_SOURCE BASH_VERSION FUNCNAME LINENO RANDOM SECONDS PPID PS1 PS2 IFS REPLY OPTARG OPTIND HISTFILE'

# Keys the operator env files provide (every deploy script `set -a`-sources one).
ENV_FILE_KEYS=$(
  cat scripts/operator-workstation*.env 2>/dev/null \
    | grep -oE '^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*=' \
    | sed -E 's/^[[:space:]]*(export[[:space:]]+)?//; s/=$//' \
    | sort -u | tr '\n' ' '
)

awk_err=$(mktemp)
trap 'rm -f "$awk_err"' EXIT

fail=0
for file in ${FILES[@]+"${FILES[@]}"}; do
  [ -f "$file" ] || continue
  : >"$awk_err"
  out=$(
    awk -v extra="$SHELL_BUILTINS $ENV_FILE_KEYS" '
      BEGIN {
        n = split(extra, e, /[ \t\n]+/)
        for (i = 1; i <= n; i++) if (e[i] != "") ok[e[i]] = 1
      }

      # ── heredoc body ───────────────────────────────────────────────────────
      in_here {
        if ($0 ~ ("^[ \t]*" delim "[ \t]*$")) { in_here = 0; next }
        if (!expand) next                      # <<"EOF" / <<\x27EOF\x27 stays literal
        line = $0
        # `\$host` reaches the rendered file as a literal — not an expansion.
        gsub(/\\\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/, "", line)
        # ${VAR:-…} / :? / :+ / := are guarded: safe under set -u.
        gsub(/\$\{[A-Za-z_][A-Za-z0-9_]*:[-?+=][^}]*\}/, "", line)
        while (match(line, /\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/)) {
          tok = substr(line, RSTART, RLENGTH)
          line = substr(line, RSTART + RLENGTH)
          gsub(/[${}]/, "", tok)
          refline[tok] = (tok in refline) ? refline[tok] : NR
          refs[tok] = 1
        }
        next
      }

      # ── real shell code (outside every heredoc) ────────────────────────────
      # Assignments HERE are the only real ones. Same-line forms after ; & | (
      # are covered; `for x in`, `read -r x`, `${x:=}` also declare a name.
      {
        code = $0
        while (match(code, /(^|[;&|(){}[:space:]])(local[[:space:]]+|export[[:space:]]+|declare[[:space:]]+(-[a-zA-Z]+[[:space:]]+)?|typeset[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*\+?=/)) {
          seg = substr(code, RSTART, RLENGTH)
          code = substr(code, RSTART + RLENGTH)
          sub(/\+?=$/, "", seg)
          gsub(/^[;&|(){}[:space:]]+|[[:space:]]+$/, "", seg)
          sub(/^(local|export|declare|typeset)[[:space:]]+(-[a-zA-Z]+[[:space:]]+)?/, "", seg)
          if (seg ~ /^[A-Za-z_][A-Za-z0-9_]*$/) ok[seg] = 1
        }
        code = $0
        while (match(code, /for[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]/)) {
          seg = substr(code, RSTART, RLENGTH); code = substr(code, RSTART + RLENGTH)
          gsub(/^for[[:space:]]+|[[:space:]]+$/, "", seg); ok[seg] = 1
        }
        code = $0
        while (match(code, /read[[:space:]]+(-[a-zA-Z]+[[:space:]]+)*[A-Za-z_][A-Za-z0-9_]*/)) {
          seg = substr(code, RSTART, RLENGTH); code = substr(code, RSTART + RLENGTH)
          sub(/^read[[:space:]]+(-[a-zA-Z]+[[:space:]]+)*/, "", seg); ok[seg] = 1
        }
        code = $0
        while (match(code, /\$\{[A-Za-z_][A-Za-z0-9_]*:=/)) {
          seg = substr(code, RSTART, RLENGTH); code = substr(code, RSTART + RLENGTH)
          gsub(/[${}:=]/, "", seg); ok[seg] = 1
        }
      }

      # ── heredoc opener ────────────────────────────────────────────────────
      /<<-?[ \t]*['"'"'"]?[A-Za-z_][A-Za-z0-9_]*['"'"'"]?/ {
        if (match($0, /<<-?[ \t]*['"'"'"]?[A-Za-z_][A-Za-z0-9_]*['"'"'"]?/)) {
          raw = substr($0, RSTART, RLENGTH)
          expand = (raw ~ /['"'"'"]/) ? 0 : 1
          gsub(/^<<-?[ \t]*['"'"'"]?|['"'"'"]?$/, "", raw)
          delim = raw
          in_here = 1
        }
      }

      END { for (r in refs) if (!(r in ok)) print refline[r] ":" r }
    ' "$file" 2>"$awk_err" | sort -n
  )
  # A broken awk program prints to stderr and produces NO findings — which would
  # read as "clean" and silently disable this check (observed while writing it:
  # a multi-line -v value made BSD awk bail on every file while the script still
  # printed ok). Treat any awk stderr as a hard failure.
  if [ -s "$awk_err" ]; then
    echo "fail check-heredoc-vars: awk failed on $file — the check did not run:" >&2
    head -3 "$awk_err" >&2
    rm -f "$awk_err"
    exit 2
  fi
  if [ -n "$out" ]; then
    while IFS=: read -r ln name; do
      printf '  %s:%s  $%s — referenced in an expanding heredoc, but never assigned in real shell code\n' \
        "$file" "$ln" "$name"
    done <<< "$out"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo
  echo "fail heredoc bodies reference names the shell will not define." >&2
  echo "     An expanding heredoc interpolates \$name even inside comment-looking lines," >&2
  echo "     and \`set -u\` aborts on an undefined one — on the REMOTE host, mid-deploy." >&2
  echo "     NOTE: a NAME= line inside another heredoc is generated file CONTENT, not a" >&2
  echo "     shell variable; that mistake is exactly what this check exists to catch." >&2
  echo "     Fix: use a real shell variable, guard it (\${VAR:-}), escape it (\\\$name)," >&2
  echo "     de-dollar the prose, or quote the delimiter (<<'EOF') to keep the body literal." >&2
  exit 1
fi
echo "ok heredoc variable references: every expanding-heredoc name is assigned in real shell code, guarded, escaped, or env-file-provided"
