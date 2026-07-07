#!/usr/bin/env bash
# check-public-boundary.sh — #317 mirror boundary gate.
#
# The OSS mirror is filter(private): everything NOT matched by
# mirror/public-paths.txt is stripped. This gate enforces the two invariants
# that actually matter for a clean, non-leaking, non-dangling mirror:
#
#   (A) NO real operational VALUE (account id / EIP / instance id / zone id) in
#       ANY public-bound file — a leak.
#   (B) NO markdown LINK from a public-bound doc (*.md) to a PRIVATE path
#       (operator-docs/, docs/plan/, AGENTS.ops.md, pm/, infra/, dev.sh, or a
#       private setup/provision/heima/... script) — a dangling link in the mirror.
#
# Cosmetic code comments that mention a private path (e.g. `// see
# scripts/operator/chain/heima-bring-up.sh`) are NOT flagged: they don't break the build or
# render as links. Prose mentions in docs (e.g. "internal runbook
# (`operator-docs/`)") are NOT flagged either — only `](...)` link targets.
#
# Exit 0 = clean. Exit 1 = violations (printed). Exit 2 = harness error.
# Read-only. Portable to /bin/bash 3.2 (macOS) + CI bash. Run before every push.
set -uo pipefail
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
MANIFEST=mirror/public-paths.txt
[ -f "$MANIFEST" ] || { echo "fail: $MANIFEST missing"; exit 2; }

# ── parse the manifest into allow (prefix / file / glob) + deny buckets ───────
# `deny:<rule>` lines are PRIVATE overrides: a path matched by a deny rule is
# private even when an allow rule (e.g. the blanket docs/research/) would keep it.
PREFIXES=(); FILES=(); GLOBS=(); DENY=()
while IFS= read -r line; do
  line="${line%%#*}"
  line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  [ -z "$line" ] && continue
  case "$line" in
    deny:*) DENY+=("${line#deny:}") ;;
    glob:*) GLOBS+=("${line#glob:}") ;;
    */)     PREFIXES+=("$line") ;;
    *)      FILES+=("$line") ;;
  esac
done < "$MANIFEST"

is_public() {
  local p="$1" x
  # deny overrides win — a denied path is private regardless of any allow rule
  for x in ${DENY[@]+"${DENY[@]}"}; do
    case "$x" in
      glob:*) case "$p" in ${x#glob:}) return 1 ;; esac ;;
      */)     case "$p" in "$x"*) return 1 ;; esac ;;
      *)      [ "$p" = "$x" ] && return 1 ;;
    esac
  done
  for x in "${PREFIXES[@]}"; do case "$p" in "$x"*) return 0 ;; esac; done
  for x in "${FILES[@]}";    do [ "$p" = "$x" ] && return 0; done
  for x in "${GLOBS[@]}";    do case "$p" in $x) return 0 ;; esac; done
  return 1
}

# ── private-script basenames: everything under scripts/ EXCEPT the public
#    check-*/verify-*/lint-* gates + the .env.example template ─────────────────
PRIV_SCRIPTS_RE="$(git ls-files 'scripts/*' \
  | grep -E '\.(sh|env|mjs|js|py)$' \
  | grep -vE '/(check-|verify-|lint-)[^/]*$' \
  | grep -v 'operator-workstation\.env\.example$' \
  | sed 's@.*/@@; s@\.@\\.@g' \
  | paste -sd '|' -)"

# (A) real operational values (placeholders 000000000000 / 123456789012 /
#     example.invalid are intentionally NOT matched)
OPVAL_RE='\b429071895007\b|54\.164\.117\.252|100\.56\.43\.4|3\.214\.219\.209|54\.145\.185\.156|Z09723983CFJOHAE3VC65|i-0[0-9a-f]{16}'
# (B) markdown LINK targets to a private path: matches `](....private....)`.
#     `plan/` (not just `docs/plan/`) so relative forms from docs/ (`plan/x`,
#     `../plan/x`) are caught too — docs/plan/ is the only `plan/` segment in repo.
PRIVLINK_RE='\]\([^)]*(operator-docs/|plan/|research/|hardware/|volcano/|AGENTS\.ops\.md|pm/|infra/|dev\.sh)'
# deny'd-file basenames → flag a PUBLIC doc that links a deny:'d file (now stripped)
DENY_LINK_RE=""
for x in ${DENY[@]+"${DENY[@]}"}; do
  case "$x" in
    glob:*) : ;;
    */) p="$(printf '%s' "${x%/}" | sed 's/\./\\./g')"; DENY_LINK_RE="${DENY_LINK_RE:+$DENY_LINK_RE|}$p" ;;
    *)  b="$(basename "$x" | sed 's/\./\\./g')"; DENY_LINK_RE="${DENY_LINK_RE:+$DENY_LINK_RE|}$b" ;;
  esac
done

fails=0
echo "== #317 mirror boundary gate =="
PUBLIC_COUNT=0
while IFS= read -r f; do
  is_public "$f" || continue
  PUBLIC_COUNT=$((PUBLIC_COUNT+1))
  [ -f "$f" ] || continue

  # (A) operational-value leak — any public file EXCEPT this gate itself, whose
  #     OPVAL_RE definition necessarily contains the literals it hunts for.
  if [ "$f" != "scripts/utils/check-public-boundary.sh" ] && hits="$(grep -nE "$OPVAL_RE" "$f" 2>/dev/null)"; then
    echo "OPERATIONAL-VALUE LEAK in $f:"; printf '%s\n' "$hits" | sed 's/^/    /'; fails=$((fails+1))
  fi

  # (B) dangling private-path LINK — public docs (*.md) only
  case "$f" in
    *.md)
      if pl="$(grep -nE "$PRIVLINK_RE" "$f" 2>/dev/null)"; then
        echo "PRIVATE-PATH LINK in $f:"; printf '%s\n' "$pl" | sed 's/^/    /'; fails=$((fails+1))
      fi
      if [ -n "$PRIV_SCRIPTS_RE" ] && ps="$(grep -nE "\]\([^)]*scripts/([^)]*/)?($PRIV_SCRIPTS_RE)" "$f" 2>/dev/null)"; then
        echo "PRIVATE-SCRIPT LINK in $f:"; printf '%s\n' "$ps" | sed 's/^/    /'; fails=$((fails+1))
      fi
      # private harness paths: everything under e2e/ EXCEPT e2e/fixtures/
      if ph="$(grep -nE '\]\([^)]*e2e/' "$f" 2>/dev/null | grep -v 'e2e/fixtures/')"; then
        echo "PRIVATE-HARNESS LINK in $f:"; printf '%s\n' "$ph" | sed 's/^/    /'; fails=$((fails+1))
      fi
      # links to a deny:'d file (stripped from the mirror)
      if [ -n "$DENY_LINK_RE" ] && pd="$(grep -nE "\]\([^)]*($DENY_LINK_RE)" "$f" 2>/dev/null)"; then
        echo "PRIVATE-DENY LINK in $f:"; printf '%s\n' "$pd" | sed 's/^/    /'; fails=$((fails+1))
      fi
      ;;
  esac
done < <(git ls-files)

echo "-- scanned $PUBLIC_COUNT public-bound files --"
if [ "$fails" -eq 0 ]; then
  echo "ok: no operational-value leak, no dangling private-path link in any public-bound file"
  exit 0
fi
echo "fail: $fails public-boundary violation group(s) above — de-link/genericize them, or reclassify the path in $MANIFEST"
exit 1
