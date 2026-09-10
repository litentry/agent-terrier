#!/usr/bin/env bash
# check-template-content-only.sh — the F0/F1 CONTENT gate for application
# templates (family applications, epic #660; plan §4.2).
#
#   F0  a new application ships with ZERO framework changes: a template is
#       content only — a manifest, a persona, skills docs, knowledge docs.
#   F1  the framework knows KINDS, never household nouns: no template file may
#       be code the framework executes.
#
# What this checks, for every `presets/<id>/`:
#   1. only these paths exist: preset.json · SOUL.md · skills/*.md · knowledge/*.md
#      (README.md allowed at the template root) — anything else (a script, a
#      Dockerfile, a .rs/.ts/.sh, a nested dir) fails.
#   2. preset.json is valid JSON whose `id` equals the directory name.
#   3. every `context.skills[]` / `context.knowledge[]` name in the manifest
#      resolves to a file (the broker's validator pins this at compile time
#      too; this catches it before the crate builds).
# Pure file checks — no network, no creds, CI-safe.
#
#   bash scripts/utils/check-template-content-only.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PRESETS="$REPO_ROOT/presets"

c() { [ -t 1 ] && printf '\033[%sm%s\033[0m' "$1" "$2" || printf '%s' "$2"; }
ok()  { printf '  %s %s\n' "$(c '1;32' ok)"   "$1"; }
bad() { printf '  %s %s\n' "$(c '1;31' fail)" "$1"; }

command -v jq >/dev/null 2>&1 || { bad "jq is required"; exit 2; }
[ -d "$PRESETS" ] || { bad "missing $PRESETS"; exit 2; }

fails=0
for dir in "$PRESETS"/*/; do
  id="$(basename "$dir")"
  # 1. content-only file set.
  while IFS= read -r f; do
    rel="${f#"$dir"}"
    case "$rel" in
      preset.json|SOUL.md|README.md) ;;
      skills/*.md|knowledge/*.md)
        case "$rel" in */*/*) bad "$id: nested path $rel (skills/ and knowledge/ are flat)"; fails=$((fails+1)) ;; esac ;;
      *) bad "$id: $rel is not template content (allowed: preset.json, SOUL.md, README.md, skills/*.md, knowledge/*.md)"; fails=$((fails+1)) ;;
    esac
  done < <(find "$dir" -type f | sort)
  # 2. manifest id == directory.
  if ! jq -e . "$dir/preset.json" >/dev/null 2>&1; then
    bad "$id: preset.json is not valid JSON"; fails=$((fails+1)); continue
  fi
  mid="$(jq -r '.id // ""' "$dir/preset.json")"
  [ "$mid" = "$id" ] || { bad "$id: manifest id '$mid' != directory name"; fails=$((fails+1)); }
  [ -f "$dir/SOUL.md" ] || { bad "$id: SOUL.md missing"; fails=$((fails+1)); }
  # 3. context pointers resolve.
  for kind in skills knowledge; do
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      [ -f "$dir/$kind/$name" ] || { bad "$id: context.$kind names $name but presets/$id/$kind/$name is missing"; fails=$((fails+1)); }
    done < <(jq -r ".context.$kind // [] | .[]" "$dir/preset.json")
  done
  [ "$fails" = 0 ] && ok "$id: content only (manifest + persona + $(find "$dir/skills" -name '*.md' 2>/dev/null | wc -l | tr -d ' ') skill(s), $(find "$dir/knowledge" -name '*.md' 2>/dev/null | wc -l | tr -d ' ') knowledge doc(s))"
done

if [ "$fails" != 0 ]; then
  bad "$fails template content violation(s) — a template is content, never framework code (F0/F1)"
  exit 1
fi
ok "every template is content-only"
