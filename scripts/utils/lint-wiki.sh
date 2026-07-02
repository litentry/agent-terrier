#!/usr/bin/env bash
# Lint docs/wiki/*.md for GitHub-Wiki rendering rules.
#
# GitHub Wiki renders each page's title from its FILENAME and copies the
# markdown body verbatim (see .github/workflows/publish-wiki.yml — it is a raw
# folder mirror, no transform). Two source patterns therefore render badly and
# are forbidden:
#
#   1. YAML frontmatter   GitHub does NOT strip it; the `---...---` block
#                         renders as a literal heading + sidebar-preview text.
#   2. A leading `# H1`   duplicates the filename-derived page title and pushes
#                         every section one level deeper in the right-sidebar
#                         table of contents.
#
# Both are pure-source rules: a page body must OPEN on real content — a lead
# paragraph, a **Status**/**Scope** block, a `>` note, or an `## H2` section.
#
# Exit 0 = clean, 1 = at least one violation. Read-only, deterministic, no LLM,
# safe to re-run. Runnable locally (`bash scripts/utils/lint-wiki.sh`) and in CI
# (.github/workflows/wiki-lint.yml). See AGENTS.md "Wiki-location policy".
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
wiki_dir="$repo_root/docs/wiki"

if [ ! -d "$wiki_dir" ]; then
  echo "fail docs/wiki not found at $wiki_dir" >&2
  exit 1
fi

violations=0
checked=0
for f in "$wiki_dir"/*.md; do
  [ -e "$f" ] || continue
  checked=$((checked + 1))
  name="$(basename "$f")"
  # First non-blank line of the file.
  first="$(grep -m1 -vE '^[[:space:]]*$' "$f" || true)"
  if [ "$first" = "---" ]; then
    echo "fail $name — opens with YAML frontmatter ('---'). GitHub Wiki renders it as literal text. Remove the '---...---' block; let the body open on real content."
    violations=$((violations + 1))
  elif printf '%s' "$first" | grep -qE '^# '; then
    echo "fail $name — opens with a leading '# ' H1 ($first). GitHub Wiki already shows the filename as the page title, so a body H1 duplicates it and over-indents the sidebar TOC. Remove the redundant H1 (keep '##' sections); open the body on the lead paragraph / Status block instead."
    violations=$((violations + 1))
  fi
done

if [ "$violations" -ne 0 ]; then
  echo "fail wiki lint — $violations of $checked page(s) violate the GitHub-Wiki source rules above." >&2
  exit 1
fi

echo "ok wiki lint — all $checked docs/wiki page(s) clean (no YAML frontmatter, no redundant leading H1)."
