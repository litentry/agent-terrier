#!/usr/bin/env bash
# Gate: no process-env mutation in Rust code under crates/.
#
# WHY: process env is global to the test process and `cargo test` runs
# tests on parallel threads — a `std::env::set_var` / `remove_var` in one
# test leaks into every sibling running concurrently (the bug class behind
# the PR #258 daemon deflake, the PR #259 broker BrokerConfig refactor,
# and the PR #264 repo-wide sweep). The fix pattern is value injection:
# read env ONCE in a `from_env`-style constructor, hand tests a config
# struct / parameter they fill explicitly (see BrokerConfig in
# crates/agentkeys-broker-server/src/config.rs and BundlerBootValues in
# crates/agentkeys-bundler/src/server.rs).
#
# The ban is repo-wide over crates/**/*.rs (not just #[cfg(test)] blocks):
# production code mutating env at runtime is the same global-state hazard
# under a multithreaded tokio runtime, and std marks set_var/remove_var
# unsafe from edition 2024 onward.
#
# Pure comment lines (leading `//` / `///` / `//!`) are exempt — prose
# ABOUT set_var can't execute. Trailing comments after real code don't
# shield the code part of the line.
#
# Allowlist: files listed in ALLOWLIST_FILES may still match. Every entry
# needs a comment with the reason + the condition for removing it, e.g.:
#   ALLOWLIST_FILES=(
#     # Transitional: PR #NNN replaces these with config injection.
#     "crates/foo/src/bar.rs"
#   )
# A stale entry (file no longer matches) prints a loud warning so the
# list shrinks instead of rotting. It has been EMPTY since PR #259 +
# #264 landed — keep it that way; the parallel-threads `cargo test` in
# harness-ci.yml rust-checks is the runtime half of this gate.
#
# Output convention: `ok proceeding` / `fail <reason>` per the repo's
# idempotent-script rule.

set -euo pipefail

cd "$(dirname "$0")/.."

ALLOWLIST_FILES=()

# Match direct calls (std::env::set_var / env::set_var) AND aliasing
# imports (use std::env::set_var) so the gate can't be dodged by a `use`.
PATTERN='(std::)?env::(set_var|remove_var)|use std::env::\{?[^}]*(set_var|remove_var)'

matches=$(grep -rnE "$PATTERN" crates/ --include='*.rs' || true)

violations=""
seen_allowlisted=" "
while IFS= read -r line; do
  [ -z "$line" ] && continue
  file="${line%%:*}"
  rest="${line#*:}"
  text="${rest#*:}"
  # Pure comment line? (leading whitespace then //) — exempt.
  stripped="${text#"${text%%[![:space:]]*}"}"
  case "$stripped" in
    //*) continue ;;
  esac
  allowlisted=0
  for allowed in ${ALLOWLIST_FILES[@]+"${ALLOWLIST_FILES[@]}"}; do
    if [ "$file" = "$allowed" ]; then
      allowlisted=1
      seen_allowlisted="$seen_allowlisted$allowed "
      break
    fi
  done
  if [ "$allowlisted" -eq 0 ]; then
    violations+="$line"$'\n'
  fi
done <<<"$matches"

# Warn loudly about stale allowlist entries (file clean or gone) so the
# list shrinks instead of rotting.
for allowed in ${ALLOWLIST_FILES[@]+"${ALLOWLIST_FILES[@]}"}; do
  case "$seen_allowlisted" in
    *" $allowed "*) ;;
    *)
      echo "==> ⚠️  WARN: allowlist entry '$allowed' no longer matches anything —" >&2
      echo "    delete it from scripts/check-no-env-mutation-in-tests.sh" >&2
      ;;
  esac
done

if [ -n "$violations" ]; then
  echo "fail process-env mutation found in crates/ Rust code:" >&2
  printf '%s' "$violations" >&2
  cat >&2 <<'EOF'

Process env is GLOBAL and cargo test runs tests on parallel threads —
set_var/remove_var in any test leaks into concurrently running siblings
(flake class fixed by PRs #258/#259/#264). Do not mutate env:

  * test code: inject the value instead — read env once in a from_env()
    constructor and have tests build the config struct / pass the param
    explicitly (BrokerConfig / BundlerBootValues pattern).
  * production code: thread the value through config; runtime env
    mutation is the same hazard under a multithreaded runtime.

If a mutation is genuinely unavoidable, add the file to ALLOWLIST_FILES
in scripts/check-no-env-mutation-in-tests.sh with the reason and the
condition under which the entry gets removed.
EOF
  exit 1
fi

echo "ok proceeding — no process-env mutation outside the allowlist in crates/**/*.rs"
