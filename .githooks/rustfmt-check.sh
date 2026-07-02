#!/usr/bin/env bash
# Shared fmt gate for the git pre-commit + pre-push hooks (installed via
# core.hooksPath=.githooks, wired by scripts/utils/setup-dev-env.sh). Mirrors the CI
# "cargo fmt + clippy + test" fmt step EXACTLY — `cargo fmt --all -- --check` in
# BOTH cargo workspaces: the root (harness-ci.yml) and the standalone viz/server
# (viz-ci.yml, working-directory: viz/server). fmt --check only parses (no
# compile), so this runs in ~1s. clippy/test stay in CI (too slow for a commit
# gate; format drift is the failure that bites on nearly every PR).
#
# NOTE: jj does NOT run git hooks — `jj git push` bypasses pre-push. In this
# repo's worktree PR flow the gating git step is the `git commit`, so PRE-COMMIT
# is the effective guard; pre-push only covers a raw `git push`.
set -euo pipefail

command -v cargo >/dev/null 2>&1 || exit 0   # no Rust toolchain → nothing to gate

root="$(git rev-parse --show-toplevel)"
fail=0
check() {
  [ -f "$1/Cargo.toml" ] || return 0
  ( cd "$1" && cargo fmt --all -- --check ) || fail=1
}
check "$root"
check "$root/viz/server"

if [ "$fail" -ne 0 ]; then
  {
    echo ""
    echo "✗ rustfmt: code is not formatted — the CI fmt gate would reject this."
    echo "  fix:  cargo fmt --all   (touched viz/server too?  (cd viz/server && cargo fmt --all))"
    echo "  then re-stage + retry. Bypass once with --no-verify (not recommended)."
    echo ""
  } >&2
  exit 1
fi
