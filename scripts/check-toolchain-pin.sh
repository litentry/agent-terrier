#!/usr/bin/env bash
# Toolchain-pin gate (read-only; wired into harness-ci.yml rust-checks).
#
# rust-toolchain.toml is the SINGLE source of truth for the Rust version —
# local dev, CI, and the broker host all resolve it via rustup. Two invariants:
#
#   1. rust-toolchain.toml pins a CONCRETE version (X.Y.Z), never a floating
#      channel (stable/beta/nightly). CI runs `cargo clippy -- -D warnings`,
#      so a floating channel makes lints introduced in a newer stable fail CI
#      while passing on older local toolchains (the PR #270 needless_lifetimes
#      skew: local 1.94 green, CI latest-stable red).
#
#   2. No workflow installs a toolchain around the pin. dtolnay/rust-toolchain
#      sets RUSTUP_TOOLCHAIN, which BYPASSES rust-toolchain.toml — @stable
#      floats, and even a pinned `@1.x.y` is a second pin site that drifts.
#      Workflows install via `rustup toolchain install` (no args — reads the
#      pin file, channel + components).
#
# Bump ritual: docs/dev-setup.md "Toolchain pin + bump ritual".
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
fail=0

channel="$(sed -n 's/^channel *= *"\(.*\)".*/\1/p' rust-toolchain.toml)"
if [[ ! "$channel" =~ ^1\.[0-9]+\.[0-9]+$ ]]; then
  echo "fail rust-toolchain.toml channel is '${channel:-<missing>}' — must be a concrete X.Y.Z pin, not a floating channel" >&2
  fail=1
fi

# Match only real `uses:` action references — comments may legitimately name
# the banned actions when explaining this very rule.
bypass="$(grep -rnE '^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*(dtolnay/rust-toolchain|actions-rs/toolchain)' .github/workflows/ || true)"
if [[ -n "$bypass" ]]; then
  echo "fail workflow installs a toolchain around the rust-toolchain.toml pin — use 'rustup toolchain install' (reads the pin) instead:" >&2
  echo "$bypass" >&2
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
echo "ok rust-toolchain.toml pins $channel and no workflow bypasses it"
