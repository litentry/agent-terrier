#!/usr/bin/env bash
# Regenerate the device FFI header from the Rust `extern "C"` signatures (#367).
# The header is the firmware's contract; it is GENERATED, never hand-edited, so it
# cannot drift from crates/agentkeys-device-core/src/ffi.rs.
#
#   bash crates/agentkeys-device-core/gen-header.sh           # regenerate in place
#   bash crates/agentkeys-device-core/gen-header.sh --check   # CI: fail if stale
#
# (The "Missing [defines] entry for feature = ffi" cbindgen warning is benign —
#  the items are emitted unconditionally, which is what the firmware build wants.)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
HEADER="$REPO_ROOT/firmware/esp32s3-touch-lcd-4b/components/agentkeys_device/include/agentkeys_device.h"

if ! command -v cbindgen >/dev/null 2>&1; then
    echo "cbindgen not installed — run: cargo install cbindgen --version 0.27.0" >&2
    exit 1
fi

if [ "${1:-}" = "--check" ]; then
    tmp="$(mktemp)"
    cbindgen --config "$HERE/cbindgen.toml" --output "$tmp" "$HERE" 2>/dev/null
    if ! diff -u "$HEADER" "$tmp" >/dev/null 2>&1; then
        echo "STALE: agentkeys_device.h differs from ffi.rs — run gen-header.sh" >&2
        diff -u "$HEADER" "$tmp" || true
        rm -f "$tmp"
        exit 1
    fi
    rm -f "$tmp"
    echo "ok agentkeys_device.h in sync with ffi.rs"
else
    mkdir -p "$(dirname "$HEADER")"
    cbindgen --config "$HERE/cbindgen.toml" --output "$HEADER" "$HERE" 2>/dev/null
    echo "ok regenerated $HEADER"
fi
