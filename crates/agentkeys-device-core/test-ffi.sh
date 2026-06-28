#!/usr/bin/env bash
# Board-free verification of the agentkeys-device-core C ABI (issue #367): build
# the no_std crate as a host staticlib (the SAME artifact the firmware links for
# Xtensa, minus the cross target), compile the C smoke harness against the
# generated header, link, and run it. Proves the FFI the firmware's
# device_identity.c calls works across the real C boundary — no ESP-IDF, no board.
#
#   bash crates/agentkeys-device-core/test-ffi.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
HEADER_DIR="$REPO_ROOT/firmware/esp32s3-touch-lcd-4b/components/agentkeys_device/include"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

echo "==> building host staticlib (--features freestanding, panic=abort)"
CARGO_TARGET_DIR="$OUT/target" cargo rustc -p agentkeys-device-core \
    --features freestanding --crate-type staticlib --release -- -Cpanic=abort
LIB="$OUT/target/release/libagentkeys_device_core.a"
[ -f "$LIB" ] || { echo "staticlib not produced at $LIB" >&2; exit 1; }

echo "==> compiling + linking the C smoke harness"
CC="${CC:-cc}"
# Rust staticlibs need the system libs they pull in (pthread/dl/m on Linux);
# macOS resolves them via libSystem automatically.
EXTRA_LIBS=""
case "$(uname -s)" in
    Linux) EXTRA_LIBS="-lpthread -ldl -lm" ;;
esac
"$CC" "$HERE/ctest/ffi_smoke.c" -I "$HEADER_DIR" "$LIB" $EXTRA_LIBS -o "$OUT/ffi_smoke"

echo "==> running"
"$OUT/ffi_smoke"
