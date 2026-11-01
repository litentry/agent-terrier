#!/usr/bin/env bash
# CI gate (#322): the committed policy-intent classifier dataset must pass the
# SAME deterministic validator the runtime gate uses, and the gold set must pass
# the eval self-test. This is what makes "CI fails on a safety regression" real:
# edit a gold/seed label to lower a sensitivity floor, emit a decision field, or
# name a fabricated operation, and this gate goes red.
#
# Cheap + deterministic + no network. The validator bin is already compiled by
# the workspace build that precedes this in rust-checks; python3 is stdlib-only
# here (the eval self-test needs no pip install).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
DS="ml/policy-intent-dataset"

echo "→ build classify-dataset validator"
cargo build -q -p agentkeys-classify-dataset --bin classify-dataset
BIN="target/debug/classify-dataset"

# The portable copy under ml/validator must be byte-identical to the canonical
# crates (lib.rs modulo the ts-rs frontend-codegen lines) — ml/ is designed to
# be lifted into another project, and a drifted copy would validate a dataset
# against a DIFFERENT contract than the runtime gate. Fix upstream, re-copy.
echo "→ vendored ml/validator parity"
for f in compile.rs policy_intent.rs validate.rs; do
  diff -u "crates/agentkeys-catalog/src/$f" "ml/validator/agentkeys-catalog/src/$f" \
    || { echo "fail ml/validator drifted from crates/agentkeys-catalog/src/$f"; exit 1; }
done
diff -u <(sed -e 's/, ts_rs::TS//' -e '/#\[ts(export/d' crates/agentkeys-catalog/src/lib.rs) \
  "ml/validator/agentkeys-catalog/src/lib.rs" \
  || { echo "fail ml/validator lib.rs drifted (modulo ts-rs strip)"; exit 1; }
for f in main.rs record.rs; do
  diff -u "crates/agentkeys-classify-dataset/src/$f" "ml/validator/classify-dataset/src/$f" \
    || { echo "fail ml/validator drifted from crates/agentkeys-classify-dataset/src/$f"; exit 1; }
done

echo "→ validate committed corpus (catalog + safety invariants)"
"$BIN" validate "$DS/seeds/seeds.jsonl"
"$BIN" validate "$DS/data/gold.jsonl"

echo "→ eval self-test (gold vs gold: exact 100%, zero high-risk false negatives)"
CATALOG_JSON="$(mktemp)"
"$BIN" dump-catalog > "$CATALOG_JSON"
python3 "$DS/eval.py" --self-test --catalog "$CATALOG_JSON"
rm -f "$CATALOG_JSON"

echo "ok classify-dataset gate green"
