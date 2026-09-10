# Card-contract golden fixtures (#670)

One JSON card document per fixture, rendered by EVERY renderer's test:

- `agentkeys-protocol::card` (Rust) — parses each fixture and pins the
  plain-text (v0 `doc`) rendering.
- `@agentkeys/design-system/react` `CardView` — the console renderer; the
  parent-control snapshot test renders each fixture in `en` and `zh` and
  compares to the `<name>.<locale>.html` golden beside it
  (`UPDATE_CARD_GOLDENS=1 npm test --prefix apps/parent-control` rewrites them).

The card document's ONE owner is `crates/agentkeys-protocol/src/card.rs`
(ts-rs generates the console type). Adding a fixture: drop `<name>.json` here
and list it in both tests.
