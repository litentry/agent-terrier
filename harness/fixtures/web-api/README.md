# web-api fixtures (issue #203 / the #206 parity ladder)

Canonical contracts for the daemon's **web API** (`/v1/master/*`) — the
frontend↔daemon↔harness surface, distinct from the broker/worker client protocol
in [`../backend-protocol/`](../backend-protocol/).

`master_memory_plant.json` pins the `POST /v1/master/memory/plant` route + the
`ApiMemoryEntry` body shape. Three consumers must agree:

| Consumer | How it's gated |
|---|---|
| daemon (Rust, source of truth) — `MASTER_MEMORY_PLANT_ROUTE` + `ApiMemoryEntry` in [`ui_bridge.rs`](../../../crates/agentkeys-daemon/src/ui_bridge.rs) | `ui_bridge` unit test `master_memory_plant_contract_matches_fixture` (run by `cargo test`) |
| React frontend — [`daemon.ts`](../../../apps/parent-control/lib/client/daemon.ts) `plantMemory` | `# @web-fixture` annotation → [`check-web-api-drift.sh`](../../../scripts/check-web-api-drift.sh) |
| harness — [`web-parity-demo.sh`](../../web-parity-demo.sh) step 3 | `# @web-fixture` annotation → `check-web-api-drift.sh` |

**Changing the contract:** edit `ApiMemoryEntry` / the route const in `ui_bridge.rs`,
update this fixture to match (the unit test enforces it), and the two consumers are
re-gated by `check-web-api-drift.sh`. This is rung 2 of the parity ladder (see
[`../../AGENTS.md`](../../AGENTS.md) "Parity/wiring checks evolve down a ladder"); the
rung-3 endgame is compiling the daemon plant types into the browser host via
`agentkeys-web-core` so `daemon.ts` stops hand-building the body.
