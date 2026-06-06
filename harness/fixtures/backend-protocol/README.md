# backend-protocol fixtures (issue #203)

**Auto-generated — do not hand-edit.** Each `*.json` is a sample broker/worker
request body serialized straight from the serde types in
[`agentkeys-backend-client::protocol`](../../../crates/agentkeys-backend-client/src/protocol.rs),
so its top-level keys are exactly what goes on the wire. Values are placeholders
(`<…>`) — the gate compares **keys only**.

Regenerate after any wire-shape change:

```bash
cargo run -p agentkeys-backend-client --bin dump-protocol-fixtures
```

These are the canonical key-sets the drift gate
[`scripts/check-backend-fixture-drift.sh`](../../../scripts/check-backend-fixture-drift.sh)
diffs every `# @backend-fixture: <shape>`-annotated bash body against. CI runs
both the fixture `--check` (these files match the Rust types) and the bash gate
(annotated bodies match these files) in the `harness-ci.yml` `rust-checks` job.

| File | Shape | Endpoint |
|---|---|---|
| `cap_mint_request.json` | `BrokerCapRequest` | `POST /v1/cap/{cred-store,cred-fetch,memory-put,memory-get,config-store,config-fetch}` |
| `memory_put_body.json` | `MemoryPutBody` | `POST /v1/memory/put` |
| `memory_get_body.json` | `MemoryGetBody` | `POST /v1/memory/get` |
| `config_put_body.json` | `ConfigPutBody` | `POST /v1/config/put` (#201) |
| `config_get_body.json` | `ConfigGetBody` | `POST /v1/config/get` (#201) |
| `audit_append_v2.json` | `AuditAppendV2` | `POST /v1/audit/append/v2` |

> **Gate note:** `config_put_body` (`{cap, plaintext_b64}`) and `config_get_body`
> (`{cap}`) are key-set-identical to the cred-worker store/fetch bodies, so the
> `check-backend-fixture-drift.sh` **pass-2** auto-detector deliberately excludes
> them (it would false-positive on every cred `{cap}` body). Config bodies are
> gated via **explicit `# @backend-fixture: config_*` annotation** (pass 1) only.
