# Issue #144 — Full arch.md §10.2 agent-bootstrap (HDKD omni + broker link-code endpoints)

Converges the PR #141 **interim** §10.2 (agent omni derived from the agent's own
wallet; `openssl rand` link-code stub) to the literal ceremony: the **master**
mints a one-time link code bound to a **hard-derived child omni**
`O_agent = SHA256("agentkeys-hdkd-v1" || O_master || "//label")`; the **agent
daemon** generates its own K10 in the sandbox, redeems the code (proving K10
possession via `pop_sig`), and the broker mints **`J1_agent`** carrying the HDKD
omni + parent lineage. The master then approves the binding + scope async (push →
one Touch ID), iOS/Android-style.

## Decisions (asked + answered — see PR description)
1. **Master submits the on-chain binding** (no contract change, no broker chain key). Broker mints the code + `J1_agent`, records a pending binding; the master pulls it and submits `registerAgentDevice` + `setScopeWithWebauthn`.
2. **Child omni is PUBLIC + recomputable** (`SHA256(domain‖O_master‖//label)`); unforgeability = the J1_master-gated `/v1/agent/create` + master-submitted binding. Agent keeps a K10 device key only (omni decoupled from it).
3. **Daemon owns keygen + redeem** (`--init-link-code`), sharing `agentkeys-core::device_crypto` with the CLI.

## Implementation order (every step landed unless noted)

| # | Step | Files | Status |
|---|------|-------|--------|
| 1 | Shared `device_crypto` (keccak/evm_address/eip191/ecrecover/pop + `DeviceKey`) | `crates/agentkeys-core/src/device_crypto.rs`, `lib.rs`, `Cargo.toml` (+`rand_core`) | ✅ |
| 2 | HDKD `child_omni`/`child_omni_hex` + `validate_label` (+ frozen vectors) | `crates/agentkeys-core/src/actor_omni.rs` | ✅ |
| 3 | Link-code + pending-binding store (SQLite, single-use, TTL 600s) | `crates/agentkeys-broker-server/src/storage/link_codes.rs` (+ `mod.rs`, `state.rs`, `boot.rs`, `main.rs`) | ✅ |
| 4 | `AgentKeysClaims` + `mint_agent_session_jwt` (parent_omni/derivation_path/device_pubkey) | `jwt/verify.rs`, `jwt/issue.rs` | ✅ |
| 5 | `POST /v1/agent/create` (J1_master-gated) | `handlers/agent/create.rs` | ✅ |
| 6 | `POST /v1/auth/link-code/redeem` (pop_sig-gated, pre-consume verify) | `handlers/agent/redeem.rs` | ✅ |
| 7 | `GET /v1/agent/pending-bindings` (J1_master-gated; push substrate) | `handlers/agent/pending.rs` | ✅ |
| 8 | `mint-oidc-jwt` reads `actor_omni` from the claim (STS-relay prereq; wallet-session byte-identical) | `handlers/oidc.rs` | ✅ |
| 9 | Route registration | `lib.rs`, `handlers/mod.rs`, `handlers/grant/mod.rs` (`require_session_jwt` → `pub(crate)`) | ✅ |
| 10 | Daemon `--init-link-code` one-shot (keygen in sandbox → redeem → persist J1_agent → emit artifact) | `crates/agentkeys-daemon/src/main.rs` | ✅ |
| 11 | CLI `agent create` + `agent pending` (master-side) | `crates/agentkeys-cli/src/agent_admin.rs`, `main.rs`, `lib.rs` | ✅ |
| 12 | Harness Phase P: P.0 create (real code) → P.1 install (daemon) → P.2 bind → P.3 grant; build+upload daemon binary | `harness/phase1-wire-demo.sh` | ✅ |
| 13 | Docs reconciliation (§10.2 steps, §5 `agent_omni`, §6.2, route list) | `docs/arch.md` | ✅ |
| 14 | Runbook Phase P (daemon keygen + real code + retry note) | `docs/operator-runbook-wire.md` | ✅ |

### Deviation note (vs the asked plan)
The asked plan listed CLI `agent bind` + `agent grant` Rust subcommands. Chain
submission lives in shell + `cast` by architecture, and the two existing chain
helpers (`heima-agent-create.sh --from-pubkey` = **bind**, `heima-scope-set.sh
--webauthn` = **grant**) already provide the deterministic two-step split the
test drives. So the CLI ships `agent create` + `agent pending` (master-side, the
genuinely-new broker surfaces incl. the production rendezvous); bind/grant remain
the two shell helpers. The optional one-gesture `agent approve` wrapper is NOT
implemented (the two helpers are the split). Documented for transparency.

## Tests
- `cargo test -p agentkeys-core` — `child_omni` frozen vector; `pop_sig` sign→ecrecover round-trip (redeem-critical).
- `cargo test -p agentkeys-broker-server --features auth-email-link` — link-code store (issue/consume/TTL/single-use/pending/mark_bound/purge); `agent_bootstrap_flow` integration (create-gated, bad-label, full create→redeem→pending, bad-pop_sig-retryable); `mint-oidc-jwt` wallet-session byte-identical regression + agent HDKD-omni tag.
- `cargo test -p agentkeys-cli -p agentkeys-daemon` — compile + existing suites (note: `k11::tests::enroll_writes_file_with_strict_perms` is a pre-existing parallel-execution flake — passes in isolation; unrelated to #144).
- End-to-end: `bash harness/phase1-wire-demo.sh --real --webauthn` — Phase P uses the real broker code + daemon redeem + master bind/grant; assert 4.2 deterministic memory-inject stays green (STS relay tags the HDKD omni).

## Out of scope (deferred)
Broker chain-write / meta-tx; secret-keyed HDKD / frozen genesis seed; HDKD
sub-actors; broker-side K11 verify (stays on-chain); production push transport
(APNs/FCM) — the pending-binding data model + `pending-bindings` endpoint ship now.
