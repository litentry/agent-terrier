# Method A — agent-initiated pairing (replaces #149's master-initiated front-half)

Status: **implemented** (broker + daemon + CLI + harness + docs). Branch `claude/agent-initiated-pairing` off `main` (post-#149). Agent-side unbind / factory-reset re-pair is intentionally **deferred** → #156 (client) + #155 (on-chain self-revoke); everything else in this doc landed.

## Decision + rationale
§10.2 agent bootstrap flips from **master-initiated** (#149: master mints a link code → agent redeems) to **agent-initiated** (A: the agent submits a pairing request → the master claims it by scanning/entering the code). Reasons:

1. **No-input physical devices.** The IoT convention (Matter/HomeKit) is "the device shows a QR/setup code; the owner scans it." A no-keyboard AI companion **cannot** accept a master-minted code typed *into* it — so M is structurally impractical for hardware. A needs only the device's screen (output) + the owner's camera.
2. **Device-initiated unbind / factory-reset → re-pair to a new owner.** Resale / reset is a *device* act. M is master-rooted — the old master would have to cooperate. A handles it: factory reset → fresh key → show a new QR → new owner claims.
3. **Sybil-safe.** The request is *unbound* (names no master) and **inert** until a master deliberately consumes the code, so an agent can't attach itself or flood a master — equivalent to M's "master action is the sole binder."

Replace (not coexist): A subsumes M's device-review (the master sees `device_pubkey` at claim time), keeps arch.md's "one path, one test surface," and reuses #149's on-chain bind + scope tail unchanged.

## Flow (A)
```
1. AGENT (daemon --request-pairing):
   - generate/load K10 in the sandbox; pop_sig over agentkeys-agent-pop preimage
   - POST /v1/agent/pairing/request { device_pubkey, pop_sig }   (no bearer; rate-limited)
   - broker verifies pop_sig, stores an UNBOUND request (operator=∅, TTL 600s),
     returns { request_id (secret), pairing_code }
   - agent DISPLAYS pairing_code (QR / text) and polls (step 4)
2. MASTER (agentkeys agent claim --pairing-code <code> --label A --services memory):
   - scan/enter the code; J1_master-gated POST /v1/agent/pairing/claim
   - broker: look up unbound request by code; bind to THIS operator_omni;
     O_agent = HDKD(O_master, "//label"); mint J1_agent; record pending binding;
     mark request claimed. Returns the device + omni to the master.
3. MASTER binds + scopes (REUSED from #149, unchanged):
   - registerAgentDevice(deviceKeyHash, operator, actor, …)  [msg.sender == master]
   - setScopeWithWebauthn(…)  (Touch ID)
   - POST /v1/agent/pending-bindings/ack
4. AGENT poll → once claimed: { session_jwt: J1_agent, child_omni, … } (device re-proves
   possession with a fresh pop_sig to retrieve it). Persists J1_agent.
```

Unbind / factory-reset + re-pair is **out of this PR**: client-side unbind + re-pair → **#156**, on-chain self-revoke → **#155**. This PR ships only the pairing-direction flip.

## Changes (file-by-file, staged)

### 1. Broker (`crates/agentkeys-broker-server`)
- **NEW** `storage/pairing_requests.rs` — unbound, agent-created request pool keyed by `pairing_code` + `request_id`; `{device_pubkey, pop_sig, status, operator_omni?, child_omni?, label?, created_at}`; `issue / claim / poll / purge_expired`. (Adapt from `link_codes.rs`, which is removed.)
- **NEW** `handlers/agent/request.rs` — `POST /v1/agent/pairing/request` (no bearer, pop_sig-gated, rate-limited).
- **NEW** `handlers/agent/claim.rs` — `POST /v1/agent/pairing/claim` (J1_master-gated): assigns omni, mints J1_agent, records pending binding.
- **NEW** `handlers/agent/poll.rs` — `GET/POST /v1/agent/pairing/poll` (pop_sig-gated): returns J1_agent once claimed.
- **REMOVE** `handlers/agent/{create,redeem}.rs` + `storage/link_codes.rs` + their routes; **KEEP** `pending.rs` (+`/ack`) — the bind tail is reused.
- `mint_oidc_jwt` agent gate (the finding-1/A invariant) is unchanged + still required — J1 still exists pre-on-chain-bind, so the active+operator+actor+role gate stays.

### 2. Daemon (`crates/agentkeys-daemon`)
- `--init-link-code` → `--request-pairing` (submit → display code → poll → persist J1).
  (`--unbind` / factory-reset is deferred → #156.)

### 3. CLI (`crates/agentkeys-cli`)
- `agent create` → `agent claim --pairing-code <code> --label <…> --services <…>`.

### 4. Harness (`harness/phase1-wire-demo.sh`)
- Phase P flips: P.0 = **agent** `--request-pairing` (gets code); P.1 = **master** `agent claim`; P.1b/P.2/P.3 (pending/bind/scope) reused. (The unbind → re-pair test is deferred → #156.)

### 5. Docs
- `docs/arch.md` §10.2 — rewrite the ceremony for A (agent-initiated QR/scan; the IoT model); update §6.2 route list; note unbind (local rekey) + link #155 for on-chain self-revoke. Re-verify §10.2 canonical-names + the route table.
- `docs/operator-runbook-wire.md` — rewrite the pairing walkthrough (agent shows code → master scans/claims → bind → Touch ID), incl. the factory-reset/re-pair demo.

## Security notes
- `pairing_code` + `request_id` must be **high-entropy** (claim-by-code = whoever holds the code binds; request_id = the agent's retrieval ticket). Display the code only to the intended master (proximity for HW; out-of-band for SW).
- The `request` endpoint is **unauthenticated** → rate-limit + TTL + cap the pool (DoS, not Sybil).
- Master **reviews `device_pubkey`** at claim before `registerAgentDevice` (the M second-factor, preserved).
- Pre-bind window unchanged: J1 exists post-claim, pre-on-chain-bind → the mint-oidc-jwt on-chain gate (active + operator==parent + actor + CAP_MINT) is still mandatory.

## Verification
Per stage: `cargo build` + `cargo test` (broker/daemon/mcp/core), `cargo fmt --all --check`, `clippy --workspace --all-targets -- -D warnings`, `bash -n` harness. Behavioral confirmation = a live `phase1-wire-demo.sh --real --webauthn` run after a broker redeploy (can't integration-test the sandbox/broker locally).

## Out of scope (tracked)
- Agent-side unbind / factory-reset + re-pair (client lifecycle) → **#156**.
- On-chain agent self-revocation (contract change + Heima-mainnet redeploy) → **#155**.
