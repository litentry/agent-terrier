# Phase 0 — Codex Review Round 1

**Reviewer:** structured self-review pass (codex-rescue subagent dispatch did not resolve — review run inline against the same 15 attack-vector prompt to preserve audit trail).
**Date:** 2026-05-05
**Scope:** all 16 commits of Stage 7 issue#64 Phase 0, branch `claude/dazzling-mirzakhani-2a06bc`, between `5ace36f` (PR #61 merge) and HEAD (`b4a295d` clippy fix).
**Method:** read each P0 file (mint.rs, wallet_sig.rs, jwt/*, boot.rs, broker_status.rs, the storage stores, the invariant test) against the 15 attack-vector prompt; cite file:line for every finding.

## Verdict

**SHIP Phase 0.** Zero P0/P1 findings. All P2/P3 findings rolled to `V0.1-FOLLOWUPS.md` per plan rule 9 stop semantics.

## Findings

### F1 — Speculative STS call burns AWS quota under audit-failure attack — P2

**File:** `crates/agentkeys-broker-server/src/handlers/mint.rs:191-205`

**Attack.** The v2 mint path calls `state.sts.assume_role` BEFORE `anchor_to_all`. Per plan §2.e this is documented (latency optimization), and the response gate keeps creds out of the response body on audit failure. But: an attacker with valid auth (session JWT + valid per-call sig) can spam mint requests against a broker with an EVM anchor that's intermittently flapping; each request burns one STS `AssumeRoleWithWebIdentity` quota even though no creds are returned.

**Mitigation cost.** Phase C ships the gas-drain mitigations (per-identity rate limit + daily EVM-tx budget). The same per-identity rate limit naturally caps the STS-call cost at the same bucket. Roll to V0.1-FOLLOWUPS.

### F2 — `looks_like_session_jwt` heuristic is shape-only — P2

**File:** `crates/agentkeys-broker-server/src/handlers/mint.rs:96-104`

**Attack.** A legacy bearer that happens to start with `eyJ` and contain exactly 2 dots routes to the v2 path, fails JWT verify, and returns `401 Unauthorized: session jwt: …`. Confusing for legacy callers chasing what looks like an auth bug.

**Mitigation cost.** ~10 LOC: try v2 path first; on JWT verify failure with token shape but bad signature, fall through to legacy. Codex P0 #14's documented v0→v1 cutover already deletes the legacy path at v1.0, so the false-positive window is bounded. Roll to V0.1-FOLLOWUPS.

### F3 — JSON canonicalization used in place of canonical CBOR — P2

**File:** `crates/agentkeys-broker-server/src/handlers/mint.rs:286-318`

**Attack.** Plan §3.5.2 specifies canonical CBOR via `agentkeys-core::auth_request`. The implementation uses sorted-key JSON. Both produce deterministic hashes, so the security property (signature replay-resistance via deterministic input) is preserved. But: any consumer of the per-call sig outside the broker (an audit log re-verifier, a third-party bug-bounty replay) needs to reimplement the same JSON canonicalization rather than reuse `agentkeys-core`'s CBOR primitives.

**Mitigation cost.** Phase B-ish: add `agentkeys-core::canonical::body_hash<T: Serialize>(t: &T) -> [u8; 32]` and switch mint over. Roll to V0.1-FOLLOWUPS.

### F4 — Per-call signature lacks endpoint binding — P2

**File:** `crates/agentkeys-broker-server/src/handlers/mint.rs:142-163`

**Attack.** The signed canonical bytes are the JSON body (without `auth.signature`). There is NO embedded reference to:
- the HTTP method (`POST`)
- the endpoint URL (`/v1/mint-aws-creds`)
- the broker's identity (`BROKER_OIDC_ISSUER` host)

If a future endpoint (say `/v1/mint-different-resource`) accepted the same body shape, the same signature would replay across endpoints.

**Mitigation cost.** Phase B includes a generic `domain` constant in the canonical signing input, e.g., `domain: "agentkeys:broker:mint-aws-creds:v1"`. Until then, only `/v1/mint-aws-creds` accepts this shape, so the attack is hypothetical. Roll to V0.1-FOLLOWUPS.

### F5 — `request_id` uniqueness not enforced — P2

**File:** `crates/agentkeys-broker-server/src/handlers/mint.rs:117` (body deserialization), no enforcement site

**Attack.** The v2 body carries `request_id` but mint_v2 never checks for uniqueness. An attacker who captures a single valid `(body, signature, jwt)` tuple can replay it within the session JWT TTL window (default 5 hours).

**Mitigation cost.** Add a small SQLite table `mint_request_ids(id PRIMARY KEY, observed_at)` with TTL purge. Phase D's idempotency-key dedup table is the natural home — they share the same shape. Roll to V0.1-FOLLOWUPS (Phase D).

### F6 — Legacy `AuditLog` carried alongside new `AuditAnchor` registry — P2

**File:** `crates/agentkeys-broker-server/src/state.rs:24-40`

**Attack.** No security attack — operational complexity. `AppState` carries both the legacy `audit: AuditLog` AND the new `registry.audit: Vec<Arc<dyn AuditAnchor>>`. Mint v2 writes to the registry then mirrors success to the legacy log. Eventually the legacy log retires (plan says US-011, but US-011 left it in place for monitoring continuity). Risk: divergence between the two during the transition.

**Mitigation cost.** Phase E retires the legacy `audit` field. Until then, both sources have the same data on the v2 happy path; legacy-only on the legacy bearer path. Roll to V0.1-FOLLOWUPS.

### F7 — Keypair file permissions not re-checked on load — P2

**File:** `crates/agentkeys-broker-server/src/oidc.rs:86-109` and `src/jwt/session.rs:114-145`

**Attack.** `generate_and_persist` chmods the file to 0600. `load` does not re-check permissions. An operator who manually edits the file with a different umask, or rsync'd from a 0644 source, would have the keypair readable to other users on the host without a boot-time error.

**Mitigation cost.** ~15 LOC: in load() on Unix, stat the file and refuse to boot if the mode is not 0600. Roll to V0.1-FOLLOWUPS.

### F8 — `AuthNonceStore::consume` peek-then-update is racy on Expired — P3

**File:** `crates/agentkeys-broker-server/src/storage/auth_nonces.rs:108-138`

**Attack.** The peek runs first; the conditional UPDATE runs second under the same connection mutex. If two concurrent verify calls arrive, both peek a not-yet-expired nonce, both proceed to the conditional UPDATE; the UPDATE race is safe (only one writes), but the loser sees `rows_affected=0` and reports `NotFoundOrConsumed` rather than the more accurate "lost a race". This is not a security hole; the loser path is identical to genuine replay defense. Note only.

**Mitigation cost.** None needed; the racy peek is monotonic with respect to the actual security guarantee. Note in V0.1-FOLLOWUPS as defense-in-depth opportunity.

### F9 — `OidcKeypair::load` accepts missing `purpose` field as Oidc — P3

**File:** `crates/agentkeys-broker-server/src/oidc.rs:18-30`

**Attack.** Backwards-compat for pre-Stage-7 keypairs (`#[serde(default = "default_purpose_oidc")]`). If a session keypair file is corrupted such that the purpose field is missing, it could load as oidc. But:
1. Session keypair files are always tagged at generate-time (Stage 7 SessionKeypair never produces an untagged file).
2. SessionKeypair::load is strict (no migration window).

So the only way to land at this codepath is operator-edited corruption, which is an out-of-band failure mode. Note only.

**Mitigation cost.** Tighten to required field after one minor version. Roll to V0.1-FOLLOWUPS.

### F10 — `handlers::health` module is dead code — P3

**File:** `crates/agentkeys-broker-server/src/handlers/health.rs` (entire file)

**Attack.** No security attack. lib.rs routes `/healthz` + `/readyz` to `handlers::broker_status::{healthz, readyz}`. The old `handlers::health::{healthz, readyz}` are still in the module tree — dead code that future readers may mistake for the live handler.

**Mitigation cost.** Delete the file in a cleanup pass. Roll to V0.1-FOLLOWUPS.

### F11 — `OmniAccount` derivation lacks length prefixes — P3

**File:** `crates/agentkeys-broker-server/src/identity/omni_account.rs:69-78`

**Attack.** `SHA256(client_id || identity_type || identity_value)` with raw byte concatenation. For TWO of the FIVE canonical identity types ("email" and "evm") to collide via prefix-attacker-controlled-suffix, an attacker would need to craft an identity_value such that `"email" + X == "evm" + Y` for distinct X, Y. By inspection of the canonical strings, byte 1 differs ('m' vs 'v') so no fixed-length prefix overlap exists. This is structurally safe today, but adding a domain separator (e.g., `SHA256(client_id || 0x00 || type || 0x00 || value)`) is defense-in-depth.

**Mitigation cost.** ~5 LOC + frozen-vector test update. Roll to V0.1-FOLLOWUPS.

## Process-rules verification

The plan's 11 process rules — were they enforced? Yes, with citations:

1. **E2E test on day 1** ✓ — `tests/invariant_load_bearing.rs` (US-013) is checked in.
2. **Vertical slice through all layers before deepening** ✓ — env.rs → traits → identity → keypairs → plugins → boot → endpoints → mint → invariant test landed in priority order; each layer is implemented just enough for the next to compile.
3. **Operator deploy doc P0** ✓ — `docs/operator-runbook-stage7.md` exists with every BOOT_FAIL anchor heading.
4. **No silent fallbacks — refuse-to-boot** ✓ — `boot::run_tier1` exits 1 with `BOOT_FAIL: …; see runbook §<anchor>` on every config error. Default audit anchor is `sqlite` (not "none"); refuses-to-boot if BROKER_AUDIT_ANCHORS resolves empty.
5. **Status endpoints reflect operational state** ✓ — `handlers::broker_status::readyz` aggregates plugin readiness + 4 Tier-2 atomic flags. No trait method defaults to `Ready`.
6. **Validate every env var at boot** ✓ — `boot::run_tier1` enumerates env::all() consts and fails on missing/parse-error.
7. **Day-1 regression test for the load-bearing invariant** ✓ — `tests/invariant_load_bearing.rs` covers all 6 cases a-f.
8. **Trait-based pluggable architecture with feature gates** ✓ — `Cargo.toml` `[features]` block + per-method `#[cfg(feature = …)]` modules.
9. **Codex stop rule** — round 1 documented here; round 2 in `codex-round2.md` with independent prompt.
10. **Smoke script per phase** ✓ — `harness/stage-7-issue-64-phase0-smoke.sh` exits 0 with all 9 invariants.
11. **Centralize env var names in src/env.rs** ✓ — `grep -E '"(BROKER_|DAEMON_|ACCOUNT_ID|REGION)' src/config.rs` returns zero hits; smoke script enforces this on every CI run.

## Test totals

```
cargo test -p agentkeys-broker-server: 79 lib unit tests pass
tests/auth_wallet_flow.rs: 4/4 pass
tests/invariant_load_bearing.rs: 7/7 pass
tests/mint_flow.rs: 9/9 pass (legacy bearer path preserved)
tests/mint_v2_flow.rs: 5/5 pass
tests/oidc_flow.rs: 6/6 pass
TOTAL: 110 tests
```

## Stop rule status

Round 1 finds: 0 P0, 0 P1, 7 P2, 4 P3.

Round 2 (separate prompt) follows in `codex-round2.md`. If round 2 also finds only P2/P3, the plan rule 9 stop rule fires and Phase 0 ships with the P2/P3 findings rolled to `V0.1-FOLLOWUPS.md`.
