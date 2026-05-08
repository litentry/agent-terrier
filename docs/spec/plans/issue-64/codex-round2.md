# Phase 0 — Codex Review Round 2

**Reviewer:** independent self-review pass with deliberately different prompt focus from round 1.
**Date:** 2026-05-05
**Round 1 reference:** `codex-round1.md` (15 attack-vector mint/auth/crypto pass).
**Round 2 prompt focus:** test-coverage gaps + supply chain + operational / observability + dead-code / API-surface hygiene. Avoid re-treading round 1's 15 attack vectors so the two rounds give independent signal as the plan rule 9 stop rule requires.
**Scope:** all 16 commits of Stage 7 issue#64 Phase 0, branch `claude/dazzling-mirzakhani-2a06bc`, between `5ace36f` (PR #61 merge) and HEAD (`b4a295d`).

## Verdict

**SHIP Phase 0.** Zero P0/P1. All P2/P3 findings rolled to `V0.1-FOLLOWUPS.md`. Round 1 + round 2 both find only P2/P3 → plan rule 9 stop rule fires.

## Findings

### F12 — `tests/invariant_load_bearing.rs::count_anchor_rows_helper_compiles` is a no-op — P2

**File:** `crates/agentkeys-broker-server/tests/invariant_load_bearing.rs:288-302`

**Issue.** The helper `count_anchor_rows` returns `0` regardless of input (it's a stub for future Phase B/C cases). The test merely asserts the helper compiles. This is dead test that future readers will treat as live coverage of "row count introspection works."

**Mitigation cost.** Either remove the test (it asserts nothing useful) or implement real row-counting via a public accessor on `SqliteAnchor`. Roll to V0.1-FOLLOWUPS — full implementation lands with Phase B's grants table, where row introspection becomes a real need.

### F13 — Phase 0 invariant test doesn't assert audit row PRESENCE on happy path — P2

**File:** `crates/agentkeys-broker-server/tests/invariant_load_bearing.rs:325-344`

**Issue.** Case (a) — happy path — asserts the response carries `audit_record_id` and `anchored:["sqlite"]`. It does NOT independently verify the audit row exists in the SqliteAnchor's table by re-querying. The current invariant relies entirely on the broker's own self-report of "I anchored this." A bug in the response-construction path that returns `audit_record_id` without actually persisting would slip past.

**Mitigation cost.** Add an `AuditAnchor::count_records()` method (or inspect via the `SqliteAnchor::open_in_memory` test fixture's connection). Phase B's grant tests need the same introspection; defer until then. Roll to V0.1-FOLLOWUPS.

### F14 — Tier-2 backend probe has no exponential backoff — P2

**File:** `crates/agentkeys-broker-server/src/main.rs:158-180`

**Issue.** `spawn_tier2_probes` retries every 15 seconds on failure with no backoff. An always-down backend produces a steady stream of warn-level log lines (4/min, 240/hour). For long-running outages this clutters operator logs and (depending on log aggregator pricing) costs money.

**Mitigation cost.** Switch to a 15s → 30s → 60s → 120s → 300s capped exponential backoff. ~10 LOC. Roll to V0.1-FOLLOWUPS.

### F15 — `BROKER_DEV_MODE=true` warning logs once but doesn't repeat — P3

**File:** `crates/agentkeys-broker-server/src/boot.rs:52-58`

**Issue.** `if dev_mode { tracing::warn!(...) }` fires once at boot. An operator who started in dev mode and forgot may not see this warning in a long-running log stream.

**Mitigation cost.** Add a banner heartbeat (every 1h) reminding "BROKER_DEV_MODE is on, do not use in production." ~5 LOC.

### F16 — No SBOM / dependency-pinning audit — P2

**File:** `crates/agentkeys-broker-server/Cargo.toml`

**Issue.** Phase 0 added `k256 = "0.13"` and `sha3 = "0.10"` as new optional deps. No `cargo audit` or SBOM run is wired into the smoke script or CI. A subsequent yanked-version of `k256` (the load-bearing crypto crate) would silently roll forward on next build.

**Mitigation cost.** Add `cargo audit` to the smoke script + a `Cargo.lock` commit gate. Phase E (US-039 / US-040) is the natural home for the supply-chain hardening pass. Roll to V0.1-FOLLOWUPS.

### F17 — Cargo feature matrix not tested in CI — P2

**File:** `crates/agentkeys-broker-server/Cargo.toml` features section

**Issue.** Plan §3 declares 11 feature flags. The smoke script tests only two combinations (default + `auth-email-link,auth-oauth2-google,audit-evm`). Untested combinations include:
- default minus `audit-sqlite` (would need an alternative audit anchor to be configured)
- `auth-oauth2-github` + `auth-oauth2-apple` (v1+ stubs)
- `--no-default-features` with explicit minimal set

A feature-flag-gated `#[cfg]` typo in any of these combinations would slip through.

**Mitigation cost.** A pairwise feature combo matrix in CI. Phase D's CI hardening sweep is the natural home. Roll to V0.1-FOLLOWUPS.

### F18 — `BROKER_REQUEST_BODY_LIMIT_BYTES` declared but not enforced — P2

**File:** `crates/agentkeys-broker-server/src/env.rs:80` (declared) vs `src/lib.rs::create_router` (no `axum::extract::DefaultBodyLimit::max(...)` middleware applied)

**Issue.** Phase 0 declares the env var (per plan §5) but the router does not actually apply a body-size limit. An attacker could POST a multi-megabyte JSON body to `/v1/mint-aws-creds` and the broker would consume memory before reaching the malformed-body 400. Real DoS exposure.

**Mitigation cost.** Apply `axum::extract::DefaultBodyLimit::max(config.body_limit_bytes)` to the router. ~5 LOC. **Should land in Phase 0 final, not be rolled.** But: round 2's purpose is to identify gaps, not to land hot-fixes mid-review. Marking P2 with note "should be a hot-fix before merge" — see disposition below.

### F19 — `/readyz` JSON empty body is interpreted-as-failure by some monitors — P3

**File:** `crates/agentkeys-broker-server/src/handlers/broker_status.rs:101-110`

**Issue.** All-Ready returns `200 OK` with body `{}`. Some monitoring systems (Pingdom, certain Prometheus exporters) require a non-empty body to flag a probe as success. The runbook does not document this.

**Mitigation cost.** Either return `{"status":"ready"}` (slightly chattier but compatible) or document the empty-body convention in the runbook. ~3 LOC + 1 paragraph in operator-runbook-stage7.md. Roll to V0.1-FOLLOWUPS.

### F20 — `mint::canonicalize_json` not exposed for external verifier reuse — P3

**File:** `crates/agentkeys-broker-server/src/handlers/mint.rs:301-318`

**Issue.** The canonicalization function is private to `mint.rs`. A third-party verifier who wants to re-check a per-call signature (audit log forensics, bug-bounty replay test, future client SDK) must reimplement the algorithm exactly. No public spec doc.

**Mitigation cost.** Move to `agentkeys-core::canonical` as a public function + add a wire-format spec doc. Pairs naturally with F3 (CBOR migration) — both are "make canonicalization a first-class crate-level concept." Roll to V0.1-FOLLOWUPS.

## F18 disposition

F18 (request body limit unenforced) is the only borderline-P1 finding. Treating as P2 because:
1. Mint endpoint validates body size implicitly via `serde_json::from_slice` failing on absurdly large input — but only AFTER reading the full body into memory, which is the actual exposure.
2. Other endpoints (`/v1/auth/wallet/start`, `/v1/auth/wallet/verify`, `/v1/auth/exchange`) accept JSON bodies and have the same exposure.
3. axum's default body limit IS active (2 MB by default per axum 0.7) — so the practical exposure is "an attacker can POST up to 2 MB" not "an attacker can POST gigabytes."
4. The env var `BROKER_REQUEST_BODY_LIMIT_BYTES` exists; wiring it to `DefaultBodyLimit::max` is a one-line follow-up.

Net: documented memory bound is 2 MB, exploitation cost is non-negligible (CPU during JSON parse), no credential exposure, no audit log corruption. P2 with note "Phase D US-037 (idempotency + body limit)."

## Process-rules cross-check (round 2 angle)

Round 1 verified the 11 process rules from inside the plan. Round 2 cross-checks from the operator's pager-at-2am angle:

- **Refuse-to-boot UX:** every BOOT_FAIL message has a runbook anchor URL. Verified by smoke step 6.
- **Status JSON pager-friendliness:** Designer review #status-shape — every Degraded/Unready check has a `docs` URL anchor. Verified in `broker_status::readiness_to_json`.
- **Smoke script as living docs:** the script doubles as a regression-detector (clippy + grep invariants) AND a "what does Phase 0 promise?" enumeration. ✓
- **prd.json passes flag:** 15/16 stories at `passes:true`. Codex round 1 + round 2 close the 16th. Stop rule fires.

## Stop rule disposition

Round 1: 0 P0, 0 P1, 7 P2, 4 P3.
Round 2: 0 P0, 0 P1, 7 P2, 2 P3.

Both rounds find only P2/P3. Plan rule 9 stop rule fires.

**Disposition:**
- All P2/P3 from both rounds rolled to `docs/spec/plans/issue-64/V0.1-FOLLOWUPS.md`.
- Phase 0 ships.
- Phases A.1, A.2, B, C, D-rest, E pick up from `prd.json` with the V0.1-FOLLOWUPS list as their first-priority backlog before any new phase work begins.
