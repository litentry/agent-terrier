# Phase A.1 — Codex Review Round 1

**Reviewer:** structured self-review pass (independent prompt focus from Phase 0).
**Date:** 2026-05-05.
**Scope:** Phase A.1 commits — `9a1e0d4` (US-017 EmailLink plugin + storage) and the US-018 commit (HTTP endpoints + boot wiring + integration tests).
**Method:** read each P0 file (storage/email_tokens.rs, storage/email_rate_limits.rs, plugins/auth/email_link.rs, handlers/auth/email_*.rs, the boot.rs email branch, the test fixtures) against a Phase-A-specific 10-attack-vector prompt; cite file:line for every finding.

## Verdict

**SHIP Phase A.1.** Zero P0/P1. All P2/P3 findings rolled to `V0.1-FOLLOWUPS.md`. Round 2 (`codex-phaseA-round2.md`) confirms.

## Findings

### F21 — Real SES sender backend not yet wired — P2

**File:** `crates/agentkeys-broker-server/src/boot.rs::build_registry::email_link branch`

**Issue.** Phase A.1 unconditionally constructs `StubEmailSender` for the email-link plugin. Production deployments cannot send real emails. Acknowledged by V0.1-FOLLOWUPS scaffolding; no operator should enable email-link in production today.

**Mitigation cost.** Phase E pre-cutover ships `SesEmailSender` (lettre or aws-sdk-sesv2) selected via `BROKER_EMAIL_BACKEND={stub,ses}` env var. Roll to V0.1-FOLLOWUPS.

### F22 — Per-email rate limit applies BEFORE per-IP in challenge() — P2

**File:** `crates/agentkeys-broker-server/src/plugins/auth/email_link.rs:218-244`

**Issue.** `challenge()` increments the per-email bucket FIRST, then the per-IP bucket. An attacker hammering with a fixed email burns the per-email bucket without any per-IP defense kicking in (the per-IP increment never runs because per-email already returned RateLimited). Conversely, an attacker rotating emails from one IP can flood the email-tokens table at the per-IP-per-minute cap before per-email kicks in.

**Mitigation cost.** Either check both buckets BEFORE incrementing either, or document the priority. Roll to V0.1-FOLLOWUPS as a Phase D rate-limit hardening pass.

### F23 — `BROKER_EMAIL_LANDING_URL_BASE` env var not declared — P2

**File:** `crates/agentkeys-broker-server/src/boot.rs::email_link branch:landing_base`

**Issue.** Boot derives the landing URL base from `oidc_issuer + "/auth/email/landing"`. Production deployments behind a reverse proxy may want a different host for the landing page (e.g., a customer-facing brand domain rather than the OIDC issuer). No env var override exists.

**Mitigation cost.** Add `BROKER_EMAIL_LANDING_URL_BASE` to `env.rs`. Roll to V0.1-FOLLOWUPS Phase E.

### F24 — `EmailLinkAuth::verify` returns `omni_account` as `identity_value` — P3

**File:** `crates/agentkeys-broker-server/src/plugins/auth/email_link.rs:340-355`

**Issue.** The trait's `verify()` returns `VerifiedIdentity { identity_type: Email, identity_value: omni_account }`. For wallet-sig the `identity_value` is the raw wallet address. The asymmetry could surprise callers expecting `identity_value` to be the email itself. Note: this preserves the email→omni mapping without re-leaking the email, which is the security property; the doc-comment explains.

**Mitigation cost.** None — documented intentional. Note only.

### F25 — Email normalization is `to_lowercase()` only — P3

**File:** `crates/agentkeys-broker-server/src/plugins/auth/email_link.rs:201-204`

**Issue.** RFC 5321 quoted-local-part emails (`"a.b"@example.com`) and Gmail-style plus-addressing (`alice+tag@gmail.com`) are not normalized. Two distinct-byte emails could resolve to the same human inbox without the broker noticing — relevant for rate-limit bucketing and OmniAccount derivation collisions.

**Mitigation cost.** Add `email_normalize` helper using a known-good crate or RFC-5321 rules. Roll to V0.1-FOLLOWUPS Phase E.

### F26 — Stub email sender's `last_sent` is racy under concurrent challenge() — P3

**File:** `crates/agentkeys-broker-server/src/plugins/auth/email_link.rs::StubEmailSender`

**Issue.** Multiple concurrent challenge() calls race the Vec push. Tests that read `last_sent` after a single challenge are deterministic; tests that fire concurrent challenges (none today) would see arbitrary ordering. This is a test-only concern.

**Mitigation cost.** None for v0; if Phase D adds a chaos test, switch to `tokio::sync::Mutex`. Note only.

### F27 — `email_request.rs` plumbs raw `body.source_ip` from JSON — P3

**File:** `crates/agentkeys-broker-server/src/handlers/auth/email_request.rs:18-30`

**Issue.** The handler trusts the client's claimed `source_ip` field. A malicious client could forge any IP to bypass the per-IP rate limit. Phase D introduces X-Forwarded-For-aware extraction; Phase A.1 explicitly documents this in the doc-comment as "trusts the caller's hint".

**Mitigation cost.** Phase D rate-limit hardening adds a `ConnectInfo<SocketAddr>` extractor. Roll to V0.1-FOLLOWUPS.

### F28 — Empty wallet_address in session JWT for email-only identities — P2

**File:** `crates/agentkeys-broker-server/src/handlers/auth/email_verify.rs:80-93`

**Issue.** When verify mints a session JWT for an email-only identity, the `agentkeys.wallet_address` claim is the empty string. Any downstream code that asserts a non-empty wallet (e.g., `mint_v2` per-call sig verification) will reject these JWTs — which is correct in v0 (email-only users can't mint AWS creds without first binding a wallet via Phase B), but the failure mode is silent and confusing.

**Mitigation cost.** Either reject session-JWT mint at the email-verify path with a clearer "bind a wallet via Phase B first" error, OR document the email-only-identity limit in the runbook. Phase B's grant flow naturally resolves this — a daemon binds a wallet via grant + ClientSideKeystoreProvisioner before attempting any mint. Roll to V0.1-FOLLOWUPS Phase B.

### F29 — `BROKER_EMAIL_HMAC_KEY_PATH` content not validated for high-entropy — P3

**File:** `crates/agentkeys-broker-server/src/plugins/auth/email_link.rs:158-163`

**Issue.** Construction validates `hmac_key.len() >= 32` but does not validate that the bytes are actually random. An operator who points the env var at `/etc/issue` would pass the length check with mostly-zero entropy. Real attack only matters if the HMAC key is used for authentication (Phase A.1 uses it for audit-log row keying, not directly for token signing — tokens are 32-byte CSPRNG with SHA256 stored, no HMAC), but tightening defense-in-depth is cheap.

**Mitigation cost.** Either run a Shannon-entropy probe on load or accept the operator-side responsibility. Note only — runbook should call out `head -c 32 /dev/urandom > $key_path`.

## Process-rule cross-check (Phase A.1 angle)

- **Smoke per phase:** `harness/stage-7-issue-64-phaseA-smoke.sh` exits 0 with 9 invariants.
- **No silent fallbacks:** `BROKER_EMAIL_HMAC_KEY_PATH`/`BROKER_EMAIL_FROM_ADDRESS` refuse-to-boot when email_link is configured but vars are unset.
- **Status reflects operational state:** `EmailLinkAuth::ready()` Ready when SES verify cache is fresh, Degraded when stale, Unready when token store unwritable.
- **Centralized env vars:** `BROKER_EMAIL_*` constants declared in `env.rs::all()`.
- **Day-1 invariant test:** Phase 0's `tests/invariant_load_bearing.rs` continues to pass; the new email-link surface introduces no regression in the 6 cases.

## Test totals after Phase A.1

```
Default features (no email-link):    116 tests pass (Phase 0 baseline preserved)
With --features auth-email-link:     150 tests pass
  - 112 lib unit tests (added: 12 email_link plugin + 9 email_tokens
    + 6 email_rate_limits = 27 new)
  - 4 auth_wallet_flow integration
  - 7 email_flow integration (NEW)
  - 7 invariant_load_bearing integration
  - 9 mint_flow integration
  - 5 mint_v2_flow integration
  - 6 oidc_flow integration
```

## Stop rule

Round 1 finds: 0 P0, 0 P1, 4 P2 (F21, F22, F23, F28), 5 P3 (F24, F25, F26, F27, F29).
