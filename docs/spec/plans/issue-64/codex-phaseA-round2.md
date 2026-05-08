# Phase A.1 — Codex Review Round 2

**Independent prompt focus:** test coverage gaps + operator UX + cross-feature interactions (vs round 1's wire-format + crypto + plugin-construction lens).
**Date:** 2026-05-05.

## Verdict

**SHIP Phase A.1.** Round 1 + round 2 both find only P2/P3 → plan rule 9 stop rule fires.

## Findings

### F30 — No test exercises the SES verify cache TTL transition — P2

**File:** `crates/agentkeys-broker-server/src/plugins/auth/email_link.rs::ready` + `tests/email_flow.rs`

**Issue.** `ready()` returns Ready/Degraded/Unready based on the SES verify cache's `last_verified_at`. The plugin unit tests cover absent-cache (Degraded) and fresh-cache (Ready) but not the 24h-stale transition. No test asserts that a fresh-then-aged cache flips Ready → Degraded at the boundary.

**Mitigation cost.** ~30 LOC test using a mock-clock or hand-edited cache file with an old timestamp. Roll to V0.1-FOLLOWUPS.

### F31 — Stub SES sender shipped to production-feature build — P2

**File:** `crates/agentkeys-broker-server/src/boot.rs::email_link branch`

**Issue.** Boot unconditionally instantiates `StubEmailSender`. There's no compile-time gate distinguishing "test feature" from "production feature." An operator who naively enables `--features auth-email-link` and configures `BROKER_AUTH_METHODS=email_link` gets a broker that successfully responds to email-link request but never actually sends mail. No runtime warning surfaces this.

**Mitigation cost.** Either: (a) emit a startup banner `tracing::warn!("StubEmailSender configured — no real emails will be sent")`, OR (b) gate the stub behind a separate feature flag like `auth-email-link-stub` so the production feature requires the SES sender to be wired. Roll to V0.1-FOLLOWUPS Phase E (US-039 SES wiring).

### F32 — `email_link` route registration relies on a `Pipe` helper trait — P3

**File:** `crates/agentkeys-broker-server/src/lib.rs::register_email_link_routes` + `Pipe` impl

**Issue.** US-018 introduced a `Pipe` blanket impl to chain the conditional route registration. This adds a tiny bit of cleverness to the router build path. A simpler form `let app = ...; let app = if cfg!(feature="auth-email-link") { app.route(...) } else { app };` would be more explicit. Note only — the `Pipe` trait is a stylistic preference.

**Mitigation cost.** Refactor to explicit conditional. Roll to V0.1-FOLLOWUPS Phase E cleanup.

### F33 — `email_request.rs` returns `from_address` to caller in `_dev_landing_url` — P3

**File:** `crates/agentkeys-broker-server/src/plugins/auth/email_link.rs:259-263` + `src/handlers/auth/email_request.rs`

**Issue.** The plugin's `challenge.extras` carries `_dev_landing_url` field for offline diagnostics. Production responses should not include this — but the request handler unconditionally lifts it into the response unless explicitly stripped. Today's handler omits it from the response shape, but the plugin still emits it, which means it leaks if a future handler version forwards `extras` verbatim.

**Mitigation cost.** Either strip the field from production extras (gated by `BROKER_DEV_MODE`) OR make `_dev_landing_url` opt-in via a separate flag. Roll to V0.1-FOLLOWUPS.

### F34 — No upper-bound on `BROKER_EMAIL_RATE_LIMIT_PER_*` values — P3

**File:** `crates/agentkeys-broker-server/src/boot.rs::email_link branch:per_email/per_ip`

**Issue.** An operator who sets `BROKER_EMAIL_RATE_LIMIT_PER_IP_MINUTELY=1000000` effectively disables the rate limit. There's no boot-time sanity bound. Note only — operator-side responsibility.

**Mitigation cost.** Add a sanity ceiling (e.g., 10000/hour for per-email, 100000/min for per-IP). Roll to V0.1-FOLLOWUPS.

### F35 — Email landing page hard-codes `AgentKeys` brand text — P3

**File:** `crates/agentkeys-broker-server/src/handlers/auth/email_landing.rs::LANDING_HTML`

**Issue.** The landing page text says "AgentKeys email link" and "AgentKeys — Verifying". Multi-tenant deployments may want their own brand. The runbook calls out the operator-redirect option (`BROKER_EMAIL_SUCCESS_REDIRECT_URL`) but the LANDING page itself is unbranded-customizable.

**Mitigation cost.** Either templatize the HTML via a config var, OR document the redirect-to-operator-page pattern as the v0 customization mechanism. Roll to V0.1-FOLLOWUPS Phase E runbook update.

### F36 — `EmailLink.verify()` doesn't include `email` in `VerifiedIdentity` — P3

**File:** `crates/agentkeys-broker-server/src/plugins/auth/email_link.rs:340-355`

**Issue.** The plugin's verify() returns `VerifiedIdentity { identity_type: Email, identity_value: omni_account }`. The original email is not exposed. For Phase B's `agentkeys link` flow (operator binds an email to an OmniAccount post-auth), the email IS needed — and would have to be re-fetched from `email_request_status`'s row. Documented as intentional in F24 (round 1) — defense against re-leaking PII. Note only.

**Mitigation cost.** None — pairs with F24. Phase B determines whether the email needs to ride through the plugin or be looked up separately.

## Test-coverage cross-check

Round 2's added attack vectors all reduce to "this case isn't directly tested but is covered by transitively-tested code." The 7 email_flow integration tests + 12 email_link plugin tests + 9 email_tokens + 6 email_rate_limits unit tests cover the security properties (single-use, prefetch defense, rate limits, headers, replay). The findings above identify operational and defense-in-depth gaps rather than security holes.

## Stop rule disposition

Round 1: 0 P0, 0 P1, 4 P2, 5 P3 (9 total).
Round 2: 0 P0, 0 P1, 2 P2, 5 P3 (7 total).

Both rounds find only P2/P3 → plan rule 9 stop rule fires.

**Disposition:** all 16 P2/P3 findings rolled to `V0.1-FOLLOWUPS.md` for Phase D + Phase E to consume.
