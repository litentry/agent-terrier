### Vector 1 — CallbackError ownership tagging
**Severity**: P1 CLOSED
**File:line**: `crates/agentkeys-broker-server/src/plugins/auth/oauth2/mod.rs:464`
**Finding**: P1 CLOSED — `handle_callback` now distinguishes pre-consume errors from post-consume owned-row errors. Early-return table: line 464-466 `verify_state(...).map_err(CallbackError::pre_consume)` is before consume, `owned_request_id=None`; line 467-470 `pending_store.consume(...).map_err(CallbackError::pre_consume)` is before an `Available` ownership return, `owned_request_id=None`; line 477-481 `OAuth2PendingConsume::Expired` is not consumed, `owned_request_id=None`; line 482-487 `OAuth2PendingConsume::NotFoundOrConsumed` is not owned by this invocation, `owned_request_id=None`; line 492-500 provider mismatch is after `Available`, `owned_request_id=Some(request_id)`; line 502-506 nonce mismatch is after `Available`, `owned_request_id=Some(request_id)`; line 513-516 token-exchange error is after `Available`, `owned_request_id=Some(request_id)`; line 523-526 id-token verify error is after `Available`, `owned_request_id=Some(request_id)`. The HTTP handler only calls `mark_failed` when `owned_request_id` is `Some` at `crates/agentkeys-broker-server/src/handlers/auth/oauth2_callback.rs:103`.
**Fix**: None required

### Vector 2 — Readyz rate-limit probe non-destructiveness
**Severity**: P2 CLOSED
**File:line**: `crates/agentkeys-broker-server/src/storage/email_rate_limits.rs:135`
**Finding**: P2 CLOSED — `EmailRateLimitStore::writable()` does not insert or update `email_rate_limits`; it only executes `CREATE TABLE IF NOT EXISTS _readyz_probe (id INTEGER PRIMARY KEY)` at line 140. That sentinel table is separate from rate-limit accounting, and because the method creates only the table and no rows, repeated `/readyz` probes do not grow data unboundedly.
**Fix**: None required

### Vector 3 — JWK use-field filtering fail-closed behavior
**Severity**: P2
**File:line**: `crates/agentkeys-broker-server/src/plugins/auth/oauth2/google.rs:204`
**Finding**: `jwk_matches()` does reject explicit `kty = "EC"` because line 204 only accepts empty or `"RSA"`, and it rejects explicit `use = "enc"` because line 205 only accepts empty or `"sig"`. The problem is the `kty` side is not actually fail-closed: line 204 accepts `jwk.kty.is_empty()`, so a JWKS key with a matching `kid`, RSA components, and omitted/empty `kty` can be selected even though the expected policy for this round is `kty == "RSA"` only. `use` empty is acceptable per the vector; `kty` empty is the unexpected key-type gap.
**Fix**: Change `let kty_ok = jwk.kty.is_empty() || jwk.kty == "RSA";` to `let kty_ok = jwk.kty == "RSA";`, and add tests for `kty="RSA"` accepted, `kty="EC"` rejected, and missing/empty `kty` rejected.

### Vector 4 — request_id re-issue after provider mismatch
**Severity**: No finding
**File:line**: `crates/agentkeys-broker-server/src/plugins/auth/oauth2/mod.rs:492`
**Finding**: No finding — the provider-mismatch branch fires after `pending_store.consume()` has returned `OAuth2PendingConsume::Available`, so `CallbackError::post_consume(..., request_id)` is used at lines 492-500 and the handler marks that owned request failed at `crates/agentkeys-broker-server/src/handlers/auth/oauth2_callback.rs:103`. The failing request_id is not returned to the browser or caller on this error path; the handler returns the mapped auth error at line 106. Re-issue is also blocked by storage: `oauth2_pending.request_id` is a primary key at `crates/agentkeys-broker-server/src/storage/oauth_pending.rs:104`, and `issue()` uses a plain parameterized `INSERT` at lines 139-151, so a duplicate request_id errors instead of replacing or resurrecting a consumed row.
**Fix**: None required

### Vector 5 — Phase B grants preview
**Severity**: P1
**File:line**: `crates/agentkeys-broker-server/src/storage/grants.rs:256`
**Finding**: Phase B file exists, and `try_consume` fails the requested atomicity bar. It performs a Rust-level `SELECT`/peek at lines 256-278, branches in Rust on revoked/expired/exhausted state at lines 279-290, and only then runs the conditional `UPDATE ... used_count = used_count + 1 ... used_count < max_uses` at lines 293-303. That update is conditionally safe against overuse, but the vector explicitly requires no Rust-level read before the update, so this is P1. The post-peek race is partially acknowledged by the `n == 0` lost-race handling at lines 304-306, but the selected grant_id and audit_proof are still chosen before the write. There is no `revoke_by_master` function in this file; the existing `revoke` path is parameterized at lines 165-168. The active grant lookup does specify newest-first ordering with `ORDER BY granted_at DESC LIMIT 1` at lines 263-264.
**Fix**: Make grant resolution and consumption a single SQL operation, for example an `UPDATE ... WHERE grant_id = (SELECT grant_id ... ORDER BY granted_at DESC LIMIT 1) AND used_count < max_uses ... RETURNING grant_id, audit_proof`, or equivalent transactionally atomic statement for the supported SQLite version. Keep the failure classification in a separate diagnostic path only after the atomic consume fails.

## Summary table
| # | Short name | Severity | Ships? |
|---|-----------|----------|--------|
| 1 | CallbackError ownership tagging | P1 CLOSED | Yes |
| 2 | Readyz rate-limit probe non-destructiveness | P2 CLOSED | Yes |
| 3 | JWK use-field filtering fail-closed behavior | P2 | No |
| 4 | request_id re-issue after provider mismatch | No finding | Yes |
| 5 | Phase B grants preview | P1 | No |

## ROUND-2 VERDICT
FAIL — open P0/P1 items: Vector 5 P1, `GrantStore::try_consume` performs a Rust-level peek before the conditional consume update.
