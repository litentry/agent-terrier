### Vector 1 — Round-2 closures
**Severity**: P1 CLOSED / P2 CLOSED
**File:line**: `crates/agentkeys-broker-server/src/plugins/auth/oauth2/google.rs:202`; `crates/agentkeys-broker-server/src/storage/grants.rs:264`
**Finding**: P2 CLOSED for `jwk_matches`: the function now checks `jwk.kid` first at `google.rs:203`, then requires `let kty_ok = jwk.kty == "RSA";` at `google.rs:206`, so missing/empty `kty` no longer slips through; `use` still accepts empty or `"sig"` at `google.rs:207`. P1 CLOSED for `try_consume`: the success path is one `UPDATE ... RETURNING` statement at `grants.rs:264`, with no Rust-side `SELECT` before the update; the diagnostic `SELECT expires_at, revoked_at, max_uses, used_count` only runs after `consumed` is `None` at `grants.rs:292`. Exact SQL string:
```sql
UPDATE grants
                 SET used_count = used_count + 1
                 WHERE grant_id = (
                    SELECT grant_id FROM grants
                    WHERE master_omni_account = ?1
                      AND daemon_address = ?2
                      AND service = ?3
                      AND revoked_at IS NULL
                      AND expires_at > ?4
                      AND used_count < max_uses
                    ORDER BY granted_at DESC
                    LIMIT 1
                 )
                 RETURNING grant_id, audit_proof
```
**Fix**: None required.

### Vector 2 — Audit proof verification
**Severity**: P3
**File:line**: `crates/agentkeys-broker-server/src/jwt/issue.rs:76`; `crates/agentkeys-broker-server/src/lib.rs:29`; `crates/agentkeys-broker-server/src/handlers/oidc.rs:49`
**Finding**: `mint_grant_audit_proof` signs a compact ES256 JWT with the broker's `SessionKeypair` passed as `keypair` at `jwt/issue.rs:77` and signed via `keypair.sign_jwt(&claims)` at `jwt/issue.rs:110`. The signed claims are `iss`, `sub = agentkeys:grant:<grant_id>`, `aud = agentkeys:audit-proof`, `iat = granted_at`, `exp = expires_at`, plus `agentkeys.kind`, `grant_id`, `master_omni_account`, `daemon_address`, `service`, `scope_path`, `granted_at`, `expires_at`, and `max_uses` at `jwt/issue.rs:88`. The broker routes only `/.well-known/openid-configuration` and `/.well-known/jwks.json` at `lib.rs:26` and `lib.rs:29`, and that JWKS handler returns `state.oidc.jwks_json()` at `handlers/oidc.rs:49`, not the session key. External auditors therefore have no documented endpoint for the session public key needed to verify grant `audit_proof`; rolls to Phase E US-039. The proof expiry is intentionally coupled to the grant expiry: `exp` is set to `expires_at` at `jwt/issue.rs:97`, with an inline comment at `jwt/issue.rs:93` saying the JWT becomes invalid exactly when the grant does.
**Fix**: Publish a session-key JWKS or documented verifier bundle for `agentkeys:audit-proof`, clearly separate it from the AWS OIDC JWKS, and include the expiry semantics in the Phase E operator/verifier runbook.

### Vector 3 — Revoke enumeration
**Severity**: No finding
**File:line**: `crates/agentkeys-broker-server/src/handlers/grant/revoke.rs:49`
**Finding**: The revoke handler collapses not-found, wrong-master, and already-revoked into one branch. When `revoke()` returns false at `revoke.rs:49`, the comment at `revoke.rs:50` explicitly says the failed row could be missing, owned by another master, or already revoked, and the returned message is exactly `"grant_id {:?} not found, not owned by this master, or already revoked"` at `revoke.rs:54`. The handler does not leak distinct messages for those conditions.
**Fix**: None required.

### Vector 4 — Mint grant error status
**Severity**: P2
**File:line**: `crates/agentkeys-broker-server/src/handlers/mint.rs:192`
**Finding**: Revoked, expired, and exhausted grants map to `BrokerError::Unauthorized` at `mint.rs:193`, `mint.rs:198`, and `mint.rs:203`, so they return HTTP 401 because `BrokerError::Unauthorized` maps to `StatusCode::UNAUTHORIZED` in `error.rs:32`. That contradicts the Phase B contract in `GrantStore::try_consume`'s own comment, which says `NoGrant / Revoked / Expired / Exhausted` all map to 403 at `grants.rs:243`, and breaks the plan §3.5.5 client error-handling contract. This is not a credential-release bug, but clients expecting 403 for unusable grants will misclassify these failures as session-auth failures.
**Fix**: Add a `BrokerError::Forbidden` variant mapped to HTTP 403, or otherwise return a 403 response for `GrantConsumeOutcome::{Revoked, Expired, Exhausted}` while preserving 401 for invalid/missing session JWT and per-call signature failures.

### Vector 5 — Legacy implicit-grant fallback
**Severity**: P3
**File:line**: `crates/agentkeys-broker-server/src/handlers/mint.rs:182`
**Finding**: `NoGrant` still proceeds with the mint: the branch at `mint.rs:182` logs `"Phase 0 implicit-grant path"` and returns `String::new()` at `mint.rs:190`, and the audit record stores that empty grant ID at `mint.rs:272`. This is documented inline as a Phase 0 migration window with a Phase E US-039 fail-closed flip point at `mint.rs:164`, so it is not the P2 silent-permanent-fallback case. I found no operator-runbook mention of the implicit-grant migration window or the flip point, so this remains a P3 documentation gap.
**Fix**: Add the implicit-grant fallback, empty `grant_id` audit meaning, and Phase E US-039 fail-closed cutover procedure to `docs/operator-runbook-stage7.md`.

### Vector 6 — Concurrent create and consume
**Severity**: No finding
**File:line**: `crates/agentkeys-broker-server/src/storage/grants.rs:56`
**Finding**: The grant store is not a SQLite pool with multiple write connections. It owns a single `rusqlite::Connection` behind `Mutex<Connection>` at `grants.rs:56`, both `open()` and `open_in_memory()` initialize that single connection at `grants.rs:66` and `grants.rs:76`, and every operation enters through `lock()` at `grants.rs:85`. The schema setup enables WAL at `grants.rs:94`, but visibility between `create()` and `try_consume()` is governed by the single serialized connection, not by cross-connection read timing. A freshly committed `create()` row is visible to a later `try_consume()` once the mutex is released.
**Fix**: None required.

## Summary table
| # | Short name | Severity | Ships? |
|---|-----------|----------|--------|
| 1 | Round-2 closures | P1/P2 CLOSED | Yes |
| 2 | Audit proof verification | P3 | Yes |
| 3 | Revoke enumeration | No finding | Yes |
| 4 | Mint grant error status | P2 | Yes |
| 5 | Legacy implicit-grant fallback | P3 | Yes |
| 6 | Concurrent create and consume | No finding | Yes |

## ROUND-3 VERDICT
PASS — Phase A.2 + Phase B grants ship (no P0/P1, no new P2 worse than round-1 residual)

Carry forward new findings to V0.1-FOLLOWUPS: Vector 4 P2 grant-error failures return 401 instead of the planned 403; Vector 2 P3 audit-proof verification lacks a documented session-public-key path; Vector 5 P3 implicit-grant fallback is not in the operator runbook.
