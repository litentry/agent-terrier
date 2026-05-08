### Vector 1 — State HMAC bypass / forgery
**Severity**: No finding
**File:line**: N/A — no issue
**Finding**: No finding — `verify_state` recomputes the HMAC over the payload half before parsing JSON, rejects signature mismatch, and checks the payload `ver` against the current schema version. The length mismatch path in `constant_time_eq` returns false before the byte loop, but the HMAC length is public and this does not create a forgery path.
**Fix**: None required

### Vector 2 — PKCE verifier timing
**Severity**: No finding
**File:line**: N/A — no issue
**Finding**: No finding — the PKCE verifier is generated at start, stored in `oauth2_pending`, consumed once, and sent only to the provider token endpoint. I found no production logging of `pkce_verifier` or `code_verifier`; the column remains after `consumed_at` is set, but after token exchange it is no longer sufficient to redeem the authorization code.
**Fix**: None required

### Vector 3 — id_token nonce verification
**Severity**: No finding
**File:line**: N/A — no issue
**Finding**: No finding — Google nonce verification maps a missing nonce claim to `""` and compares it to the pending-row nonce, which is generated as a non-empty 16-byte random base64url string. If Google omits nonce, verification returns `NonceMismatch`; a legitimate old JWT without nonce does not pass.
**Fix**: None required

### Vector 4 — JWKS cache race
**Severity**: P2
**File:line**: `crates/agentkeys-broker-server/src/plugins/auth/oauth2/google.rs:183`
**Finding**: `lookup_jwk` does a read-lock cache lookup, drops the read path, and every miss/stale cache calls `refresh_jwks().await` independently. Two or more concurrent callbacks for the same unknown `kid` can all fetch Google's JWKS endpoint, creating a thundering-herd risk during key rotation or cache expiry.
**Fix**: Add refresh deduplication around JWKS refresh, for example a `tokio::sync::Mutex`/singleflight guard that re-checks the cache after acquiring the refresh lock and lets only one task perform the network fetch for a miss.

### Vector 5 — Callback error path and tampered state
**Severity**: No finding
**File:line**: N/A — no issue
**Finding**: No finding — when `handle_callback` fails and the handler cannot recover a request ID from the state, it only attempts `mark_failed` after `plugin.verify_state` succeeds. A tampered state that fails HMAC verification does not leak `rid` into the failure path; the pending row remains pending until timeout, which matches the observed code path.
**Fix**: None required

### Vector 6 — Callback ordering / consume / mark_failed race
**Severity**: P1
**File:line**: `crates/agentkeys-broker-server/src/handlers/auth/oauth2_callback.rs:99`
**Finding**: The handler blindly re-verifies any valid state on `handle_callback` error and calls `mark_failed` for that `rid`. Because `handle_callback` consumes the row before token exchange and id-token verification, a concurrent replay of the same callback can hit `NotFoundOrConsumed`, then the error path can mark the original consumed-but-still-pending row as `failed` while the first callback is still in flight. The first callback later calls `mark_verified`, but `mark_verified` only updates `status = 'pending'`; if the replay already marked it failed, the legitimate flow fails and the CLI sees `failed`.
**Fix**: Do not mark failed on `NotFoundOrConsumed` replay errors, or return structured callback errors that identify whether the row was actually consumed by this invocation before marking failure. A stronger storage fix is to transition to an explicit `processing` state during consume and allow only the owner of that transition to mark `verified` or `failed`.

### Vector 7 — provider_method_name leak
**Severity**: No finding
**File:line**: N/A — no issue
**Finding**: No finding — `Box::leak` is executed in `OAuth2Auth::new` when constructing the plugin, and `name()` returns the cached `&'static str`. The code does not allocate on every `name()` call.
**Fix**: None required

### Vector 8 — start_rate_limit per-IP trust boundary
**Severity**: No finding
**File:line**: N/A — no issue
**Finding**: No finding — `/v1/auth/oauth2/start` takes `source_ip` from the request body, but the handler documents it as an optional client-supplied IP and explicitly notes that Phase D will add X-Forwarded-For-aware extraction. This is an acceptable documented v0 limitation.
**Fix**: None required

### Vector 9 — Cargo feature graph
**Severity**: No finding
**File:line**: N/A — no issue
**Finding**: No finding — `auth-oauth2-google` implies `auth-oauth2` in Cargo features, and the OAuth2 modules/routes/storage exports are behind `#[cfg(feature = "auth-oauth2")]` or `#[cfg(feature = "auth-oauth2-google")]`. Without OAuth2 features, the Google module and OAuth2 route handlers are not compiled.
**Fix**: None required

### Vector 10 — /readyz aggregation for OAuth2 stores
**Severity**: P2
**File:line**: `crates/agentkeys-broker-server/src/plugins/auth/oauth2/mod.rs:473`
**Finding**: `OAuth2Auth::ready()` checks provider readiness and `pending_store.writable()`, but it never checks the OAuth2 rate-limit store. A corrupt or unwritable `oauth2_rate_limits.sqlite` can make `/v1/auth/oauth2/start` fail in `check_and_increment` while `/readyz` still reports the OAuth2 plugin as ready or only provider-degraded.
**Fix**: Add a lightweight writability probe to `EmailRateLimitStore` and call it from `OAuth2Auth::ready()` alongside `pending_store.writable()`, returning `Readiness::unready("oauth2 rate-limit table not writable")` on failure.

### Vector 11 — Token endpoint timeout error mapping
**Severity**: No finding
**File:line**: N/A — no issue
**Finding**: No finding — `GoogleOAuth2Provider` builds a `reqwest` client with a 5-second timeout; token exchange send errors map to `OAuth2Error::Network`, then to `AuthError::Upstream`, then through `map_auth_err` to `BrokerError::BackendUnreachable`, which renders as HTTP 502 Bad Gateway.
**Fix**: None required

### Vector 12 — Re-entrant verify_state
**Severity**: P3
**File:line**: `crates/agentkeys-broker-server/src/handlers/auth/oauth2_callback.rs:99`
**Finding**: The callback handler can verify the same state twice on the error path: once inside `plugin.handle_callback(...)`, then again in the `Err(e)` arm to recover `rid` for `mark_failed`. The extra HMAC + JSON parse is acceptable for v0 performance, but the duplicate verification is real.
**Fix**: Refactor `handle_callback` to return a structured error carrying the verified `request_id` when available, so the handler does not need to parse and verify state a second time.

### Vector 13 — JWT decode security / JWK use=sig
**Severity**: P3
**File:line**: `crates/agentkeys-broker-server/src/plugins/auth/oauth2/google.rs:277`
**Finding**: The Google JWK model parses the `use` field into `usage`, but `lookup_jwk` selects keys only by `kid`, and `verify_id_token` uses the returned RSA components without checking `usage == "sig"` or `kty == "RSA"`. A JWKS key marked for encryption would be accepted for signature verification if it had the matching `kid` and RSA components.
**Fix**: Filter candidate keys before use: require `kty == "RSA"` and `usage` empty or `"sig"` for Google's JWKS, then reject anything else as `InvalidIdToken`.

### Vector 14 — jsonwebtoken InvalidIssuer mapping
**Severity**: P3
**File:line**: `crates/agentkeys-broker-server/src/plugins/auth/oauth2/google.rs:292`
**Finding**: `ExpiredSignature` and `InvalidAudience` receive explicit mappings, but `InvalidIssuer` falls through to the catch-all `OAuth2Error::InvalidIdToken(e.to_string())`. This is not an auth bypass, but it loses the specific issuer failure classification.
**Fix**: Add an explicit `ErrorKind::InvalidIssuer => OAuth2Error::InvalidIdToken("wrong issuer".into())` branch, or add a dedicated `WrongIssuer` variant if callers need issuer-specific UX.

### Vector 15 — Identity-binding semantics
**Severity**: No finding
**File:line**: N/A — no issue
**Finding**: No finding — the callback derives the OmniAccount from `outcome.sub`, stores `outcome.sub` as `identity_value`, and passes `outcome.sub` into the session JWT. The optional email returned from Google is carried in the intermediate outcome but is not used for OmniAccount derivation or persisted as the verified identity value in this flow.
**Fix**: None required

| # | Short name | Severity | Must-fix before ship? |
|---|-----------|----------|-----------------------|
| 1 | State HMAC bypass / forgery | No finding | No |
| 2 | PKCE verifier timing | No finding | No |
| 3 | id_token nonce verification | No finding | No |
| 4 | JWKS cache race | P2 | No |
| 5 | Callback tampered-state error path | No finding | No |
| 6 | Callback consume/mark_failed race | P1 | Yes |
| 7 | provider_method_name leak | No finding | No |
| 8 | start_rate_limit per-IP trust boundary | No finding | No |
| 9 | Cargo feature graph | No finding | No |
| 10 | /readyz OAuth2 store aggregation | P2 | No |
| 11 | Token endpoint timeout mapping | No finding | No |
| 12 | Re-entrant verify_state | P3 | No |
| 13 | JWK use=sig validation | P3 | No |
| 14 | InvalidIssuer mapping | P3 | No |
| 15 | Identity-binding semantics | No finding | No |

ROUND-1 VERDICT: FAIL (P0/P1 found: Vector 6 P1 callback consume/mark_failed race).
