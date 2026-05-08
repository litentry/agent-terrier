# Stage 7 — Pluggable Broker (Issue #64), production-ready on testnet

**Repo:** `litentry/agentKeys`
**Issue:** [#64](https://github.com/litentry/agentKeys/issues/64) — Option C, pluggable attestation + audit, no hard Heima dependency
**Branch:** `claude/dazzling-mirzakhani-2a06bc` (worktree off `main`, PR #61 just merged)
**Reference repos:** `dexs-k/dexs-backend` (Go, EIP-191 patterns), `dexs-k/perp-app` (React frontend)
**Author:** drafted 2026-05-05, awaiting 4-reviewer pass before exec

---

## 0. Context — why this plan exists

PR #61 (broker phase 2 — OIDC issuer + AWS-cred wiring) merged to main. The broker today exposes 6 routes: `/healthz`, `/readyz`, `/v1/mint-aws-creds`, `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/v1/mint-oidc-jwt`. Auth is a bearer token validated by an HTTP call to `BROKER_BACKEND_URL/session/validate`. Audit is local SQLite. Wallet provisioning, user-identity verification, and chain anchoring are all implicit / external today.

Issue #64 asks for the **three layers** below the credential mint to become pluggable, behind Rust traits + feature gates, so that:

1. **Auth layer** (who is the user?) is selectable: `WalletSig` (SIWE-wrapped EIP-191), `EmailLink` (passwordless magic-link), `OAuth2/Google` (id_token + PKCE), and v1+ extensions (additional OAuth providers, Passkey, TeePasskey).
2. **Wallet provisioning layer** (what wallet does this user own?) is selectable: `ClientSideKeystore` (BIP-39 in OS keychain, broker only sees address), and v1.5+ extensions (SmartContractAa, HeimaTee, AwsNitro).
3. **Audit layer** (where does the immutable record go?) is selectable: `Sqlite` (default), `EvmTestnet` (Base Sepolia for v0.1 testnet target), and v1+ extensions (Solana, HeimaParachain, S3 Object Lock).

A sibling branch `claude/quizzical-ellis-d6f1e9` carries 6 codex review rounds of prior work on this idea — full plugins/ scaffold, Solidity AgentKeysAudit contract on Base Sepolia, dual-write circuit breaker, OmniAccount derivation, storage schema. It is **prior art**, not the implementation path: the user has chosen to start fresh with stricter process rules, harvesting only what survives review.

**Goal:** ship a v0 broker that is production-ready on testnet — Base Sepolia for chain anchor, real SES email, real wallet-sig auth, real recovery — under explicit process discipline.

**Non-goals:** Heima TEE integration, mainnet anchoring, smart-contract-AA wallets. These are v1.5/v2.

---

## 1. The 11 process rules — pinned

Every section below is governed by these rules. Numbering matches the user's brief:

1. **E2E integration test on day 1.** `harness/stage-7-e2e.sh` exists and passes on the very first slice, before any individual layer is "deepened".
2. **Slice through all layers before deepening any.** Phase 0 (Day 1) ships the thinnest vertical slice that exercises the load-bearing invariant end-to-end. Subsequent phases deepen one layer at a time.
3. **Operator deploy doc is P0.** `docs/operator-runbook-stage7.md` is acceptance-gated by `harness/stage-7-done.sh` — not a Phase F polish task.
4. **No silent fallbacks. Default = refuse-to-boot.** Every plug-in choice, every env var, every credential source is explicit. If something is missing or invalid, the broker exits non-zero with a single-line error pointing at the runbook anchor.
5. **Status endpoints reflect operational state.** `/readyz` returns 503 unless every loaded plugin has reported `ready` for its own dependencies (DB connection, RPC reachable, JWKS keypair on disk, SES sender verified, audit DB writable). No trait default returning `Ok`.
6. **Validate every env-var-derived value at boot.** Type, range, format, reachability where cheap. Already partial on main — extend to all new vars.
7. **The load-bearing invariant gets a regression test on day 1.** See §2.
8. **Trait-based pluggable architecture with feature gates.** Default Cargo build links only the v0 plugins. `--features evm-audit,email-link` opts in to extras. v0 deployments do not link Solana/Heima/WebAuthn crates.
9. **Codex stopping rule.** Two consecutive rounds returning only same-severity P2 findings → ship; remaining P2s become v0.1 follow-ups in a tracked file.
10. **Smoke script per stage / per phase.** `harness/stage-7-phaseN-smoke.sh` for each phase below.
11. **Centralize env var names.** New module `crates/agentkeys-broker-server/src/env.rs` is the **only** place `BROKER_*` strings are defined. All callers reference `env::BROKER_OIDC_ISSUER` constants. Doc, runbook, and tests reference the same constants via a generated table.

---

## 2. The load-bearing invariant + Day-1 regression test

**Invariant (one sentence):**
> *No credential leaves the broker process except via a flow where the caller has proven control of an authenticated identity, that identity is bound to a wallet, that wallet has a valid grant for the requested resource, and an audit record naming all four (identity, wallet, resource, grant) has been durably persisted to **every** configured audit anchor before the credential is returned.*

This is one invariant, not five. Breaking it anywhere — auth bypass, identity-to-wallet mismatch, missing grant, audit write that returned `Ok` without durability, audit write to anchor A but not anchor B — produces an unaudited credential release, which is the worst-class bug this system can have.

**Day-1 regression test** (`crates/agentkeys-broker-server/tests/invariant_load_bearing.rs`):

A single integration test that runs against an in-process broker stood up with the v0 plugin set + a `FailingAuditAnchor` test fixture. It asserts:

- (a) Happy path: full WalletSig → keystore → mint → audit-write → response. SQLite row count goes 0 → 1, response returns AWS creds, and the row's `(identity, wallet, resource, grant_id)` matches the request.
- (b) Auth bypass attempt: tampered EIP-191 signature → 401, **zero** audit rows written, **zero** STS calls made.
- (c) Wrong-wallet attempt: valid sig for wallet A, request claims wallet B → 403, zero audit rows, zero STS.
- (d) Missing-grant attempt: valid identity + wallet, no grant for resource → 403, zero audit rows, zero STS.
- (e) **Audit-failure refuse-to-release** (load-bearing): valid auth+wallet+grant, but `FailingAuditAnchor::anchor()` returns `Err` → broker returns 500 *and the AWS credential is never returned in the response body*. STS may have been called speculatively, but the response must not leak. (Implementation note: speculative STS is acceptable; the gate is the audit write before the response is constructed.)
- (f) Dual-anchor partial-failure: when two anchors are configured (Sqlite + EvmTestnet) and one fails after the other succeeds → policy is `dual_strict`: response 500, no leak, but the SQLite row is logged as `quarantined` so a reconciliation job can either retry the EVM anchor or roll the SQLite row to `failed`. Test verifies (i) no creds returned, (ii) SQLite row marked quarantined, (iii) `/readyz` flips to `degraded` in subsequent calls.

This test is checked in on Day 1 and runs in CI for every commit thereafter. It is the contract.

---

## 3. Architecture — three traits, three feature gates

```rust
// crates/agentkeys-broker-server/src/plugins/auth.rs
#[async_trait]
pub trait UserAuthMethod: Send + Sync {
    fn name(&self) -> &'static str;
    fn ready(&self) -> Readiness;                      // operational state, not Ok-by-default
    async fn challenge(&self, p: ChallengeParams) -> Result<Challenge, AuthError>;
    async fn verify(&self, r: AuthResponse)        -> Result<VerifiedIdentity, AuthError>;
}

// crates/agentkeys-broker-server/src/plugins/wallet.rs
#[async_trait]
pub trait WalletProvisioner: Send + Sync {
    fn name(&self) -> &'static str;
    fn ready(&self) -> Readiness;
    async fn bind_address(&self, id: &VerifiedIdentity, addr: WalletAddress)
        -> Result<WalletBinding, WalletError>;        // v0: client-side keystore: just record
    async fn lookup(&self, id: &VerifiedIdentity)
        -> Result<Option<WalletBinding>, WalletError>;
}

// crates/agentkeys-broker-server/src/plugins/audit.rs
#[async_trait]
pub trait AuditAnchor: Send + Sync {
    fn name(&self) -> &'static str;
    fn ready(&self) -> Readiness;
    async fn anchor(&self, r: &AuditRecord) -> Result<AnchorReceipt, AuditError>;
    async fn verify(&self, r: &AuditRecord, rcpt: &AnchorReceipt)
        -> Result<bool, AuditError>;                  // for reconciliation jobs
}
```

`Readiness` is an enum: `Ready { detail }` | `Degraded { reason }` | `Unready { reason }`. The `/readyz` handler aggregates all loaded plugins' readiness; any `Unready` produces 503; any `Degraded` produces 200 with a JSON body listing degradations. **No trait method may default to `Ready`.**

**Feature gates** (`crates/agentkeys-broker-server/Cargo.toml`):

```toml
[features]
default                = ["auth-wallet-sig", "wallet-keystore", "audit-sqlite"]
auth-wallet-sig        = ["dep:k256", "dep:sha3"]
auth-email-link        = ["dep:lettre", "dep:aws-sdk-sesv2"]
auth-oauth2            = ["dep:reqwest", "dep:jsonwebtoken"]   # JWKS fetch + id_token verify
auth-oauth2-google     = ["auth-oauth2"]                       # Google-specific quirks (response_type=code, openid+email scope)
auth-oauth2-github     = ["auth-oauth2"]                       # v1+: GitHub returns no id_token, calls userinfo
auth-oauth2-apple      = ["auth-oauth2"]                       # v1+: Apple uses form_post response_mode
wallet-keystore        = []                            # no extra deps; uses agentkeys-types
audit-sqlite           = []                            # already in default deps
audit-evm              = ["dep:alloy-provider", "dep:alloy-signer-local", "dep:alloy-rpc-types-eth"]
audit-solana           = ["dep:solana-client", "dep:solana-sdk"]
test-stub              = []                            # existing
```

A v0 testnet deployment compiles with `--features auth-email-link,audit-evm` on top of defaults. Heima/Solana/Passkey are simply not in the dependency graph for v0.

**Wiring at boot:** `BrokerConfig::from_env()` returns a `PluginSelection` struct that the router uses to construct `Box<dyn ...>` per layer. Selection is driven by env vars (centralized in `env.rs`):

- `BROKER_AUTH_METHODS=wallet_sig,email_link,oauth2_google` (comma list)
- `BROKER_WALLET_PROVISIONER=client_keystore`
- `BROKER_AUDIT_ANCHORS=sqlite,evm_testnet` (comma list — multi-anchor write)
- `BROKER_AUDIT_POLICY=dual_strict | sqlite_primary | evm_primary` (sane default `dual_strict`; behavior under partial failure is tested in §2.f)

Boot fails fast if any selected plugin is not compiled in (clear error pointing to the right `--features` flag).

---

## 3.5. Auth flow — grounded in dexs-backend reference, optimized for AgentKeys

Reference: `~/.claude/plans/agentkeys-broker-port-vs-greenfield.md` (dexs-backend's auth surface, what to port, what to drop).

### What we port (crypto primitives only)
- **EIP-191 envelope**: the exact message format `"\x19Ethereum Signed Message:\n<len><msg>"`, Keccak256, k256 ecrecover, recovery-id normalization. Mechanical, well-tested. Port verbatim from dexs-backend's Go `crypto.Keccak256Hash` + `ecrecover` path into `plugins/auth/wallet_sig.rs`.
- **OmniAccount derivation**: `SHA256(client_id || identity_type || identity_value)`. **Our `client_id` is `"agentkeys"`**, distinct from dexs-backend's `"wildmeta"`, so the same email/wallet maps to a different OmniAccount in our broker.
- **45-minute timestamp anti-replay window** on the signed message body (with a single-use nonce table on top — dexs-backend relies on the timestamp alone, we tighten to timestamp + nonce).

### What we explicitly drop (the dexs-backend baggage)
- ~~Email + password + bcrypt + Google-2FA-TOTP~~ → magic-link only, fragment-token wire (§3.5.3); **OAuth2** (Google for v0) covers the "I want to sign in with my Google account" surface without password+TOTP — see §3.5.4.
- ~~`user_id INT AUTOINCREMENT` primary key~~ → `omni_account TEXT` everywhere (matches Heima identity model, future-compatible).
- ~~Two parallel JWT issuers (HS256 + TEE-RSA)~~ → **single ES256 issuer** (broker session keypair). One issuer, one verify path, one revoke path.
- ~~`/v3/account/post_heima_login` style URLs~~ → AgentKeys-native `/v1/auth/{wallet,email}/{start,verify}` + `/v1/grant/{create,revoke,list}`.
- ~~Trading-specific user fields~~ (slippage, gas type, MEV, push registration). Not in our schema.
- ~~`check_hyper_agent_address` semantics~~ → first-class `grants` table with TEE-style signature on the grant content (§3.5.4).

### 3.5.1 Wire format — wallet-sig auth (SIWE-wrapped EIP-191)

**Decision: adopt SIWE (EIP-4361)** instead of raw EIP-191 with ad-hoc payload. Wallet UX win is large (user sees a readable sign-in prompt instead of hex), security win is concrete (domain binding kills cross-app replay). Crypto path is identical: SIWE is a structured message inside an EIP-191 envelope. Implementation cost is ~30 LOC over the bare EIP-191 path. Codex review flagged raw EIP-191 as P0 replayable; SIWE closes that.

```
POST /v1/auth/wallet/start
  request:  { "address": "0x9c3e...f4a2", "chain_id": 84532 }
  response: { "request_id": "req_01HZ…",
              "siwe_message": "broker.agentkeys.dev wants you to sign in with your Ethereum account:\n0x9c3e...f4a2\n\nAuthenticate with AgentKeys broker.\n\nURI: https://broker.agentkeys.dev\nVersion: 1\nChain ID: 84532\nNonce: 8a3f9b2c\nIssued At: 2026-05-05T14:22:11Z\nExpiration Time: 2026-05-05T15:07:11Z\nResources:\n- urn:agentkeys:client:agentkeys" }

POST /v1/auth/wallet/verify
  request:  { "request_id": "req_01HZ…", "signature": "0xabc…<130 hex chars>" }
  response: { "session_jwt":  "eyJ…<ES256-signed>",
              "session_jwt_kid": "ak-session-2026-05",
              "expires_at": "2026-05-05T20:22:11Z",
              "omni_account": "0x7f…",
              "wallet_address": "0x9c3e...f4a2" }
```

Server-side verify: parse the SIWE message body, assert `domain`, `chain_id`, `nonce` (consume from `auth_nonces` table single-use), `issued_at` ≤ now, `expiration_time` > now, ecrecover-derive the address, compare to `0x9c3e...f4a2`. Issue ES256 session JWT bound to `(omni_account, wallet_address, kid_of_session_keypair)`.

### 3.5.2 Wire format — mint with per-call daemon signature

**Optimization (codex review #5 + design review #4):** single session JWT alone is not enough to mint AWS creds. Each mint request carries a **per-call signature** over `(timestamp, body_hash, mint_intent)` made by the daemon's wallet key. The broker verifies the per-call signature against the wallet bound in the JWT before calling STS. Stolen JWT alone is useless without the daemon's private key.

```
POST /v1/mint-aws-creds
  headers:  Authorization: Bearer <session_jwt>
            Idempotency-Key: <ulid>          (optional)
  body:     { "request_id": "mnt_01HZ…",
              "issued_at":  "2026-05-05T14:25:00Z",
              "intent":     { "agent_id": "0xabc…", "service": "s3", "scope_path": "bots/0xabc/" },
              "auth": {
                  "address":   "0x9c3e...f4a2",                         (must match JWT)
                  "signature": "0x…<sig over canonical(body without auth)>"
              } }
  response: { "credentials": { "access_key_id": "ASIA…",
                                "secret_access_key": "…",
                                "session_token": "…",
                                "expiration":   "2026-05-05T15:25:00Z" },
              "audit_record_id": "aud_01HZ…",
              "anchored": ["sqlite", "evm_testnet"] }
```

Canonicalization: serialize `body` minus `auth.signature` via existing `agentkeys-core::auth_request` CBOR (deterministic), hash with Keccak256, EIP-191 envelope, daemon signs. Reuse the dexs-backend port for the signing primitive — it's the same code path as wallet-sig auth.

### 3.5.3 Wire format — email-link (fragment-token + POST + CLI polling)

**Optimizations (codex P0 #3 + design #1):** token in URL **fragment**, not query string. Single-use enforced via DB UNIQUE + conditional update. CLI gets the session JWT via a polling endpoint, not via the browser-facing redirect.

```
1) CLI:    POST /v1/auth/email/request   { "email": "u@x.com" }
   ←       200  { "request_id": "req_01HZ…",
                  "expires_in_seconds": 600,
                  "poll_url": "/v1/auth/email/status/req_01HZ…" }

2) Broker mails:  https://broker.agentkeys.dev/auth/email/landing#t=<32-byte-base64url>
                  (token is in fragment — never sent to server in HTTP request line)

3) User clicks → static HTML loads.
   Page sets `Cache-Control: no-store` + `Referrer-Policy: no-referrer`.
   Inline JS:    POST /v1/auth/email/verify
                 body  { "token": "<from window.location.hash>", "request_id": "req_01HZ…" }
   ←             200  { "ok": true }    (no session JWT in browser response)
   Page renders: "Verified — return to your terminal."

4) CLI (polling every 2s):  GET /v1/auth/email/status/req_01HZ…
   ←  before click:  200 { "status": "pending"  }
   ←  after click:   200 { "status": "verified",
                            "session_jwt":  "eyJ…",
                            "session_jwt_kid": "ak-session-2026-05",
                            "expires_at":    "2026-05-05T20:30:00Z",
                            "omni_account":  "0x7f…" }
```

Why this shape:
- Fragment-token: never appears in server logs, proxy logs, browser referrers. Defeats prefetch consumption (prefetchers don't follow fragments).
- Verify is POST: link prefetchers don't POST. Single-use is enforced at DB level.
- Session JWT lands on the CLI's polling endpoint, not in the browser. CLI is the long-lived process; browser is disposable.
- The browser landing page is broker-hosted, minimal-brand (10 lines of HTML, no JS framework). Operator-redirect is opt-in via `BROKER_EMAIL_SUCCESS_REDIRECT_URL`.

### 3.5.4 Wire format — OAuth2 (Google for v0; provider-pluggable)

Standard OAuth2 + OIDC + PKCE + state-CSRF. The session JWT lands on the CLI's polling endpoint, never in the browser — same shape as email-link (§3.5.3) for UX consistency.

```
1) CLI:    POST /v1/auth/oauth2/start
           body: { "provider": "google" }
   ←       200  { "request_id": "req_01HZ…",
                  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?
                       client_id=<…>&
                       redirect_uri=https%3A%2F%2Fbroker.agentkeys.dev%2Fauth%2Foauth2%2Fcallback&
                       response_type=code&
                       scope=openid%20email&
                       state=<HMAC-signed(request_id || nonce)>&
                       code_challenge=<S256(verifier)>&
                       code_challenge_method=S256&
                       prompt=select_account",
                  "expires_in_seconds": 600,
                  "poll_url": "/v1/auth/oauth2/status/req_01HZ…" }

2) User opens authorization_url in browser, authenticates with Google, consents.

3) Google redirects:
   GET https://broker.agentkeys.dev/auth/oauth2/callback?code=<oauth-code>&state=<state>
   - Broker handler:
       a. Verify state HMAC → extract request_id, ensure request still pending and not consumed.
       b. Look up PKCE verifier for request_id (kept in `oauth_pending` table, single-use).
       c. POST to https://oauth2.googleapis.com/token with
            { code, code_verifier, client_id, client_secret, grant_type=authorization_code, redirect_uri }
            (timeout 5s, refuse-to-fail-open).
       d. Verify Google's returned id_token: JWKS fetch (cached), iss="https://accounts.google.com",
          aud=our client_id, exp > now, iat skew < 60s, nonce binding.
       e. Extract `sub` (Google user ID, stable). Optional `email`.
       f. omni_account = SHA256("agentkeys" || "google" || sub).
       g. Mint session JWT bound to (omni_account, identity_type="google", identity_value=sub).
       h. Store {status:"verified", session_jwt, expires_at} keyed by request_id (5-min TTL).
       i. Return minimal HTML "Verified — return to your terminal."
       Headers: Cache-Control: no-store, Referrer-Policy: no-referrer.

4) CLI (polling every 2s):  GET /v1/auth/oauth2/status/req_01HZ…
   ←  before callback:  200 { "status": "pending"  }
   ←  after callback:   200 { "status": "verified",
                              "session_jwt":  "eyJ…",
                              "session_jwt_kid": "ak-session-2026-05",
                              "expires_at":    "...",
                              "omni_account":  "0x7f…",
                              "identity_type": "google",
                              "identity_value": "<google-sub>" }
   ←  on Google rejection: 200 { "status": "failed", "reason": "user_denied" | "id_token_invalid" | "code_exchange_failed" }
```

Why this shape:
- **PKCE** mandatory even though we have a client_secret — defense in depth against code interception.
- **State HMAC ties to request_id** — prevents CSRF and ties browser callback to the originating CLI session.
- **`prompt=select_account`** — defends against a user already-logged-in to a different Google account in the browser silently authenticating the wrong identity.
- **Email is optional, sub is canonical** — Google `email` can change (workspace migration); `sub` is stable. We use `sub` as the OmniAccount input. Email is stored in `identity_links` if present, useful for recovery and human-readable display.
- **Session JWT to CLI polling, never to browser** — same security posture as email-link (§3.5.3).
- **Provider abstraction** — `BROKER_OAUTH2_PROVIDERS=google` for v0; the trait shape supports `github` and `apple` as additional plug-ins behind their own Cargo features (each has provider-specific quirks: GitHub returns no id_token, Apple uses form_post response_mode).
- **Single-tenant client_id** — broker holds the OAuth client credentials; multi-tenant (each operator brings their own Google project) is a v1.5 question.

Operator setup: register an OAuth2 web app in Google Cloud Console, add `https://<broker-domain>/auth/oauth2/callback` as an authorized redirect URI, set `BROKER_OAUTH2_GOOGLE_CLIENT_ID` and `BROKER_OAUTH2_GOOGLE_CLIENT_SECRET_FILE` env vars. Runbook §oauth2-setup spells this out (Phase A deliverable).

### 3.5.5 Capability grants — first-class data layer

Per port-vs-greenfield §"What we design from scratch": grants are explicit endpoint surface, not implicit storage rows.

```
POST /v1/grant/create
  Authorization: Bearer <session_jwt>           (master)
  body  { "daemon_address": "0xabc…",
          "scope":          { "service": "s3", "scope_path": "bots/0xabc/" },
          "expires_at":     "2026-08-05T00:00:00Z",
          "max_uses":       1000 }
  ← 200 { "grant_id": "grn_01HZ…",
          "audit_proof":   "<ES256 signature over canonical grant content>" }

POST /v1/grant/revoke
  Authorization: Bearer <session_jwt>           (master)
  body  { "grant_id": "grn_01HZ…" }
  ← 200 { "revoked_at": "..." }                 (instant, audit-anchored)

GET /v1/grant/list?owner=<omni_account>
  Authorization: Bearer <session_jwt>           (master)
  ← 200 { "grants": [...] }
```

Mint flow checks the grant before calling STS:
- `grant_id` is implied from `(JWT.omni_account, intent.agent_id, intent.service)` — the broker resolves the active matching grant.
- TTL + `used_count < max_uses` + `revoked_at IS NULL` enforced atomically.
- The `audit_proof` (broker's ES256 signature over the grant content) means even if the SQLite DB is exfiltrated, an attacker who tampers with a grant row can't pass verification.

This makes `agentkeys revoke <agent>` truly instant — one SQL row update — and gives end users an audit-anchored answer to "what does my agent actually have access to?"

### 3.5.6 Single JWT issuer; two purpose-tagged keypairs

We carry **two ES256 keypairs**, never co-mingled:

| Keypair | Purpose | `kid` prefix | Used by | TTL of issued tokens |
|---|---|---|---|---|
| `oidc_keypair` (existing) | OIDC issuer for AWS STS `AssumeRoleWithWebIdentity` | `ak-oidc-…` | external (AWS IAM trust policy) | 60–3600 s, configurable |
| `session_keypair` (new) | broker-internal session JWT for `/v1/mint-*` calls | `ak-session-…` | internal (the broker's own routes) | 5 hours default, configurable |

On-disk JSON format includes a `"purpose": "oidc" | "session"` field. **Load-time validation**: refuse-to-boot if a keypair file has the wrong purpose (codex/eng review #7 footgun — a misconfig where the OIDC key signs session JWTs would let session tokens pass as IAM federation tokens).

### 3.5.7 Backward-compat: shim instead of dual-accept

Codex P0 #14 flagged: today's daemon/CLI calls `/v1/mint-aws-creds` with a **backend-validated bearer** (the current `auth.rs` HTTP-calls `BROKER_BACKEND_URL/session/validate`). The previous draft of this plan proposed accepting both bearer types on `mint-aws-creds`, which Codex correctly called out as a permanent-until-removed surface.

**Better:** the new `POST /v1/auth/wallet/verify` and `POST /v1/auth/email/verify` are the only ways to get a session JWT. **AND** we add a one-time exchange path:

```
POST /v1/auth/exchange
  Authorization: Bearer <legacy backend bearer>
  ← 200 { "session_jwt": "eyJ…", "expires_at": "..." }
```

Daemon/CLI bumps to call `/v1/auth/exchange` once at startup, caches the session JWT, uses it for all subsequent mint calls. ~5 lines of daemon code change. No dual-accept on the mint endpoint. The exchange endpoint itself is removed at v1.0 along with the legacy backend bearer.

---

## 4. Phases

### Phase 0 — Day 1 vertical slice (target: 1–2 days)

**Deliverables (all land in one PR):**

- `src/env.rs` — every `BROKER_*` constant, with type + validation rules, exposed as a `Validated` struct + a `print_table()` for the runbook generator.
- Trait definitions in `src/plugins/{auth,wallet,audit}.rs` + `mod.rs` registering them. **No plug-in implementations beyond the bare minimum to compile.**
- One auth plugin: `WalletSig` — **SIWE-wrapped EIP-191** (§3.5.1), k256 ecrecover, single-use nonce table + 45-min issued_at/expiration_time window, domain binding via SIWE `domain` field.
- One wallet plugin: `ClientSideKeystore` (broker only stores `(omni_account, wallet_address, created_at, role)` rows; address binding inferred from the SIWE message — no separate "bind" sig needed because SIWE already proves control).
- One audit plugin: `SqliteAnchor` (port today's `audit.rs` to the trait shape, no behavior change).
- One **first-class capability grant layer** (§3.5.5): `POST /v1/grant/create`, `POST /v1/grant/revoke`, `GET /v1/grant/list`, with `audit_proof` (broker ES256 sig over canonical grant content) — this is what makes `revoke` truly instant.
- New HTTP endpoints: `POST /v1/auth/wallet/start` + `POST /v1/auth/wallet/verify` (returns session JWT, §3.5.1).
- Backward-compat shim: `POST /v1/auth/exchange` (§3.5.7) — accepts the legacy backend-validated bearer once, returns the new session JWT. Daemon/CLI calls it once at startup. No dual-accept on `/v1/mint-aws-creds`.
- `POST /v1/mint-aws-creds` upgraded: accepts session JWT only, requires per-call daemon signature (§3.5.2) over `(timestamp, body_hash, intent)`. Resolves the active grant for `(omni_account, agent_id, service)`, atomically increments `used_count`, returns creds + audit_record_id.
- Two ES256 keypairs (§3.5.6): existing `oidc_keypair` + new `session_keypair`. Purpose-tagged on disk; load-time validation refuses to boot on mismatch.
- `src/handlers/broker_status.rs` — `/readyz` aggregates plugin readiness (DB writable, JWKS keypair loaded, every plugin's `ready()`).
- `harness/stage-7-phase0-smoke.sh` — boot broker, run a curl-driven challenge → verify → mint flow against a fixture wallet, assert audit row, assert `/readyz==200`.
- `crates/agentkeys-broker-server/tests/invariant_load_bearing.rs` — the §2 test, all six cases.
- `docs/operator-runbook-stage7.md` — **draft** version of the deploy doc, with all env-var names referenced from `env.rs` (no copy-paste).
- `harness/stage-7-done.sh` skeleton — initially asserts only that Phase 0 deliverables exist; phases B–F append their assertions.

**Why this slice:** it exercises auth → wallet → mint → audit on the actual prod path, with both refuse-to-boot config validation and audit-gated release tested. Every later phase deepens, never re-architects.

**Acceptance:** `cargo test -p agentkeys-broker-server --features auth-wallet-sig` passes; `bash harness/stage-7-phase0-smoke.sh` exits 0; the load-bearing invariant test is green.

### Phase A — Auth deepening: EmailLink + OAuth2 (Google) (2–3 weeks)

Add two plug-ins. Both share the **polling-based browser-to-CLI session JWT delivery** pattern (§3.5.3 / §3.5.4): the browser never sees the session JWT, only a "Verified — return to your terminal" page; the CLI gets the JWT via a `GET /v1/auth/<method>/status/{request_id}` poll. This consistency reduces the cognitive load on developers and shares ~70% of the implementation between the two methods.

#### A.1 — EmailLink (`auth-email-link` feature)

Wire format fully specified in §3.5.3 — **not deferred** (Codex P0 #3, Designer #1).

- Endpoints (§3.5.3):
  - `POST /v1/auth/email/request` — mails a fragment-token magic link via existing SES.
  - `POST /v1/auth/email/verify` — consumes the token (POST body, never URL query) and stores the verification result keyed by `request_id`.
  - `GET /v1/auth/email/status/{request_id}` — CLI polling endpoint that returns `{status: pending|verified, session_jwt?}`.
  - `GET /auth/email/landing` — broker-hosted static HTML page (no JS framework, ~30 lines) that reads `window.location.hash`, POSTs to `/verify`, and shows "Verified — return to your terminal." Headers: `Cache-Control: no-store`, `Referrer-Policy: no-referrer`.
- Token format: 32 bytes from CSPRNG, base64url-encoded, stored in `email_tokens` with UNIQUE constraint on the token hash (we store `SHA256(token)`, not the token, so DB exfil doesn't yield usable tokens).
- Single-use enforcement: race-safe `UPDATE email_tokens SET consumed_at=now WHERE token_hash=? AND consumed_at IS NULL` — exactly one writer wins.
- Rate limits (Codex P1 #5): per-email per-hour bucket + per-source-IP per-minute bucket, both configurable via `BROKER_EMAIL_RATE_LIMIT_*` env vars; refuse-to-boot if config nonsensical.
- HMAC key (`BROKER_EMAIL_HMAC_KEY_PATH`): 32-byte file. We HMAC the token row's primary key into the audit log so audit trail entries can be verified post-hoc without reading the raw token.
- Prefetch resistance: tokens are consumed only on POST. Email clients that prefetch GET URLs see the static landing page (which is harmless). Codex P0 #3 → closed.
- `Readiness` checks: SES sender identity verified (cached 5 min, persisted to disk so restart-loops don't burn SES API budget — Codex P2 #8), HMAC key file readable, rate-limit table writable.
- Smoke: `harness/stage-7-phaseA-smoke.sh` (email portion) — full flow against `--features test-stub` SES driver, plus a curl assertion that the verify endpoint refuses GET (returns 405).

#### A.2 — OAuth2 / Google (`auth-oauth2-google` feature)

Wire format in §3.5.4 — standard OAuth2 + OIDC + PKCE + state-CSRF, with session-JWT delivery via the same polling endpoint shape as A.1.

- Endpoints (§3.5.4):
  - `POST /v1/auth/oauth2/start` — returns `authorization_url` + `request_id` + `poll_url`. Broker mints PKCE verifier + HMAC-signed `state` (binds request_id) and persists in `oauth_pending` table.
  - `GET /auth/oauth2/callback` — Google's redirect target. Verifies state HMAC, looks up PKCE verifier, server-side exchanges code for id_token at `https://oauth2.googleapis.com/token` (5s timeout). Verifies id_token via cached JWKS (TTL 1h). Mints session JWT, stores keyed by request_id, renders minimal HTML.
  - `GET /v1/auth/oauth2/status/{request_id}` — CLI polling endpoint, returns `{status: pending | verified | failed, session_jwt?, reason?}`.
- Identity binding: `omni_account = SHA256("agentkeys" || "google" || google_sub)`. Email (if returned by Google) saved in `identity_links` for recovery + display, never as the OmniAccount input. Email migration (Workspace move) does not change the OmniAccount.
- Defenses:
  - PKCE mandatory (defense in depth — code interception → still need verifier).
  - State HMAC ties browser callback to originating CLI session — prevents CSRF.
  - `prompt=select_account` — defends against silent wrong-account auth when user has multiple Google accounts in the browser.
  - JWKS fetch with cached pubkey, refresh on `kid` miss; refuse to verify on JWKS fetch failure (no soft-fail).
  - id_token: verify `iss="https://accounts.google.com"`, `aud=our_client_id`, `exp > now`, `iat` skew ≤ 60s, `nonce` matches request-bound nonce.
  - `oauth_pending` row TTL 10 min; consumed on first callback success.
- Rate limit: per-IP-minute on `/auth/oauth2/start` (configurable `BROKER_OAUTH2_START_RATE_LIMIT_PER_IP_MINUTELY`, default 30/min).
- `Readiness` for OAuth2 plugin checks: client_id + client_secret loaded; JWKS fetch succeeded ≥ once in last hour (cached); `oauth_pending` table writable.
- Operator setup (Phase E runbook §oauth2-setup): create OAuth client in Google Cloud Console, register redirect URI `https://<broker-domain>/auth/oauth2/callback`, set `BROKER_OAUTH2_GOOGLE_CLIENT_ID` + `BROKER_OAUTH2_GOOGLE_CLIENT_SECRET_FILE`. Validate by running `curl https://broker/v1/auth/oauth2/start -d '{"provider":"google"}'` and opening the returned URL.
- Smoke: `harness/stage-7-phaseA-smoke.sh` (oauth portion) — `--features test-stub` mocks Google's token + JWKS endpoints; flow asserts state CSRF rejection (mutated state → 400), PKCE verifier required (missing verifier on stubbed token endpoint → 401), id_token expired → 401, happy path → session JWT.

**Acceptance:** cargo test green with `--features auth-wallet-sig,auth-email-link,auth-oauth2-google`; `bash harness/stage-7-phaseA-smoke.sh` exits 0; manual test against real Google OAuth in a dev project (one-time per operator); manual test confirms an email link prefetched by `curl -L` does NOT consume the token.

### Phase B — Capability grants + wallet recovery (1.5 weeks)

Two deliverables in one phase:

**B.1 Capability grants (Codex P0 #4 mitigation, port-vs-greenfield "first-class data"):**
- Endpoints (§3.5.5): `POST /v1/grant/create`, `POST /v1/grant/revoke`, `GET /v1/grant/list`.
- Storage: `grants(grant_id ULID PK, master_omni_account, daemon_address, scope_json, granted_at, expires_at, max_uses, used_count, revoked_at, audit_proof BLOB)`.
- `audit_proof` = broker session-keypair ES256 signature over canonical CBOR of the grant content. Means a tampered grant row in an exfiltrated DB fails verification — DB exfil ≠ unauthorized mint.
- Mint flow now resolves the active grant atomically (`SELECT … FOR UPDATE`-equivalent via SQLite immediate transaction) and increments `used_count`. Revoke is one row update; instant.

**B.2 Recovery — master-gated, never email-only (Codex P0 #4):**
- New table: `identity_links(omni_account, identity_type, identity_value, linked_at)`.
- New endpoint: `POST /v1/wallet/link` (auth: master session JWT).
- Recovery is **not** "fresh-auth-from-any-linked-identity → re-bind." That model lets a phished email become wallet takeover. Instead, recovery is **a new capability grant** signed by an existing master:
  - The recovering daemon authenticates with whatever identity it has (email or fresh wallet-sig).
  - It cannot mint anything until the master issues a `POST /v1/grant/create` for the new daemon address. The master signs a session JWT challenge from their existing trusted device.
  - Optional time-locked grant: `BROKER_RECOVERY_GRANT_DELAY_SECONDS` enforces a configurable cooldown before a recovery grant becomes active, with a notification (email to all linked identities) — defends against compromised-master scenarios.
- For v0 testnet, time-locked recovery is feature-flagged off by default; operators can enable. Decision-sheet item.
- Smoke: `harness/stage-7-phaseB-smoke.sh` — pair → link email → revoke daemon → spin new daemon → master issues recovery grant → new daemon mints → assert grants for old daemon are independent (revoking old grant doesn't revoke new one, and vice versa).

**Acceptance:** grant + recovery smokes green; cargo test green; audit_proof verification rejects tampered grant rows.

### Phase C — Chain audit anchor (testnet) (2 weeks)

Add `EvmTestnetAnchor` behind `audit-evm` feature. Target: **Base Sepolia** (cheap, fast, public, no Litentry coordination — matches sibling branch's choice).

Components:
- Reuse the sibling branch's `AgentKeysAudit.sol` contract design (foundry, indexed `recordHash`, indexed `omni_account`, indexed `wallet`). Re-deploy fresh from this branch, recorded in `crates/agentkeys-broker-server/solidity/deployments/base-sepolia.json`.
- Rust: `alloy-provider` + `alloy-signer-local` for tx submission. Fee payer is a new env var: `BROKER_EVM_FEE_PAYER_KEYSTORE` (path to encrypted keystore JSON, refuse-to-boot if missing or unreadable).
- **Three-state write protocol** (Eng review #data-flow): SQLite row inserted as `pending` first, then EVM tx submitted, then SQLite promoted to `confirmed` only after receipt. EVM-failure → SQLite to `quarantined`. Crash between SQLite-pending and EVM submit → reconciler picks up `pending` rows on restart. Closes the eng-review-flagged hole where `confirmed` could be set without an EVM anchor.
- Multi-anchor write: when both `sqlite` and `evm_testnet` are configured, `dual_strict` policy gates the response on EVM receipt. Failure → response 500, SQLite row marked `quarantined`. The `pending`/`quarantined`/`confirmed` lifecycle is the canonical state machine.
- Reconciliation job (long-running tokio task with a `CancellationToken`): rescans `pending` rows older than 30s + `quarantined` rows every N seconds and retries the failing anchor. Joins on shutdown — drops the in-flight tx never; either it lands or it's logged as orphaned for operator-side cleanup. Closes Eng review's reconciler-shutdown hole.
- Circuit breaker on EVM anchor: open after K consecutive failures, half-open every M seconds. `/readyz` reports `degraded` when EVM circuit is open and `BROKER_AUDIT_POLICY=dual_strict` (mints serve 500s).
- **Gas-drain mitigations** (Codex P0 #7 + P1 #5): cannot rely solely on circuit breaker — that's the *failure mode*, not mitigation. Add three layers:
  1. **Per-identity sliding-window rate limit** on auth-challenge AND mint endpoints, configurable via `BROKER_RATE_LIMIT_*`. Default: 30 mints/hour per `omni_account`, 60 challenges/hour per IP.
  2. **Per-identity daily EVM-tx budget** — `BROKER_EVM_PER_IDENTITY_DAILY_TX_BUDGET` (default 100). When exceeded, the identity's mints serve 429 until budget resets at 00:00 UTC. Per-identity counter table.
  3. **Fee-payer balance floor** — `BROKER_EVM_FEE_PAYER_MIN_BALANCE`. Below this, EVM anchor flips to `Unready` immediately (not after circuit-breaker opens). Boot-to-Unready (Tier 2 in §6) checks this on startup; runtime check on every tx submit.
- Replay-receipt verification on reconciliation: `verify()` re-fetches the receipt from RPC and confirms the tx hash + block number + log topics still match (handles shallow Base Sepolia reorgs — Eng review #edge-cases).
- Smoke: `harness/stage-7-phaseC-smoke.sh` — boot with both anchors, mint creds, assert SQLite row goes `pending → confirmed` + on-chain event visible. Kill the RPC, mint again, assert 500 + `quarantined` row + `/readyz` degraded. Drain the fee-payer below floor, assert mint serves 503 + `/readyz` Unready (not 500).

**Acceptance:** Phase 0 invariant test now runs in dual-anchor mode and stays green; chain-anchor smoke green; reconciliation job verified by integration test.

### Phase D — Production hardening (1 week)

- Graceful shutdown: SIGTERM → drain in-flight requests up to `BROKER_SHUTDOWN_GRACE_SECONDS` → exit. Existing config has the var; wire it through Axum.
- Observability: structured JSON logs (already on `tracing-subscriber`), `prometheus` exporter at `/metrics` behind `BROKER_METRICS_ENABLED=true`. Counters for: mints, mints_failed, audit_writes, audit_writes_failed, auth_attempts, auth_failed_by_reason. Histograms for: mint latency, audit-write latency.
- Migration discipline: `migrations/0001_v2_schema.sql` (port the sibling branch's schema, audited). Migrations run at boot, refuse-to-boot if migration fails.
- Idempotency on mint: optional `Idempotency-Key` header dedupes within a 5-minute window — if same key + same body → return cached response; if same key + different body → 422.
- Smoke: `harness/stage-7-phaseD-smoke.sh` — kill -TERM during a slow mint, verify clean shutdown, verify metrics are exposed and increment correctly.

**Acceptance:** chaos tests for graceful shutdown + metric increments green; cargo test green.

### Phase E — Operator deploy doc completion (1 week, runs partially in parallel with C+D)

- `docs/operator-runbook-stage7.md` — finalized version. Sections: prerequisites, env-var table (auto-generated from `env.rs`), TLS termination, OIDC issuer DNS, AWS IAM trust policy + role + provider creation, EVM keypair funding on Base Sepolia, SES domain verification, smoke validation, rollback steps, troubleshooting (top 8 errors with cause → fix → docs link, mirroring CEO plan §"Error message spec").
- `docs/operator-runbook-stage7-quickstart.md` — 10-minute setup for a single-operator testnet deploy.
- `harness/stage-7-done.sh` final form: greps each P0 doc section title; greps each `BROKER_*` constant from `env.rs` against the runbook env-var table (catches drift); runs every phase smoke script; runs the load-bearing invariant test.

**Acceptance:** `bash harness/stage-7-done.sh` exits 0 with no skips.

### Phase F — Codex review loop, ship-or-roll (until stop rule fires)

Per rule 9: run codex review in rounds. Each round produces a numbered file under `docs/spec/plans/issue-64/codex-roundN.md`. Stop when two consecutive rounds find only same-severity P2 issues; remaining P2s move to `docs/spec/plans/issue-64/V0.1-FOLLOWUPS.md`.

---

## 5. Centralized env-var module (`src/env.rs`)

Single source of truth. Pattern:

```rust
pub mod env {
    pub const BROKER_BACKEND_URL:                &str = "BROKER_BACKEND_URL";
    pub const BROKER_DATA_ROLE_ARN:              &str = "BROKER_DATA_ROLE_ARN";
    pub const BROKER_OIDC_ISSUER:                &str = "BROKER_OIDC_ISSUER";
    pub const BROKER_OIDC_KEYPAIR_PATH:          &str = "BROKER_OIDC_KEYPAIR_PATH";
    pub const BROKER_OIDC_JWT_TTL_SECONDS:       &str = "BROKER_OIDC_JWT_TTL_SECONDS";
    pub const BROKER_AUDIT_DB_PATH:              &str = "BROKER_AUDIT_DB_PATH";
    pub const BROKER_SESSION_DURATION_SECONDS:   &str = "BROKER_SESSION_DURATION_SECONDS";
    pub const BROKER_AUTH_METHODS:               &str = "BROKER_AUTH_METHODS";
    pub const BROKER_WALLET_PROVISIONER:         &str = "BROKER_WALLET_PROVISIONER";
    pub const BROKER_AUDIT_ANCHORS:              &str = "BROKER_AUDIT_ANCHORS";
    pub const BROKER_AUDIT_POLICY:               &str = "BROKER_AUDIT_POLICY";
    pub const BROKER_EMAIL_HMAC_KEY_PATH:        &str = "BROKER_EMAIL_HMAC_KEY_PATH";
    pub const BROKER_EMAIL_FROM_ADDRESS:         &str = "BROKER_EMAIL_FROM_ADDRESS";
    pub const BROKER_EMAIL_SUCCESS_REDIRECT_URL: &str = "BROKER_EMAIL_SUCCESS_REDIRECT_URL";
    pub const BROKER_EVM_RPC_URL:                &str = "BROKER_EVM_RPC_URL";
    pub const BROKER_EVM_CHAIN_ID:               &str = "BROKER_EVM_CHAIN_ID";
    pub const BROKER_EVM_CONTRACT_ADDRESS:       &str = "BROKER_EVM_CONTRACT_ADDRESS";
    pub const BROKER_EVM_FEE_PAYER_KEYSTORE:     &str = "BROKER_EVM_FEE_PAYER_KEYSTORE";
    pub const BROKER_EVM_FEE_PAYER_PASSWORD_FILE:&str = "BROKER_EVM_FEE_PAYER_PASSWORD_FILE";
    pub const BROKER_METRICS_ENABLED:            &str = "BROKER_METRICS_ENABLED";
    pub const BROKER_SHUTDOWN_GRACE_SECONDS:     &str = "BROKER_SHUTDOWN_GRACE_SECONDS";
    pub const BROKER_BACKEND_TIMEOUT_SECONDS:    &str = "BROKER_BACKEND_TIMEOUT_SECONDS";
    pub const BROKER_AWS_REGION:                 &str = "BROKER_AWS_REGION";
    pub const BROKER_SESSION_KEYPAIR_PATH:       &str = "BROKER_SESSION_KEYPAIR_PATH";   // §3.5.5
    pub const BROKER_SESSION_JWT_TTL_SECONDS:    &str = "BROKER_SESSION_JWT_TTL_SECONDS";
    pub const BROKER_DEV_MODE:                   &str = "BROKER_DEV_MODE";                // relaxes HTTPS-only OIDC issuer
    pub const BROKER_REFUSE_TO_BOOT_STRICT:      &str = "BROKER_REFUSE_TO_BOOT_STRICT";   // §6
    pub const BROKER_DATA_DIR:                   &str = "BROKER_DATA_DIR";                // for ses-verify cache
    pub const BROKER_EMAIL_RATE_LIMIT_PER_EMAIL_HOURLY: &str = "BROKER_EMAIL_RATE_LIMIT_PER_EMAIL_HOURLY";
    pub const BROKER_EMAIL_RATE_LIMIT_PER_IP_MINUTELY:  &str = "BROKER_EMAIL_RATE_LIMIT_PER_IP_MINUTELY";
    pub const BROKER_EVM_FEE_PAYER_MIN_BALANCE:  &str = "BROKER_EVM_FEE_PAYER_MIN_BALANCE";
    pub const BROKER_EVM_PER_IDENTITY_DAILY_TX_BUDGET: &str = "BROKER_EVM_PER_IDENTITY_DAILY_TX_BUDGET";
    pub const BROKER_RATE_LIMIT_MINTS_PER_HOUR_PER_OMNI: &str = "BROKER_RATE_LIMIT_MINTS_PER_HOUR_PER_OMNI";
    pub const BROKER_RATE_LIMIT_CHALLENGES_PER_HOUR_PER_IP: &str = "BROKER_RATE_LIMIT_CHALLENGES_PER_HOUR_PER_IP";
    pub const BROKER_RECOVERY_GRANT_DELAY_SECONDS:    &str = "BROKER_RECOVERY_GRANT_DELAY_SECONDS"; // §Phase B
    pub const BROKER_OAUTH2_PROVIDERS:           &str = "BROKER_OAUTH2_PROVIDERS";        // §3.5.4 — comma list, e.g. "google"
    pub const BROKER_OAUTH2_REDIRECT_URI:        &str = "BROKER_OAUTH2_REDIRECT_URI";     // public callback URL
    pub const BROKER_OAUTH2_GOOGLE_CLIENT_ID:    &str = "BROKER_OAUTH2_GOOGLE_CLIENT_ID";
    pub const BROKER_OAUTH2_GOOGLE_CLIENT_SECRET_FILE: &str = "BROKER_OAUTH2_GOOGLE_CLIENT_SECRET_FILE"; // path, not value
    pub const BROKER_OAUTH2_STATE_HMAC_KEY_PATH: &str = "BROKER_OAUTH2_STATE_HMAC_KEY_PATH"; // 32-byte file
    pub const BROKER_OAUTH2_JWKS_TTL_SECONDS:    &str = "BROKER_OAUTH2_JWKS_TTL_SECONDS";  // default 3600
    pub const BROKER_OAUTH2_START_RATE_LIMIT_PER_IP_MINUTELY: &str = "BROKER_OAUTH2_START_RATE_LIMIT_PER_IP_MINUTELY";
    pub const BROKER_REQUEST_BODY_LIMIT_BYTES:   &str = "BROKER_REQUEST_BODY_LIMIT_BYTES"; // eng-review #malformed
    pub const BROKER_NTP_MAX_SKEW_SECONDS:       &str = "BROKER_NTP_MAX_SKEW_SECONDS";     // eng-review #clock-skew

    // Legacy / compat (kept for one minor version, deprecation logged at boot)
    pub const DAEMON_ACCESS_KEY_ID:              &str = "DAEMON_ACCESS_KEY_ID";            // legacy
    pub const DAEMON_SECRET_ACCESS_KEY:          &str = "DAEMON_SECRET_ACCESS_KEY";        // legacy
    pub const BROKER_DAEMON_ACCESS_KEY_ID:       &str = "BROKER_DAEMON_ACCESS_KEY_ID";     // legacy
    pub const BROKER_DAEMON_SECRET_ACCESS_KEY:   &str = "BROKER_DAEMON_SECRET_ACCESS_KEY"; // legacy
    pub const BROKER_AGENT_ROLE_ARN:             &str = "BROKER_AGENT_ROLE_ARN";           // legacy alias of BROKER_DATA_ROLE_ARN
    pub const ACCOUNT_ID:                        &str = "ACCOUNT_ID";                      // derives BROKER_DATA_ROLE_ARN
    pub const REGION:                            &str = "REGION";                          // legacy alias of BROKER_AWS_REGION

    pub const fn all() -> &'static [(&'static str, &'static str, Group)] { /* (name, doc, group) */ }
}

#[derive(Copy, Clone)]
pub enum Group { Core, Oidc, SessionJwt, Audit, AuditEvm, Auth, AuthEmail, AuthOAuth2, Limits, Legacy }
```

Each constant has an associated `Group` so the runbook auto-generator can render grouped sections (Designer review #docs).

`BrokerConfig::from_env()` reads through these constants, never raw strings. The runbook generator dumps `env::all()` as a markdown table, ensuring the doc never drifts.

---

## 6. Refuse-to-boot rules — tiered

Codex P1 #6 flagged that lumping config validation with external-reachability creates an outage trap (transient DNS / SES throttle / RPC hiccup → broker bricked in restart loop). We split into two tiers:

### Tier 1 — Refuse-to-boot (synchronous, before binding the listener)

These are config-correctness checks. No network. If anything fails the broker exits non-zero:

- All required env vars present and non-empty.
- Type/range/format: ints in declared bounds, paths exist or can be created, URLs parse, OIDC issuer is `https://` in non-dev mode (a `BROKER_DEV_MODE=true` flag relaxes this single rule and is logged loudly at startup).
- File-on-disk readability: both ES256 keypair files present + parseable + purpose-tagged correctly (§3.5.5); HMAC key file present + ≥ 32 bytes; EVM keystore JSON parses and decrypts with the password file.
- Plugin compile-time presence: every name in `BROKER_AUTH_METHODS / BROKER_AUDIT_ANCHORS / BROKER_WALLET_PROVISIONER` is registered in the runtime registry.
- SQLite migration runs cleanly (this is local I/O — counts as Tier 1).
- All-or-nothing keypair setup: if any keypair path is absent, refuse-to-boot with explicit `agentkeys-broker-server keygen --purpose oidc --out PATH` and `--purpose session --out PATH` instructions. **No silent generation.** (Today's `oidc.rs:113` silently generates — fix in Phase 0.)

Failure → exit code 1, single-line stderr: `BOOT_FAIL: <var_or_path>=<value>: <reason>; see runbook §<anchor>`.

### Tier 2 — Boot-to-Unready (async, after listener is bound)

External-reachability checks that mark the broker `Unready` until they pass. Broker still binds the port and serves `/healthz` (200) + `/readyz` (503 with structured detail). This lets the operator observe logs/metrics during transient outages instead of being stuck in a restart loop:

- Backend `/healthz` reachable.
- SES sender identity verified — when email-link enabled. **Persisted cache** under `$BROKER_DATA_DIR/ses-verify.json` survives restart, with a 24h TTL so debugging-restarts don't re-burn the SES API budget.
- EVM RPC `eth_chainId` returns the configured `BROKER_EVM_CHAIN_ID` — when audit-evm enabled.
- EVM fee-payer balance ≥ `BROKER_EVM_FEE_PAYER_MIN_BALANCE` — when audit-evm enabled.

Each Tier 2 check has its own `Readiness` entry in `/readyz` JSON. The operator runbook documents which checks block which features (e.g., "email-link auth requires SES check; mints with `dual_strict` policy require EVM RPC + fee-payer balance").

The `BROKER_REFUSE_TO_BOOT_STRICT=true` env var collapses Tier 2 into Tier 1 (every reachability check becomes a hard boot fail) for environments that prefer fail-loud over fail-degraded. Off by default.

---

## 7. Status endpoint behavior

`/healthz` — process up, returns 200 always (excluding panics).

`/readyz` — aggregates `Readiness` from every loaded plugin + `BrokerConfig::live_check()`:

| Plugin / check | `Ready` when … | `Degraded` when … | `Unready` when … |
|---|---|---|---|
| WalletSig | nonce table writable | — | DB unreachable |
| EmailLink | SES sender verified ≤ 5 min ago, HMAC key loaded | SES status stale (>5 min) | SES API error or HMAC missing |
| OAuth2/Google | client_id + client_secret loaded, JWKS fetch ≤ 1h ago, oauth_pending writable | JWKS stale (>1h, last fetch failed) | JWKS unfetchable or client_secret missing |
| ClientSideKeystore | wallets table writable | — | DB unreachable |
| SqliteAnchor | DB writable | — | DB unreachable |
| EvmTestnetAnchor | RPC reachable, circuit closed, fee-payer keystore unlocked | circuit half-open, RPC slow | circuit open or fee-payer locked |
| OIDC keypair | loaded, kid stable | — | not loaded |
| Backend session/validate | reachable | slow > 1s | unreachable |

Any `Unready` → 503. All `Ready` → 200 with empty body. Any `Degraded` → 200 with JSON body listing degraded items + `degraded: true`.

---

## 8. Code structure (file map)

```
crates/agentkeys-broker-server/
├── Cargo.toml                        # feature gates per §3
├── migrations/
│   └── 0001_v2_schema.sql            # ported & audited from sibling branch
├── solidity/
│   ├── foundry.toml
│   ├── src/AgentKeysAudit.sol        # adopt sibling's contract w/ recordHash indexed
│   ├── test/AgentKeysAudit.t.sol
│   ├── script/Deploy.s.sol
│   └── deployments/base-sepolia.json # this-branch deployment
├── src/
│   ├── env.rs                        # NEW — single source of truth for env-var names
│   ├── config.rs                     # extended; consumes env.rs
│   ├── boot.rs                       # NEW — refuse-to-boot validation chain
│   ├── lib.rs                        # router with new auth + status routes
│   ├── main.rs                       # graceful shutdown + boot.rs wiring
│   ├── error.rs
│   ├── state.rs                      # extended SharedState w/ PluginRegistry
│   ├── env_table.rs                  # NEW — generator for runbook env table
│   ├── auth.rs                       # legacy bearer (backward-compat)
│   ├── jwt/                          # session JWTs (separate from OIDC issuer keypair)
│   │   ├── mod.rs
│   │   ├── issue.rs
│   │   └── verify.rs
│   ├── identity/
│   │   ├── mod.rs
│   │   └── omni_account.rs           # SHA256(client_id || type || value), client_id="agentkeys"
│   ├── plugins/
│   │   ├── mod.rs                    # PluginRegistry, Readiness enum
│   │   ├── auth.rs                   # trait + dispatch
│   │   ├── auth/wallet_sig.rs        # Phase 0
│   │   ├── auth/email_link.rs        # Phase A.1 (cfg = "auth-email-link")
│   │   ├── auth/oauth2/mod.rs        # Phase A.2 (cfg = "auth-oauth2") — provider trait + dispatch
│   │   ├── auth/oauth2/google.rs     # Phase A.2 (cfg = "auth-oauth2-google")
│   │   ├── wallet.rs                 # trait + dispatch
│   │   ├── wallet/keystore.rs        # Phase 0 client-side keystore binding
│   │   ├── audit.rs                  # trait + dispatch + dual-write policy
│   │   ├── audit/sqlite.rs           # Phase 0 (port from current src/audit.rs)
│   │   ├── audit/evm.rs              # Phase C (cfg = "audit-evm")
│   │   ├── audit/breaker.rs          # circuit breaker shared between anchors
│   │   └── audit/dual.rs             # dual-write strategy + reconciliation worker
│   ├── storage/
│   │   ├── mod.rs
│   │   ├── users.rs                  # omni_account rows
│   │   ├── wallets.rs                # bindings
│   │   ├── grants.rs                 # which agents can mint what
│   │   ├── auth_nonces.rs            # WalletSig nonces, single-use
│   │   ├── email_tokens.rs           # EmailLink tokens, single-use
│   │   ├── oauth_pending.rs          # Phase A.2 — OAuth2 PKCE verifier + state correlation, single-use
│   │   ├── identity_links.rs         # for recovery (Phase B)
│   │   └── mint_log.rs               # audit primary
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── health.rs
│   │   ├── broker_status.rs          # NEW — operational /readyz
│   │   ├── mint.rs                   # extended: accept session JWT
│   │   ├── oidc.rs                   # unchanged
│   │   ├── auth/
│   │   │   ├── mod.rs
│   │   │   ├── challenge.rs          # WalletSig + EmailLink dispatch
│   │   │   ├── verify.rs
│   │   │   ├── email_request.rs      # Phase A.1
│   │   │   ├── email_verify.rs       # Phase A.1
│   │   │   ├── email_status.rs       # Phase A.1 (CLI poll)
│   │   │   ├── oauth2_start.rs       # Phase A.2
│   │   │   ├── oauth2_callback.rs    # Phase A.2 (Google redirect target)
│   │   │   └── oauth2_status.rs      # Phase A.2 (CLI poll)
│   │   └── wallet/
│   │       ├── mod.rs
│   │       ├── bind.rs
│   │       ├── link.rs               # Phase B
│   │       ├── recover_start.rs      # Phase B
│   │       └── recover_finish.rs     # Phase B
│   └── reconcile.rs                  # Phase C: long-running quarantine reconciler
└── tests/
    ├── invariant_load_bearing.rs     # Day 1 — the contract
    ├── auth_flow.rs                  # Phase 0 + A.1 + A.2
    ├── wallet_to_mint_flow.rs        # Phase 0 + B
    ├── audit_dual_write.rs           # Phase C
    ├── refuse_to_boot.rs             # Day 1 — every env var validation
    └── readyz_state.rs               # Day 1 + every phase

harness/
├── stage-7-phase0-smoke.sh
├── stage-7-phaseA-smoke.sh
├── stage-7-phaseB-smoke.sh
├── stage-7-phaseC-smoke.sh
├── stage-7-phaseD-smoke.sh
├── stage-7-done.sh                   # composes the above + grep checks
└── prd.json                          # phase-by-phase machine-readable acceptance

docs/
├── operator-runbook-stage7.md
├── operator-runbook-stage7-quickstart.md
└── spec/plans/issue-64/
    ├── PLAN.md                       # canonical link to this plan file
    ├── DECISIONS.md                  # one-liners per resolved ambiguity
    ├── AMBIGUITIES.md                # rolling, source for §13 here
    ├── V0.1-FOLLOWUPS.md             # codex P2s rolled out
    └── codex-roundN.md               # one per round
```

---

## 9. Testing strategy

Per layer:

- **Unit (cargo test, per-module)** — every plugin tests its own internals + a `Mock<TraitName>` so dispatch logic stays exercised when the real plugin is feature-gated out.
- **Integration (cargo test, per-flow)** — auth_flow.rs, wallet_to_mint_flow.rs, audit_dual_write.rs, refuse_to_boot.rs, readyz_state.rs, and the load-bearing invariant test.
- **Smoke (bash harness)** — one per phase, runs against a stood-up broker, hits HTTP, asserts side effects. Uses `--features test-stub` for STS / SES / RPC where unavailable in CI.
- **Chaos** — `tests/chaos_*.rs` for dual-anchor failure modes, RPC drops mid-mint, SIGTERM-during-mint.
- **CI**: GitHub Actions runs cargo build + cargo test per feature flag combination, runs every smoke script, runs cargo clippy with `-D warnings`.
- **Manual on testnet** — Phase E sign-off: deploy to a staging EC2, point a real Mac CLI at it, do the full pair → store → run → revoke loop, verify on-chain audit events show on Base Sepolia explorer.

---

## 10. Verification (how the user knows it's done)

1. `bash harness/stage-7-done.sh` exits 0.
2. `cargo build -p agentkeys-broker-server --no-default-features --features auth-wallet-sig,wallet-keystore,audit-sqlite` builds (proves v0 default).
3. `cargo build -p agentkeys-broker-server --features auth-email-link,auth-oauth2-google,audit-evm` builds (proves testnet target).
4. `cargo test -p agentkeys-broker-server --features test-stub,auth-email-link,auth-oauth2-google,audit-evm` is green.
5. The load-bearing invariant test (`invariant_load_bearing.rs`) all six cases green.
6. On-chain audit events visible at `https://sepolia.basescan.org/address/<contract>` after the manual deploy in Phase E.
7. `docs/operator-runbook-stage7.md` env-var table matches `env.rs` constants exactly (drift check in `stage-7-done.sh`).
8. Codex review log shows two consecutive rounds with only same-severity P2 findings, and `V0.1-FOLLOWUPS.md` lists the rolled P2s.

---

## 11. Critical files to touch (no surprise dependencies)

- `crates/agentkeys-broker-server/Cargo.toml` (feature gates)
- `crates/agentkeys-broker-server/src/{env,boot,lib,config,state,error}.rs` (boot path)
- `crates/agentkeys-broker-server/src/plugins/**` (new)
- `crates/agentkeys-broker-server/src/handlers/{auth,wallet,broker_status}/**` (new — auth subdir includes `oauth2_*.rs` for Phase A.2)
- `crates/agentkeys-broker-server/src/{identity,jwt,storage,reconcile}/**` (new)
- `crates/agentkeys-broker-server/migrations/0001_v2_schema.sql` (new)
- `crates/agentkeys-broker-server/solidity/**` (Phase C)
- `crates/agentkeys-broker-server/tests/**` (new + extended)
- `harness/stage-7-*.sh` (new)
- `docs/operator-runbook-stage7*.md` (new)
- `docs/spec/plans/issue-64/**` (new dir)
- `harness/features.json`, `harness/progress.json` (extend with stage-7 entries)

**Do not touch in this work:** `agentkeys-types`, `agentkeys-core`, `agentkeys-cli`, `agentkeys-daemon`, `agentkeys-mcp`, `agentkeys-provisioner`. Stage 7 is a broker-only PR series. CLI/daemon integration with the new endpoints is a follow-up stage (could be Stage 7 phase G or Stage 8).

---

## 12. Reuse from existing code

- `agentkeys-types::AgentIdentity` — extend with `OAuth2 { provider: String, sub: String }` variant. Derive `OmniAccount` in `identity/omni_account.rs` from `(client_id, identity_type, identity_value)`.
- dexs-backend `googleoauthcallbacklogic.go` — reference for the code-exchange + id_token-verification flow; port the structure (state validation, JWKS verify, sub extraction) but drop the user_id+session-cookie patterns and emit a session JWT instead.
- `agentkeys-core::auth_request` (CBOR canonicalization) — reuse for any payload that needs deterministic hashing in the audit record.
- `agentkeys-core::otp` — reuse HMAC-SHA256 derivation for email tokens (different domain separator).
- `crates/agentkeys-broker-server/src/audit.rs` — port to `plugins/audit/sqlite.rs`, no behavior change in Phase 0.
- `crates/agentkeys-broker-server/src/oidc.rs` — keep; this issuer keypair is independent of the new session JWT keypair.
- Sibling-branch artifacts to harvest verbatim (after a fresh diff review):
  - `solidity/src/AgentKeysAudit.sol` (round-6 form)
  - `solidity/test/AgentKeysAudit.t.sol`
  - `migrations/0001_v2_schema.sql`
  - `src/plugins/audit/breaker.rs` design (circuit breaker)
  - `src/plugins/audit/dual.rs` design (dual-write strategy)
  - `tests/wallet_to_mint_flow.rs` shape

---

## 13. Open ambiguities — superseded

This section was the plan's pre-review decision sheet. After the auth-flow refinement (§3.5) and the four reviewer passes, the consolidated decision sheet now lives in the response message that accompanies this plan ("Decision Sheet" section). All §13 items below either (a) have been resolved by §3.5 and §6's tiering, or (b) are merged into the consolidated sheet. Kept here for traceability, not for action:

- A1 (auth surface): now Phase 0 ships SIWE-wrapped wallet-sig; EmailLink Phase A. Resolved.
- A2 (magic link vs OTP): magic link with fragment-token wire (§3.5.3). Resolved.
- A3 (landing page): broker-hosted minimal default; operator-redirect opt-in via `BROKER_EMAIL_SUCCESS_REDIRECT_URL`. Resolved.
- B1 (wallet provisioner): `ClientSideKeystore` only for v0. Carried forward.
- B2 (recovery): now governed by capability-grant model (§3.5.4); recovery requires master-signed grant on the new daemon address. **Open** — decision sheet item.
- C1 (testnet target): Base Sepolia. Carried forward.
- C2 (audit policy): `dual_strict` default. **Open** — decision sheet item (does the user want to ship `dual_strict` or `sqlite_primary` while EVM anchor stabilizes?).
- C3 (fee-payer key): keystore + password file. Carried forward.
- D1 (codex stop rule): now requires independent prompt + user sign-off on residual P2s (Codex review #10). **Open** — decision sheet item.
- D2 (phase ordering): now Phase 0 → A → C.0 (graceful shutdown + migrations, lifted from D) → B → C → D-rest → E. **Open** — decision sheet item.
- D3 (production-ready definition): reframed in decision sheet.
- D4 (plan home): `docs/spec/plans/issue-64/`. Carried forward.
- E1 (refuse-to-boot vs boot-to-Unready): tiered (§6). Resolved.
- E2 (speculative STS): merged into decision sheet.
- E3 (EVM circuit-breaker readiness state): `Unready` when fee-payer below floor, `Degraded` when circuit half-open. Resolved.

---

## 14. Why this plan (rather than the sibling branch)

The sibling branch shipped substantial work but does not visibly satisfy several of the user's explicit rules:

- The sibling branch's broker-status / readyz handling on first inspection looks present but is not gated by every plugin's `Readiness` (§5).
- No visible centralized `env.rs` — env-var strings appear inline at multiple call sites.
- No visible Day-1 load-bearing invariant test — the test files exist for individual flows but not for the single composed invariant.
- Codex round 6 found a P2 in audit indexing (legit, valuable) but rounds 1–6 were not gated by the §9 stop rule, so the work spread without a hard stopping criterion.

This plan inherits the **artifacts** that survive review (Solidity contract, dual-write breaker, schema) and re-imposes the rule discipline at the structure level. Net delta is small in code, large in process clarity.

---

## 15. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Base Sepolia RPC instability mid-mint | Circuit breaker + dual-write quarantine + reconciler |
| SES sender verification timing out at boot | Refuse-to-boot only on hard failure; transient → degraded mode |
| Plug-in registry drift between cargo features and runtime config | Boot-time validation: every name in `BROKER_AUTH_METHODS` must resolve; clear error otherwise |
| EIP-191 nonce replay across broker restart | Nonces stored in SQLite, not in memory; UNIQUE constraint enforced |
| Email-link token in URL leaking via referrer headers | Resolved (§3.5.3): fragment-token + POST verify + `Referrer-Policy: no-referrer` |
| OAuth2 client_secret on disk (Phase A.2) | Stored at `BROKER_OAUTH2_GOOGLE_CLIENT_SECRET_FILE` with mode 0600 enforced by boot check; refuse-to-boot if file is world-readable. Operator runbook §oauth2-setup includes `chmod 600` step. |
| OAuth2 redirect URI hijack | Operator pre-registers redirect URI in Google Cloud Console; Google enforces exact match. Broker also asserts callback host matches `BROKER_OAUTH2_REDIRECT_URI` at request time, refusing forwarded callbacks. |
| OAuth2 JWKS cache poisoning | JWKS fetch over TLS only, pin to Google's documented endpoint; refresh on `kid` miss; refuse to verify if all JWKS fetches in last hour failed (no soft-fail). |
| OAuth2 silent-account hijack (browser logged into wrong account) | `prompt=select_account` forces account picker every time. Cost: one extra click; defends against the multi-account-in-browser scenario. |
| Dual-write race: SQLite committed but EVM tx accepted/dropped | Receipt polling with bounded retries; quarantine if uncertain; reconciler resolves |
| Stage 7 work landing while Stage 5b drift monitor still in flight | Stage 7 PR series is broker-only — touches no provisioner code paths; confirmed in §11 |
| Sibling-branch contributors duplicate work | Once this plan ships and is approved, sibling branch is closed with a `superseded by` note pointing at this plan and the new PR series |

---

*End of plan. Awaits 4-reviewer pass + user decision on §13.*
