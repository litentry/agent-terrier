> **Terminology (2026-04-14 decision, tracked in [#10](https://github.com/litentry/agentKeys/issues/10)):** AgentKeys canonical term is **"bearer token"**. "Session token" is accepted as a synonym in older docs. The underlying format is a JWT (verified against the Heima source `tee-worker/omni-executor/core/src/auth/auth_token.rs`), but we deliberately avoid the term "JWT" in user-facing docs because it carries "short-lived, disposable" connotations that misrepresent the 30-day TTL. Heima-side code and terminology are out of scope for this rename — only AgentKeys-side docs/code use "bearer token."

This page defines what the AgentKeys **bearer token** is, based on verification against the Heima source code.

Companion docs:

- `[wiki/blockchain-tee-architecture.md](./blockchain-tee-architecture.md)` — how blockchain + TEE split responsibilities
- `[wiki/key-security.md](./key-security.md)` — storage recommendations, hardening plan
- `[wiki/serve-and-audit.md](./serve-and-audit.md)` — audit submission patterns

---

## 1. What it is

A bearer token (a.k.a. session token) is a **long-lived signed bearer credential** issued by the Heima TEE to a client (master CLI or agent daemon) upon successful authentication. **AgentKeys policy: 30-day TTL** (set via `AuthOptions.expires_at`; Heima SDK default is ~24h).

### Underlying format (from Heima source)

The token is technically a JWT (JSON Web Token) signed by the TEE's RSA private key:

```rust
// tee-worker/omni-executor/core/src/auth/auth_token.rs
pub struct AuthTokenClaims {
    pub sub: String,    // omni account address (hex-encoded)
    pub typ: String,    // token type: "ID" or "ACCESS"
    pub exp: i64,       // expiration timestamp
    pub aud: String,    // audience / client ID
}
```

The token looks like: `eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIweD...`

### Why we don't call it "JWT" in AgentKeys

The term "JWT" carries connotations of short-lived, disposable, low-value tokens (like API gateway session cookies). AgentKeys bearer tokens are **30-day credentials** that grant access to read all scoped credentials via the TEE. Calling them "JWT" leads to underestimating storage security requirements. The canonical AgentKeys term is **"bearer token"** (see [#10](https://github.com/litentry/agentKeys/issues/10)); older docs may still say "session token" or "JWT."

**Heima side:** Heima-internal code and docs continue to use "JWT" / `AuthTokenClaims`. We do not plan to change Heima terminology. The rename is AgentKeys-local.

---

## 2. How it's issued

```
client authenticates (Passkey / Google OAuth / Web3 signature)
  ↓
client sends signed request_auth_token trusted call to TEE
  (signed with client's OWN identity key — Passkey, Web3 wallet, etc.)
  ↓
TEE verifies identity proof
  ↓
TEE creates / looks up OmniAccount
  (address deterministically derived: OmniAccountConverter::convert(&identity, &client_id))
  ↓
TEE signs a session token with its RSA private key:
  {
    sub: "0x9c3e..." (omni account, hex-encoded),
    typ: "ACCESS",
    exp: now + 30 days,
    aud: "HEIMA"
  }
  ↓
TEE returns the token string to the client
```

> **AgentKeys user-facing name:** for the email / OAuth onboarding path, this issuance step — where the signer attests control of your derived **managed wallet** and the broker mints your session bearer (J1) — is surfaced to operators as **"activate your managed wallet"**. Canonically it is the **managed-wallet attestation** (SIWE / EIP-191, signer-performed; see [`arch.md` §5 canonical names](../arch.md)). The "Web3 signature" variant above maps to the **`evm`-identity** path, where you sign directly with your own wallet — genuine Sign-In With Ethereum, *not* a managed-wallet attestation.

The issuer signing key:

- Lives inside the TEE (sealed storage), derived from the sealed TEE master seed at path `issuer/jwt/v1` via SLIP-0010 HDKD — the same seed that roots the shielding key, per-user wallet keys, OIDC-issuer key, and per-domain DKIM keys (see [Blockchain TEE Architecture §1](blockchain-tee-architecture#tee-trusted-execution-environment-worker) and [`docs/spec/heima-gaps-vs-desired-architecture.md`](../spec/heima-gaps-vs-desired-architecture.md) for the current-vs-desired gap)
- Alg is **ES256** (ECDSA P-256, SHA-256 digest). This is the TEE's internal trust anchor for the 30-day session bearer and is verified only by TEE workers — not exposed on any public JWKS endpoint.
- The session-JWT key is **separate** from the public OIDC-issuer key (`oidc/issuer/v1`, also ES256). Separation keeps the public-facing, rotatable OIDC trust anchor isolated from the internal session-JWT anchor, so an OIDC-issuer rotation (driven by AWS cache windows) does not invalidate every live session token.
- Public key published on chain via `register_enclave()` for on-chain verification by other Heima components.

---

## 3. How it's verified (on every call)

```
client sends request + session token to TEE
  ↓
TEE verifies:
  1. RSA signature valid? (check against TEE's RSA public key)
  2. exp > current time? (not expired)
  3. aud matches expected client ID? (audience check)
  4. typ == "ACCESS"? (token type check)
  ↓
all pass → extract sub (omni account address) → proceed
any fail → reject (401 unauthorized)
```

**Verification is stateless.** The TEE does not maintain a session table. It verifies the token cryptographically using the RSA public key and checks the embedded expiration. No database lookup, no chain state read for auth (chain state IS read for scope and credential blobs, but not for token validity).

---

## 4. How it differs from a private key

This is the critical distinction. The session token is NOT a private key, but it IS a high-value credential.

### What an attacker CAN do with a stolen session token

- **Authenticate to the TEE** as the user for up to 30 days (until expiration)
- **Read any credential** the account has scope for, via the TEE
- **Trigger operations** (store, read, pair requests) authenticated as the user

### What an attacker CANNOT do with a stolen session token

- **Forge new tokens** — the RSA signing key is inside the TEE; the attacker can't mint tokens
- **Sign chain extrinsics directly** — the wallet private key is inside the TEE; the attacker can only talk to the TEE, not bypass it
- **Bypass TEE enforcement** — rate limits, scope checks, and revocation are all TEE-enforced; the attacker goes through the same gateway as legitimate clients
- **Extend the token's lifetime** — the expiration is signed into the token; tampering invalidates the RSA signature

### The TEE as a mandatory gateway

This is the key architectural advantage over the "client holds private key" model. With a private key, an attacker who compromises the daemon can bypass the TEE entirely and submit signed extrinsics directly to a Heima RPC endpoint — the TEE's rate limits and scope enforcement become irrelevant. With a session token, the **TEE is the only gateway** — all operations must go through it, and it enforces policy on every call.

### Summary comparison


| Property                           | Private key (session keypair)                | Session token (TEE-issued bearer)             |
| ---------------------------------- | -------------------------------------------- | --------------------------------------------- |
| Attacker can forge new credentials | Yes                                          | No                                            |
| Attacker can bypass TEE            | Yes (sign extrinsics directly)               | No (TEE is mandatory gateway)                 |
| Attacker can impersonate user      | Indefinitely (until key rotated)             | Until token expires (30 days)                 |
| Revocation mechanism               | Rotate key on chain + re-mint + redistribute | Add account to on-chain revocation list (~6s) |
| Expiration                         | None (key has no TTL)                        | Built-in (`exp` field, signed, unforgeable)   |
| Rate limiting enforceable          | No (attacker bypasses TEE)                   | Yes (TEE enforces on every call)              |
| Client-side crypto code needed     | Yes (signing, keyring, subxt)                | No (just send a string in a header)           |


---

## 5. How to protect it

A 30-day session token is a **high-security credential**. It warrants the same storage protection as a long-lived API key. The "it's just a JWT, store it anywhere" framing is wrong for 30-day tokens.

### Storage recommendations


| Context                   | Recommended storage                                                              | Why                                                                                                                                                                                                              |
| ------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Master CLI on desktop** | **OS keychain** (default)                                                        | Keychain provides app-level ACL (prevents malware-as-same-user from extracting the token), at-rest encryption, and integration with OS lock screen. This is how `gh`, `gcloud`, and `docker` store their tokens. |
| **Daemon in sandbox**     | **Hardened file** (`~/.agentkeys/token`, mode 0600) + kernel hardening (Stage 3) | No keychain available in most sandbox environments. `memfd_secret` + `mlock` + seccomp compensate for the lack of keychain ACL.                                                                                  |
| **CI / testing**          | **Env var or file**                                                              | Ephemeral environment. Token should be short-lived (override `expires_at` to minutes, not days).                                                                                                                 |


### Memory hygiene (Stage 8)

Because the token is long-lived (30 days) and high-value, the same memory hygiene that applies to credential plaintext also applies to the session token:

- `**zeroize`/`SecretString`** wrapping for the token string in CLI and daemon memory. `Drop` impl actively zero-fills.
- `**memfd_secret`** for the token in daemon long-lived memory (the daemon holds the token for its entire lifetime — hours to days).
- `**prctl(PR_SET_DUMPABLE, 0)` + `setrlimit(RLIMIT_CORE, 0)`** on CLI and daemon startup to prevent core dumps from leaking the token.

These were briefly demoted from Stage 8 Priority A under an incorrect assumption that session tokens would be short-lived (24h). With 30-day TTL, they are **restored to Priority A**.

### Biometric gate for high-security master actions

For the master CLI, certain high-blast-radius actions should require biometric confirmation (Touch ID / Windows Hello / fprintd) in addition to the session token:

- `agentkeys approve` (pairing — creates child session with credential access)
- `agentkeys revoke` (kills an agent's access — irreversible)
- `agentkeys teardown` (deletes all credentials for an agent — destructive)
- `agentkeys init --force` (replaces master session)
- Recovery flow (re-associates credentials with a new daemon)

Normal operations (`store`, `read`, `run`, `usage`, `whoami`, `link`) stay silent.

Agent/daemon side: **always silent**, no biometric. Agents run unattended.

See [issue #11](https://github.com/litentry/agentKeys/issues/11) for the biometric gate design.

---

## 6. Revocation

Session tokens are stateless (no session table), so the TEE cannot "invalidate" a token by flipping a flag. Revocation requires an **on-chain revocation list** that the TEE checks on every call.

```
master CLI → TEE: revoke_agent(agent_account=0x44d3)
  authenticated by: master's session token
  ↓
TEE verifies master token + ownership of agent
  ↓
TEE submits revocation extrinsic:
  revoked_accounts.insert(0x44d3)
  ↓
~6s: chain confirms
  ↓
next call by the revoked agent:
  TEE verifies session token → valid (RSA sig OK, not expired) ✅
  TEE reads chain state → 0x44d3 in revoked_accounts → REJECT ❌
```

**Revocation latency = 1 block (~6s).** This meets the spec requirement from `heima-open-questions.md Q9`.

After revocation, the agent's session token is cryptographically valid (the RSA signature and expiration still check out) but functionally useless (the TEE rejects it because the account is on the revocation list). This is the right tradeoff: stateless verification for the common case (fast), on-chain revocation check for the security case (6s).

---

## 7. Lifecycle summary

```
┌─────────────────────────────────────────────────────────────┐
│                    SESSION TOKEN LIFECYCLE                    │
│                                                              │
│  ISSUE                                                       │
│  client authenticates (Passkey / OAuth / Web3)               │
│  → TEE verifies identity                                     │
│  → TEE signs token with RSA key                              │
│  → returns token string to client                            │
│  → client stores in keychain (master) or file (daemon)       │
│                                                              │
│  USE (every call, for up to 30 days)                         │
│  client sends token with request → TEE verifies:             │
│    1. RSA signature valid?                                   │
│    2. not expired?                                           │
│    3. not on revocation list? (chain state read)             │
│  → proceed or reject                                         │
│                                                              │
│  EXPIRE                                                      │
│  exp < current time → TEE rejects                            │
│  client must re-authenticate to get a new token              │
│                                                              │
│  REVOKE (master-initiated, before natural expiration)        │
│  master calls revoke → chain state updated (~6s)             │
│  → TEE rejects on next call (token valid but account revoked)│
│                                                              │
│  REFRESH                                                     │
│  no refresh mechanism in current Heima — re-auth required    │
│  (future: add refresh token flow for smoother UX)            │
└─────────────────────────────────────────────────────────────┘
```

---

## 8. v0 vs v0.1 comparison


| Property                   | v0 (mock backend)                            | v0.1 (Heima TEE)                                               |
| -------------------------- | -------------------------------------------- | -------------------------------------------------------------- |
| Token format               | Random 32-byte hex string (opaque bearer)    | Signed JWT (RSA, with claims)                                  |
| Token issuer               | Mock backend (`generate_token()`)            | Heima TEE (`jwt::create(&claims, private_key)`)                |
| Verification               | Bearer lookup in SQLite `sessions` table     | Stateless RSA signature check (no table)                       |
| Expiration                 | TTL field in SQLite (2_592_000s = 30 days default) | `exp` claim in JWT (configurable, target 30 days)        |
| Revocation                 | `UPDATE sessions SET revoked=1` in SQLite    | On-chain revocation list, ~6s propagation                      |
| Storage (master)           | OS keychain via `keyring-rs`                 | OS keychain (same, storing JWT string instead of random token) |
| Storage (daemon)           | File fallback at `~/.agentkeys/session.json` | File at `~/.agentkeys/token` (mode 0600)                       |
| Client holds               | Opaque bearer string                         | Signed bearer string (JWT)                                     |
| Client holds private keys? | No (v0 mock uses bearer-only auth)           | No (TEE holds all private keys)                                |


The v0 → v0.1 migration for session tokens is straightforward: replace the random bearer string with a JWT string. The storage mechanism (keychain + file fallback) stays the same. The `session_store.rs` code changes minimally — it stores a different string, but the save/load paths are identical.

---

## 9. References

### Heima source (verified 2026-04-12)

- `tee-worker/omni-executor/core/src/auth/auth_token.rs` — `AuthTokenClaims` struct, JWT creation and validation
- `tee-worker/omni-executor/rpc-server/src/auth_token_key_store.rs` — RSA key generation and storage
- `tee-worker/identity/app-libs/stf/src/trusted_call.rs` — `TrustedCallSigned` struct, `request_auth_token` variant
- `tee-worker/identity/client-sdk/packages/client-sdk/src/lib/requests/request_auth_token.request.ts` — client-side auth token request flow
- `parachain/pallets/omni-account/src/lib.rs` — `OmniAccountConverter`, `auth_token_requested` event

### AgentKeys docs

- `[wiki/blockchain-tee-architecture.md](./blockchain-tee-architecture.md)` Section 4 — auth token lifecycle in the blockchain+TEE architecture
- `[wiki/key-security.md](./key-security.md)` Section 2 — storage recommendations
- `[docs/spec/1-step-analysis.md](../spec/1-step-analysis.md)` Section 3.2 — session tier table (corrected for JWT model)

### Issues

- [#10](https://github.com/litentry/agentKeys/issues/10) — Rename JWT to avoid misleading terminology
- [#11](https://github.com/litentry/agentKeys/issues/11) — Biometric gate for high-security master CLI actions
- [#3](https://github.com/litentry/agentKeys/issues/3) — Stage 8 production hardening (memfd_secret + zeroize for session token restored to Priority A)

