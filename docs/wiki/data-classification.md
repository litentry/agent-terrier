> **Updated 2026-04-26 — credential storage row.** The "Credential blobs" row in §1 used to read "On chain: encrypted ciphertext." That position is superseded — sensitive ciphertext now lives **off-chain** (S3) under per-epoch DEKs that rotate; chain holds only `(blob_pointer, ciphertext_hash, epoch)`. Architectural rationale: [`docs/spec/threat-model-key-custody.md`](../spec/threat-model-key-custody.md). Operational design: [`docs/stage8-wip.md`](../stage8-wip.md). The change is structural, not cosmetic — it closes the harvest-now-decrypt-later gap that on-chain ciphertext could not.

Every piece of data in AgentKeys exists in one or more of four locations: the blockchain, the TEE, **off-chain content-addressed storage (S3 today)**, and the client (CLI or daemon). This document maps each data item to its encryption status at each location.

Companion docs:

- `[wiki/blockchain-tee-architecture.md](./blockchain-tee-architecture.md)` — how the chain and TEE split responsibilities
- `[wiki/key-security.md](./key-security.md)` — session vs credential security, hardening layers
- `[wiki/serve-and-audit.md](./serve-and-audit.md)` — audit submission, Pattern 4, fee funding
- [`docs/spec/threat-model-key-custody.md`](../spec/threat-model-key-custody.md) — why nothing sensitive lives on chain or persistently in TEE; forward-secret epoch rotation

---

## 1. Master classification table


| Data                                                        | On chain                                                            | In TEE                                                                  | On client                                                               |
| ----------------------------------------------------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| **Credential blobs** (API keys — the actual secrets)        | **Pointer + ciphertext hash only** (`pallet-vault-pointers`); ciphertext lives off-chain in S3 under per-epoch DEK | Plaintext in memory during decrypt, then wiped; DEK unwrapped per-request, never persistent in TEE memory across calls | Plaintext in memory during MCP delivery, then wiped (Stage 9 hardening, formerly Stage 8) |
| **Shielding private key**                                   | Public key only (registered via `register_enclave()`)               | Sealed storage (SGX encrypted at rest)                                  | Never                                                                   |
| **RSA JWT signing key**                                     | Never                                                               | Sealed storage (PKCS#1 DER file)                                        | Never                                                                   |
| **User wallet private keys** (current model: per-user)      | Never                                                               | Sealed storage (per `pallet-bitacross`)                                 | Never                                                                   |
| **MSK** (target model: single master key)                   | Never                                                               | Sealed storage (one blob)                                               | Never                                                                   |
| **Derived user private key** (target MSK model)             | Never                                                               | Ephemeral memory only (derived from MSK, used, discarded)               | Never                                                                   |
| **Session token** (JWT-format bearer credential)            | Never                                                               | Signed by TEE, not stored after issuance                                | Plaintext file (mode 0600) or OS keychain                               |
| **OmniAccount address**                                     | Plaintext                                                           | Derived from identity (not stored separately)                           | Known (printed by CLI, used in commands)                                |
| **Identity hash** `H(identity_info)`                        | Plaintext (hashed — original identity is NOT on chain)              | Original identity available during auth (from OAuth/Passkey/Web3 proof) | Original identity known to user only                                    |
| **Session scope** (which services a delegate can access)    | Plaintext                                                           | Read from chain                                                         | Known (displayed by CLI)                                                |
| **Session TTL / valid_until**                               | Plaintext                                                           | Read from chain                                                         | Known (displayed by CLI)                                                |
| **Revocation / suspend status**                             | Plaintext                                                           | Read from chain on every request                                        | Known (CLI can query)                                                   |
| **Audit events** (who read what, when)                      | Plaintext                                                           | Not stored (submitted async, chain is the record)                       | Queryable via `agentkeys usage`                                         |
| **Pair request** (daemon_pubkey, scope, alias, valid_until) | Plaintext                                                           | Not stored (processed and relayed to chain)                             | Daemon displays VVC + scope to user                                     |
| **Pair approval** (child session payload)                   | Encrypted (to daemon_pubkey, so only the target daemon can decrypt) | Plaintext in memory during mint, then wiped                             | Daemon decrypts with its private key, stores session locally            |
| **VVC** (visual verification code)                          | Never (derived client-side from extrinsic signature)                | Never                                                                   | Ephemeral display (both daemon and master CLI compute independently)    |
| **Wallet USDC balance**                                     | Plaintext                                                           | Read from chain when needed                                             | Queryable                                                               |
| **Generation counter** (per child path, for key rotation)   | Plaintext                                                           | Read from chain                                                         | Known                                                                   |
| **AES response keys** (per-request encryption)              | Never                                                               | Ephemeral memory (per-request, discarded)                               | Decrypted by client per-response                                        |
| **Child path** (`/agent-alias/0`)                           | Plaintext (in pair request / approval events)                       | Used for derivation, not stored                                         | Known to daemon and master CLI                                          |


---

## 2. By location: what each layer sees

### On chain — the public ledger

Everything on chain is readable by anyone with a node or block explorer. The chain stores two categories:

**Plaintext (publicly readable):**

- OmniAccount addresses (identity-derived, stable)
- Identity hashes (`H(identity_info)` — the hash, not the original identity)
- Session scope, TTL, revocation status
- Pair requests (daemon_pubkey, scope, alias, valid_until)
- Audit events (wallet, agent, service, action, result, timestamp, block)
- Wallet USDC balances
- Generation counters per child path
- Child derivation paths
- Shielding public key (registered via `register_enclave()`)

**Encrypted (only TEE can decrypt):**

- Credential blobs — encrypted to the TEE shielding key. Contains the actual API keys (e.g., `sk-or-v1-abc123`). Anyone can see that a credential exists for `(owner, agent, service)`, but cannot read the value.
- Pair approval payloads — encrypted to the target daemon's public key. Contains the child session material. Only the target daemon can decrypt.

**Never on chain:**

- Any private key (shielding, RSA, wallet, MSK, derived user keys)
- Session tokens (bearer credentials)
- VVC (visual verification codes)
- Plaintext credentials
- Original identity info (only the hash is stored)
- User public keys (in the MSK target model — derived on demand, not persisted)

### In TEE — the computation oracle

The TEE holds secrets in sealed storage and processes sensitive data in ephemeral memory.

**Sealed storage (persisted, encrypted at rest by SGX):**

- Shielding private key (permanent)
- RSA JWT signing key (permanent)
- Per-user wallet private keys (current model, permanent per user)
- MSK (target model, one value, permanent)

**Ephemeral memory (exists only during an operation, then wiped):**

- Derived user private key (MSK model — derived from MSK + identity, used for one signing/decryption, then zeroized)
- Decrypted credential plaintext (read from chain as ciphertext, decrypted, returned to caller, then zeroized)
- AES response keys (per-request, discarded after response is encrypted)
- Minted child session material (during pair approval — generated, encrypted to daemon pubkey, submitted to chain, then zeroized)

**Never in TEE (chain holds these):**

- Credential blobs (read from chain on demand)
- Session records (read from chain on demand)
- Pair requests / approvals (processed and submitted to chain)
- Audit log entries (submitted to chain, not retained)
- Revocation state (read from chain)

### On client (CLI / daemon) — the user's device

The client holds the minimum needed to authenticate and receive results.

**Stored locally:**

- Bearer token (formerly "JWT auth token"; rename tracked in [#10](https://github.com/litentry/agentKeys/issues/10)) — plaintext string. Storage: OS keychain when available (master CLI + desktop/Mac-mini daemons per [#12](https://github.com/litentry/agentKeys/issues/12)), plain file (`~/.agentkeys/token`, mode 0600) otherwise. NOT a private key. Leakage gives temporary access bounded by the AgentKeys 30-day policy (Heima SDK default is ~24h). Revocable via on-chain revocation list (~6s on Heima; instant on the v0 mock).
- Child session private key (current v0 model only, stored in `~/.agentkeys/session`, mode 0600). In the target session token model, this becomes just another session token string.

**Ephemeral memory (during operation only):**

- Decrypted credential plaintext — held in daemon memory during MCP `get_credential` response delivery, then wiped (Stage 8 Priority A hardening). In `cmd_run`, injected as env var into child process, then parent's copy is dropped.
- VVC — computed locally from the extrinsic signature (`decimal(SHA256(signature))[..6]`), displayed to user, then discarded.

**Never on client:**

- Any TEE private key (shielding, RSA, wallet, MSK)
- Credential ciphertext (client never sees the encrypted blob — it asks the TEE, which decrypts and returns plaintext)
- Other users' data (scoped by the session token's `sub` field)

---

## 3. Encryption schemes by data type


| Data                                                          | Encryption scheme                                                            | Key                                                      | Who can decrypt                                                                                         |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Credential blobs on chain                                     | Encrypted to shielding key (asymmetric, scheme TBD per Heima implementation) | TEE shielding public key                                 | Only the TEE (holds shielding private key)                                                              |
| Pair approval payload on chain                                | Encrypted to daemon_pubkey (asymmetric)                                      | Daemon's ephemeral public key (included in pair request) | Only the target daemon (holds its own ephemeral private key)                                            |
| TEE sealed storage (shielding key, RSA key, wallet keys, MSK) | SGX sealing (AES-GCM with CPU-derived seal key)                              | Derived from CPU's seal key + enclave measurement        | Only the same enclave on the same CPU (or with the same seal policy)                                    |
| Session token (JWT-format)                                    | RSA signature (not encrypted — signed for integrity, readable by anyone)     | TEE's RSA private key (signs); RSA public key (verifies) | Anyone can READ the session token payload (it's base64, not encrypted). Only the TEE can FORGE a valid signature. |
| AES response encryption                                       | AES-GCM (symmetric, per-request)                                             | `RequestAesKey` (ephemeral, per-request)                 | Only the requesting client (holds the AES key for that request)                                         |
| Identity hash on chain                                        | SHA-256 (one-way hash, not encryption)                                       | N/A (hash, not encrypted)                                | Anyone can read the hash. Nobody can reverse it to the original identity (preimage resistance).         |


---

## 4. Data flow through encryption boundaries

### Credential store flow

```
user types: agentkeys store --agent 0xAGENT openrouter sk-or-v1-abc123
  ↓
CLI has plaintext credential: "sk-or-v1-abc123"                [CLIENT: plaintext]
  ↓
CLI sends to TEE (over TLS/wss)                                [TRANSIT: TLS encrypted]
  ↓
TEE receives plaintext credential                              [TEE: plaintext in memory]
TEE encrypts to shielding key → ciphertext                     [TEE: ciphertext in memory]
TEE submits store_credential extrinsic with ciphertext          [TEE → CHAIN: ciphertext]
TEE wipes plaintext from memory                                [TEE: gone]
  ↓
Chain stores ciphertext in pallet-secrets-vault                 [CHAIN: encrypted]
  ↓
Credential exists ONLY as ciphertext on chain.
Plaintext exists NOWHERE after the TEE wipes it.
```

### Credential read flow

```
daemon sends: get_credential(openrouter) + session token       [CLIENT → TEE: token plaintext]
  ↓
TEE verifies session token (RSA sig + expiry)                  [TEE: token in memory]
TEE reads chain: credential blob for (owner, agent, service)    [CHAIN → TEE: ciphertext]
TEE decrypts with shielding key                                 [TEE: plaintext in memory]
TEE returns plaintext to daemon (over TLS/wss)                  [TEE → CLIENT: TLS encrypted]
TEE wipes plaintext from memory                                 [TEE: gone]
TEE submits audit extrinsic async (paymaster-funded)             [TEE → CHAIN: plaintext audit event]
  ↓
Daemon receives plaintext credential                            [CLIENT: plaintext in memory]
Daemon delivers to agent via MCP                                [CLIENT: plaintext in memory]
Daemon wipes plaintext from memory (Stage 8)                    [CLIENT: gone]
  ↓
Agent has plaintext in its own memory                           [AGENT: plaintext in memory]
Agent uses it for API call, then (ideally) discards             [AGENT: gone after use]
  ↓
Audit event appears on chain ~6s later                          [CHAIN: plaintext audit record]
```

### Pairing flow

```
daemon generates ephemeral keypair                              [CLIENT: daemon_privkey in memory]
daemon signs pair request payload                               [CLIENT: signature computed locally]
daemon → TEE: signed pair request                               [CLIENT → TEE: plaintext over TLS]
  ↓
TEE validates, submits to chain                                 [TEE → CHAIN: plaintext pair request]
  ↓
Chain stores: daemon_pubkey, scope, alias, valid_until          [CHAIN: all plaintext]
  ↓
master CLI → TEE: approve pair request                          [CLIENT → TEE: approval over TLS]
  ↓
TEE mints child session                                         [TEE: child session in memory]
TEE encrypts child session to daemon_pubkey                     [TEE: ciphertext in memory]
TEE submits approval extrinsic with encrypted payload           [TEE → CHAIN: encrypted payload]
TEE wipes child session plaintext from memory                   [TEE: gone]
  ↓
Chain stores: encrypted child session payload                   [CHAIN: encrypted]
  ↓
Daemon reads approval from chain                                [CHAIN → CLIENT: encrypted payload]
Daemon decrypts with daemon_privkey                             [CLIENT: child session plaintext]
Daemon stores session locally (session token or session file, mode 0600) [CLIENT: stored locally]
```

---

## 5. What an attacker gets at each compromise point


| Compromise point                                           | What they get                                                                                                                             | What they DON'T get                                                                                                 | Blast radius                                                                                                                                                                                                                                                                 |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Chain data exfiltration** (read all on-chain state)      | All plaintext: addresses, identity hashes, scopes, audit events, pair metadata. Credential ciphertext (unreadable without shielding key). | Any private key. Any plaintext credential. Session tokens (not on chain). Original identity info (only hash).       | Information disclosure only. No ability to decrypt credentials or impersonate users.                                                                                                                                                                                         |
| **Client device compromise** (laptop/sandbox)              | Session token (bearer credential). Possibly plaintext credential in memory if timed during a read operation.                              | Any TEE key. Other users' data. Credential ciphertext.                                                              | Impersonate this user until session token expires (~30 days) or is revoked (~6s). If credential was in memory, one credential for one service exposed.                                                                                                                       |
| **Session token theft**                                    | Impersonate the user for the token's remaining TTL. Scoped by the token's `sub` (one user) + on-chain scope (specific services).          | TEE keys. Other users' sessions. Ability to forge new tokens. Ability to sign extrinsics (TEE signs, not the client). | Bounded by TTL + scope. Revocable via on-chain revocation list (~6s).                                                                                                                                                                                                      |
| **TEE compromise** (enclave breach, side-channel, insider) | All sealed keys (shielding, RSA, wallet/MSK). Can decrypt ALL credential blobs. Can forge session tokens. Can sign extrinsics as any user. | Chain history (already written, immutable). Can't rewrite past audit events.                                        | **Total.** All users, all credentials, all operations. Recovery: rotate shielding key, re-encrypt all credentials, rotate MSK, re-issue all session tokens. The on-chain audit trail survives — forensic investigation of what happened during the breach is possible from chain data. |
| **Paymaster compromise** (treasury drained)                | Can stop paying for audit extrinsic submission. Existing credentials and sessions unaffected.                                             | Any key. Any credential. Any ability to impersonate.                                                                | Audit events stop appearing on chain. Credential reads still work (TEE serves from chain state). Degraded mode: reads work, audit is paused.                                                                                                                                 |


---

## 6. Summary: the three data categories

Every piece of data in the system falls into one of three categories:

### Category 1: Secrets (never plaintext outside TEE memory)

- Credential plaintext (API keys)
- All TEE private keys (shielding, RSA, wallet, MSK)
- Derived user private keys (MSK model — ephemeral)

**Rule:** exist in TEE memory only during the operation, then zeroized. Never on chain in plaintext. Never on the client device except credential plaintext during MCP delivery (Stage 8 hardening wipes immediately).

### Category 2: Encrypted artifacts (on chain, readable only by authorized party)

- Credential ciphertext (encrypted to shielding key — only TEE can decrypt)
- Pair approval payload (encrypted to daemon_pubkey — only target daemon can decrypt)

**Rule:** on chain permanently. Publicly visible as ciphertext. Decryption requires the correct private key, held by exactly one party.

### Category 3: Public metadata (on chain, readable by everyone)

- OmniAccount addresses, identity hashes, session scopes, TTLs
- Pair requests (daemon_pubkey, scope, alias, valid_until)
- Audit events (who, what, when, result)
- Revocation/suspend events
- Wallet balances, generation counters, child paths

**Rule:** designed to be public. Contains no secrets. Identity hashes protect the original identity via preimage resistance. Enables third-party verification, compliance auditing, block explorer visibility.

---

## 7. References

### Wiki

- `[wiki/blockchain-tee-architecture.md](./blockchain-tee-architecture.md)` — full architecture, TEE vs chain roles, worked examples
- `[wiki/key-security.md](./key-security.md)` — session security, hardening layers, credential lifecycle
- `[wiki/serve-and-audit.md](./serve-and-audit.md)` — Pattern 4 audit, latency, fee funding

### Issues

- [#3](https://github.com/litentry/agentKeys/issues/3) — Stage 8: Production hardening (credential memory hygiene)
- [#9](https://github.com/litentry/agentKeys/issues/9) — Stateless MSK-derived TEE architecture

### Spec

- `[docs/spec/tech-brief.md](../spec/tech-brief.md)` — shielding key model, TEE-chain split
- `[docs/spec/credential-backend-interface.md](../spec/credential-backend-interface.md)` — signing model, encryption contract

