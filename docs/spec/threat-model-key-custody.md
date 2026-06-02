# Threat Model: Key Custody and Sensitive-Data Storage

**Date:** 2026-04-26
**Status:** Design — supersedes the on-chain encrypted-vault assumption that runs through docs/wiki/blockchain-tee-architecture.md, docs/wiki/data-classification.md, docs/wiki/key-security.md, and docs/spec/credential-backend-interface.md.
**Related issues:** [#57](https://github.com/litentry/agentKeys/issues/57) (this doc — security finding), [#9](https://github.com/litentry/agentKeys/issues/9) (master-seed HDKD), [`docs/spec/heima-gaps-vs-desired-architecture.md`](./heima-gaps-vs-desired-architecture.md), [archived stage8 WIP](../archived/stage8-wip-2026-04.md)

This doc defines the canonical security position for **where sensitive ciphertext lives** and **how decryption keys are managed**. Earlier docs assume an on-chain encrypted vault (`pallet-secrets-vault`); this doc replaces that assumption with off-chain ciphertext + on-chain hash + forward-secret epoch rotation, and explains why.

If you only read one section, read §3 (the threat that drove this) and §6 (the resulting position).

---

## 1. The four properties this doc optimizes

Every storage and key-custody decision in AgentKeys lives or dies on four security properties. Different threat surfaces map to different properties; conflating them is what produces "secure-sounding" architectures that fail in practice.

| Property | Question it answers | Failure mode |
|---|---|---|
| **Authorization integrity** | Can an attacker mint a credential they were not authorized to mint? | Forward-only forgery; bounded by key rotation. |
| **Confidentiality (live)** | Can an attacker read sensitive data while it is in transit or at rest, today? | Time-bounded by detection + rotation. |
| **Retroactive confidentiality** | If the decryption key leaks at any future point, can an attacker decrypt data captured today? | **Unbounded in time. Permanent.** |
| **Metadata leak** | Can an attacker observe access patterns, ownership, or activity even without decrypting anything? | Side-channel; usually permanent. |

The asymmetry across these properties is the whole point. An authorization-integrity breach is **recoverable** — you rotate keys, force re-pair, revoke on chain. A retroactive-confidentiality breach is **unrecoverable** — anyone who captured ciphertext during the vulnerable window decrypts forever.

The current AgentKeys spec is strong on (1) and (2). It is silent on (3) and (4). This doc commits to a position on (3) and (4) — and shows that the position requires architectural changes, not just key-rotation policy.

---

## 2. Restating the current Stage 7 stance (what we are revising)

Stage 7 as currently specified ([`docs/docs/wiki/blockchain-tee-architecture.md`](../docs/wiki/blockchain-tee-architecture.md), [`docs/docs/wiki/key-security.md`](../docs/wiki/key-security.md), [`docs/spec/credential-backend-interface.md`](./credential-backend-interface.md)) takes these positions:

1. **Credential ciphertext lives on chain** in a new `pallet-secrets-vault`, encrypted to the TEE shielding key.
2. **Shielding key sealed in TEE**, derived from the master seed via SLIP-0010 at path `shielding/v1`.
3. **Bearer tokens are short-lived** (≤30 d, AgentKeys policy) and revocable on chain (~6 s).
4. **Per-user isolation on shared cloud resources** (S3, GCP, etc.) via OIDC JWT → PrincipalTag → resource policy.
5. **Audit events on chain** as extrinsics, async via paymaster.

Honest grade against the four properties:

| Property | Stage 7 grade | Why |
|---|---|---|
| Authorization integrity | **A** | Bearer tokens revocable, audit on chain, per-user PrincipalTag isolation. |
| Confidentiality (live) | **B+** | Ciphertext encrypted to TEE shielding key; plaintext exists only in TEE during decrypt. Daemon and agent windows handled by Stage 9 (memory hygiene, formerly Stage 8). |
| Retroactive confidentiality | **F** | **Public ciphertext on an immutable ledger + single long-lived shielding key = unbounded harvest-now-decrypt-later window.** |
| Metadata leak | **C** | Chain storage keys reveal "user X stored Y at block N"; activity patterns are public even when contents are encrypted. |

Properties (3) and (4) are the gap this doc closes.

---

## 3. The threat: harvest-now-decrypt-later, on chain, forever

Three properties of an immutable public ledger combine into a worst-case substrate for encrypted secrets:

1. **Public.** Every node, every block explorer, every archival service can fetch every encrypted blob.
2. **Immutable.** "Delete" is a marker; the bytes remain in every archival node.
3. **Forever.** No expiry mechanism. Block N's ciphertext is still bit-identical at block N + 10 million.

Combine those with a single long-lived shielding key (derived once from master seed at `shielding/v1`, never rotated in the current spec) and the consequence is:

> **An attacker who copies the chain today and waits — for 1 year, 10 years, 30 years — wins everything if the shielding key ever leaks. Including credentials that have long since been "revoked" or "deleted" at the application layer.**

This is the same "store now, decrypt later" model that motivates post-quantum migration, but it does not require a quantum break. It only requires:

- Side-channel extraction of the sealed master seed at any future point (a real risk on commodity TEEs over decade timescales).
- A vendor-side compromise (Intel SGX has had several published microarchitectural breaks; future hardware will too).
- A successor enclave operator who is curious about the past.
- A single insider with sealed-storage extraction capability.

None of these requires breaking AES, breaking the curve, or quantum cryptography. They only require that the *key* eventually leaves the TEE — once, ever, in any future timeframe. And the ciphertext we wrote today is still sitting in every chain node waiting to be decrypted.

**Splitting the TEE into two enclaves does not fix this.** Splitting addresses the probability of joint compromise; the consequence on retroactive confidentiality is the same — the ciphertext is still public and still permanent. Same-platform splits are the worst case (single vulnerability takes both); heterogeneous threshold across SGX + TDX + Nitro reduces probability but not consequence. The fix has to be on the *consequence* axis, not the *probability* axis.

---

## 4. The fix: two architectural moves that compose

### Move 1 — off-chain ciphertext, on-chain hash + audit

Move the ciphertext to S3 (or any off-chain content-addressed store; see §9 on alternatives). Keep on chain only what consensus is genuinely load-bearing for: ownership records, grants, audit, revocation, and the **hash of the ciphertext** (so tamper of the off-chain blob is detectable).

The chain remains the source of authority. The off-chain layer is the source of bytes.

**What changes structurally:**

| | Old (Stage 7 stance) | New (this doc) |
|---|---|---|
| Ciphertext storage | `pallet-secrets-vault` on chain | S3 object `s3://agentkeys-vault/<user_wallet>/<service>/<epoch>/<msg_id>.enc` |
| Pointer / integrity | (implicit — chain is the bytes) | On-chain `(user_wallet, slot) → {blob_pointer, ciphertext_hash, epoch}` |
| Public ciphertext | **Yes — every node has it** | **No — bucket is private, AWS-IAM-gated** |
| Deletion | Marker only; bytes persist | Real — S3 lifecycle drops bytes |
| Metadata leak | Chain access patterns are public | S3 access patterns are private to the operator |
| Tamper evidence | Consensus | Hash on chain — detectable on read |
| Censorship resistance | High (permissionless reads) | Lower (AWS can pull the plug) — mitigated by content-addressed multi-backend (§9) |

The ciphertext-hash on chain is the load-bearing primitive. It gives chain-level integrity guarantees for off-chain-stored data. A reader fetches `(blob_pointer, ciphertext_hash)` from chain, retrieves bytes from S3, recomputes hash, rejects if mismatched. The audit log records the access regardless of where bytes live.

### Move 2 — forward-secret epoch rotation

Encrypt with a per-epoch DEK (data encryption key) that is **rotated on a fixed cadence** and **destroyed after rotation**. Re-encrypt active blobs under the new DEK. Drop old blobs from S3 via lifecycle. Older epochs are no longer decryptable, even by the TEE that originally wrote them.

```
Epoch 0:  DEK_0 encrypts blobs B0,0 ... B0,N
Epoch 1:  DEK_1 encrypts blobs B1,0 ... B1,M  (B0,* re-encrypted as B1,*' if still active)
Epoch 2:  DEK_2 encrypts blobs B2,0 ... B2,K  (DEK_0 destroyed; B0,* bytes deleted)
```

After rotation + deletion of epoch K, even total compromise of the TEE leaks at most epochs `K..current`. The earlier DEKs are gone; the earlier blobs are gone. Forward secrecy holds.

**Critical:** forward secrecy is meaningful only if the old ciphertext also disappears. Rotating keys while the old ciphertext sits forever in chain archive nodes is cosmetic. Move 1 (off-chain storage) is what makes Move 2 (key rotation) deliver real forward secrecy. **The two moves multiply, they don't add.**

### What total TEE compromise leaks under the combined design

| Compromise | Old design (Stage 7 stance) | New design (this doc, after K epochs) |
|---|---|---|
| TEE master seed leaks today | All historical credentials, all users, forever | Only credentials encrypted under DEK_current; older epochs are irrecoverable |
| TEE master seed leaks 10 years from now | All credentials ever stored — chain still has the ciphertext | Same — only the then-current epoch |
| Shielding key only (not master seed) | All historical credentials | Only currently active blobs |
| Single user's blob leaks (e.g., S3 misconfiguration) | N/A — chain leaked or didn't | One blob, one user, one epoch |

The blast radius collapses from "all data ever" to "one epoch's data." That is the entire point of forward secrecy, and it is achievable only when the two moves compose.

---

## 5. What stays on chain — and why

This doc does not propose abandoning the chain. The chain earns its keep doing things consensus is genuinely needed for. Storing bulk encrypted bytes is not one of those things; storing the structural facts about ownership, access, and audit is.

| On chain (small, high-leverage) | Off chain (S3 / IPFS / ...) |
|---|---|
| `Ownership { user_wallet, slot, agent_wallet, blob_pointer, ciphertext_hash, epoch }` | The encrypted blob bytes themselves |
| `Grant { issuer_wallet, child_wallet, scope, expires_at }` | Encrypted user-data payloads (email blobs, vault entries, etc.) |
| Audit extrinsics: `BlobWritten { blob_pointer, hash, epoch }`, `CredsRead { child_wallet, blob_pointer, ts }`, `EpochRotated { from, to, ts }` | Old epochs' DEK-encrypted blobs (lifecycle-deleted) |
| Revocation list (≤ 6 s propagation) | |
| Per-domain DKIM trust anchor pubkey hashes | |
| OIDC issuer key pubkey hashes (JWKS authority) | |

The chain footprint per user remains small (kilobytes, not megabytes), which is what makes the chain economics actually work. Bulk ciphertext on chain breaks the cost story whether or not it breaks the threat model.

---

## 6. The resulting position (canonical, supersedes earlier docs)

> AgentKeys does not store sensitive payloads on the blockchain or persistently inside the TEE. The blockchain holds ownership, grants, audit, revocation, and ciphertext hashes — never the ciphertext itself. The TEE holds key-derivation roots and per-request decryption capability — never bulk plaintext, never persistent per-user material beyond what the master seed reproduces. Sensitive ciphertext lives off-chain in content-addressed storage (S3 today; multi-backend later), under per-epoch DEKs that rotate on a fixed cadence with old ciphertext deleted at lifecycle. Total TEE compromise at any future point leaks at most the currently active epoch.

Five concrete invariants, derived from that position:

1. **No `pallet-secrets-vault`-style on-chain encrypted blob store.** Earlier doc claims to this effect are superseded. The chain stores `(blob_pointer, ciphertext_hash, epoch)`, not bytes.
2. **DEKs are per-epoch, not per-key-lifetime.** The shielding key derived from `shielding/v1` is used to **wrap** epoch DEKs, not to directly encrypt bulk data. Wrapping happens in the TEE; the wrapped DEK is committed on chain alongside the ownership record.
3. **Old DEKs are destroyed at rotation.** Once epoch K+1 begins and active blobs have been re-encrypted, the TEE no longer holds DEK_K. It is unrecoverable even by the TEE itself.
4. **S3 (or successor off-chain store) is authoritative for bytes; chain is authoritative for hash.** A retrieval that fails hash check is treated as a tamper event.
5. **Per-user isolation is cloud-enforced via PrincipalTag** (Stage 7) regardless of how this doc evolves. The two systems compose; this doc does not change Stage 7's isolation primitive.

---

## 7. The encryption-center question — who holds the rotation authority

Forward-secret rotation requires a clearly identified component that:

- Decides when an epoch ends (cadence policy)
- Generates the new DEK (CSPRNG inside a trust boundary)
- Re-encrypts active blobs under the new DEK (or marks them stale)
- Destroys the old DEK (zeroize + drop)
- Emits the `EpochRotated` audit extrinsic
- Publishes the new wrapped DEK on chain

Three candidates, ordered by attack-surface footprint:

| Candidate | Attack surface | Comments |
|---|---|---|
| **TEE itself** (single enclave handling auth + decrypt + rotation) | Largest | Concentrates roles; rotation code adds bytes to the trust-critical surface. |
| **Dedicated rotation enclave** (TEE-B, separate from the auth/decrypt TEE-A) | Smaller | Can be small, network-isolated, no untrusted input parsing. Coordinates with TEE-A via attested channels. |
| **Threshold across heterogeneous enclaves** (SGX + TDX + Nitro k-of-n) | Smallest joint compromise probability | Highest implementation cost. Reasonable for v0.2+; out of scope for Stage 8. |

This doc commits to the **dedicated rotation enclave** path for Stage 8, with the threshold variant as a v0.2+ consideration. Stage 8 design and operational runbook live in [archived stage8 WIP](../archived/stage8-wip-2026-04.md).

Reducing TEE-B's attack surface is more important than splitting it from TEE-A. Specifically:

- **No network I/O** (input via attested channel from TEE-A only; output to S3 + chain via signed write tokens).
- **No untrusted input parsing** (binary protocol, fixed-size messages, exhaustively typed).
- **No general-purpose host shared memory** (only the sealed master seed and per-rotation working set).
- **Code surface small enough to formally verify or at least exhaustively review** (rotation logic should fit in a few hundred lines).

---

## 8. Composition with existing Stage 7 primitives

Stage 7 (OIDC federation, PrincipalTag, per-user isolation) is unchanged by this doc. The OIDC-issuer key still lives at `oidc/issuer/v1`. The JWT mint still emits `agentkeys_user_wallet` claims. AWS PrincipalTag still gates access to per-user S3 prefixes.

The only adjustment to the Stage 7 picture is **what gets gated**: the per-user prefix now contains the encrypted vault blobs (Stage 8) in addition to the email blobs (Stage 6). Same isolation primitive, broader scope.

```
                    s3://agentkeys-vault/<user_wallet>/...
                                       ↑
                       PrincipalTag-gated read (Stage 7)
                                       ↑
                       OIDC JWT carries user_wallet claim (Stage 7)
                                       ↑
                       TEE mints JWT with claim from authenticated session (Stage 7)
                                       ↑
                       Daemon presents bearer token + scope (Stage 4)
```

The encrypted blob inside that gated prefix is wrapped under DEK_current; DEK_current is wrapped under shielding key; shielding key is sealed in TEE; sealed via master seed. Three layers of wrapping, but the operational model stays simple: chain holds pointers, S3 holds bytes, TEE holds keys, and rotation cleans up after itself.

---

## 9. Open questions

These do not block adopting the position in §6 but need decisions before Stage 8 implementation lands.

1. **Storage backend portfolio.** S3 first (operator already runs the SES + S3 stack). Multi-backend (S3 + IPFS + Filecoin + Arweave content-addressed) is the censorship-resistance answer to §4 Move 1's main concession. When does multi-backend land? v0.1 with S3-only? v0.2 with IPFS pinning?

2. **Epoch cadence.** Daily? Weekly? Monthly? Per-credential-on-revoke? Tradeoff: shorter epoch = smaller leak window but more rotation cost; longer = the opposite. Default proposal: **weekly**, with on-demand rotation triggered by revocation events.

3. **Re-encryption strategy at rotation.** Two options:
   - **Eager**: re-encrypt all active blobs at epoch boundary. Predictable cost spike per rotation.
   - **Lazy**: re-encrypt on next read; old blobs marked stale, removed at lifecycle TTL. Smoother cost; longer effective leak window for unread blobs.
   Default proposal: **lazy with TTL**. Read-rate is predictable; idle blobs naturally expire.

4. **What about Heima's existing pallet design?** [`heima-gaps-vs-desired-architecture.md`](./heima-gaps-vs-desired-architecture.md) discusses the upstream parachain's pattern of on-chain encrypted state. We need a follow-up gap entry: "off-chain ciphertext + on-chain hash, not on-chain encrypted blob." The Heima conversation moves from "build `pallet-secrets-vault`" to "build `pallet-vault-pointers` + `pallet-vault-audit`."

5. **Threshold rotation** (TEE-B as k-of-n across heterogeneous platforms). Out of scope for Stage 8; flag as v0.2+ candidate when threat-modeling matures and second-platform enclave costs become acceptable.

6. **Recovery from accidental DEK loss.** A bug or operational mistake destroys DEK_K before active blobs are re-encrypted under DEK_K+1. Affected blobs are unrecoverable by design — this is the cost of forward secrecy. Mitigation: instrumented rotation runs with audited preconditions; never destroy DEK_K until `EpochRotated` extrinsic confirms re-encryption complete. Operationally identical to a backup-aware key-rotation runbook.

7. **Rotation under partial chain availability.** If the chain is wedged when an epoch boundary hits, the rotator cannot emit `EpochRotated`. Strategy: rotation is delayed (not skipped); the rotator's runbook covers chain-unavailable graceful degradation.

---

## 10. Migration from current claims

| Doc / claim | Current text says | After this doc |
|---|---|---|
| [`docs/docs/wiki/blockchain-tee-architecture.md`](../docs/wiki/blockchain-tee-architecture.md) §1 table row "Credential blobs" | "Encrypted ciphertext, on chain in `pallet-secrets-vault`" | Banner pointing here; row updated to "Pointer + ciphertext hash on chain; ciphertext off-chain (S3)" |
| [`docs/docs/wiki/data-classification.md`](../docs/wiki/data-classification.md) §1 row "Credential blobs" | "On chain: Encrypted (ciphertext)" | "On chain: Hash + pointer; In TEE: per-request decrypt only; Off-chain S3: ciphertext under per-epoch DEK" |
| [`docs/docs/wiki/key-security.md`](../docs/wiki/key-security.md) §1 table | "v0.1 Heima: Encrypted blob in Heima TEE (`pallet-secrets-vault`)" | "v0.1 (Stage 8): off-chain S3 ciphertext under per-epoch DEK; chain holds pointer + hash" |
| [`docs/spec/credential-backend-interface.md`](./credential-backend-interface.md) §"Mapping to Heima Primitives" | `store_credential` → `pallet-secrets-vault::write_secret` | `store_credential` → S3 write + on-chain `pallet-vault-pointers` extrinsic |
| [`docs/archived/development-stages-v2-2026-04.md`](../archived/development-stages-v2-2026-04.md) Stage 8 (current) | "Production hardening — memory hygiene" | Renumbered to **Stage 9**; new **Stage 8 = off-chain encrypted vault** (this doc's position) |
| [`docs/archived/development-stages-v2-2026-04.md`](../archived/development-stages-v2-2026-04.md) Stage 9 (current) | "Heima migration holding pen" | Renumbered to **Stage 10** |

---

## 11. Cross-references

- [archived stage8 WIP](../archived/stage8-wip-2026-04.md) — operational design for the off-chain vault (storage layout, rotation runbook, encryption-center responsibilities).
- [`docs/spec/heima-gaps-vs-desired-architecture.md`](./heima-gaps-vs-desired-architecture.md) — needs a new §5 "Off-chain ciphertext / `pallet-vault-pointers`" gap entry mirroring this doc's position.
- [`docs/spec/ses-email-architecture.md`](./ses-email-architecture.md) §4 — the email pipeline already uses the off-chain pattern; this doc generalizes it.
- [`docs/wiki/tag-based-access.md`](../wiki/tag-based-access.md) — Stage 7 PrincipalTag isolation, unchanged by this doc; gates the per-user S3 vault prefix.
- [`docs/archived/contradictions-stage4-2026-04.md`](../archived/contradictions-stage4-2026-04.md) — Stage-4 snapshot; entry resolving "where does sensitive ciphertext live" was added alongside this doc.
