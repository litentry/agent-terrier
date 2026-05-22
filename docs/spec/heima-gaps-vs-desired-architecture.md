# Heima Gaps vs. AgentKeys Desired Architecture

**Status:** living document (gap-tracking).
**Owner:** blockchain team.
**Last updated:** 2026-05-09 (revised after issue #74 step 1 / PR #75
landed the dev_key_service signer + signer-protocol contract).

## 1. Why this doc exists

The [wiki](../wiki/) always describes the **desired** architecture — the shape AgentKeys v0.1 is targeting, not the shape the upstream `litentry/heima` chain ships today. That's the right default for a design wiki: specs should describe where we're going, not where we happened to be when they were written.

This document is the other half. Every delta between:

- **desired**: what the AgentKeys wiki + spec docs describe, and
- **current**: what the upstream `litentry/heima` repo actually implements today,

gets one section below. Each section has a **Current**, **Desired**, **Impact**, **Migration path**, and (after PR #75) a **Status** banner. Gaps are closed by (a) patches landing upstream, (b) AgentKeys shipping a fork or self-hosted equivalent with the delta, or (c) the desired spec being revised downward — we mark which resolution a gap is taking as it lands.

Related docs:

- [`architecture.md`](architecture.md) — canonical broker / signer / daemon / key-flow doc (post-issue-#74).
- [`signer-protocol.md`](signer-protocol.md) — `/dev/*` wire contract.
- [`plans/issue-74-dev-key-service-plan.md`](plans/issue-74-dev-key-service-plan.md) — dev_key_service signer landed in PR #75.
- [`plans/issue-74-step-1c-device-key-auth.md`](plans/issue-74-step-1c-device-key-auth.md) — device-key auth on `/dev/*`, planned.
- [`docs/wiki/blockchain-tee-architecture.md`](../wiki/blockchain-tee-architecture.md) — canonical desired architecture (four rules).
- [`docs/wiki/key-security.md`](../wiki/key-security.md) — TEE key security model.
- [`plans/development-stages.md`](./plans/development-stages.md) — stage roadmap; this gap list is the critical path for Stage 6 and Stage 7.
- [`ses-email-architecture.md`](./ses-email-architecture.md) — Stage 6 email spec; depends on gaps §2, §3, §5.

## 1a. Status snapshot (added 2026-05-09)

The table below is the at-a-glance answer to "where do we stand?" Per-gap detail in §2 onwards.

| § | Gap | Status | Resolution path |
|---|---|---|---|
| 2 | HDKD master-seed key derivation | **PARTIAL — in-tree equivalent shipped** | AgentKeys' `dev_key_service` ships HKDF-from-master-secret derivation for the per-user wallet key (outside the TEE, dev-stage). Heima upstream is unchanged; full resolution waits on issue #74 step 2 (TEE worker). |
| 3 | TEE exposes an OIDC provider | **RESOLVED IN-TREE (operator-hosted)** | The Stage 7 Rust broker (PR #61, deployed in PR #73) ships `/.well-known/openid-configuration` + JWKS + bearer-gated `mint-oidc-jwt`. The trust anchor is the on-disk ES256 keypair, not a TEE — see [`architecture.md` §3 K2 + §7 "Pluggable surfaces"](architecture.md). Heima TEE-derived issuer remains the v0.2 hardening target. |
| 4 | BYODKIM (TEE-held DKIM keys) | **GAP — unchanged** | Stage 6 ships per-domain DKIM signing; today it's TEE-only design with no implementation. Plan unchanged. |
| 5 | On-chain email pallets | **GAP — unchanged** | `pallet-email-grants` + `pallet-email-audit` still don't exist upstream. Stage 6 blocker per original plan. |
| 6 | Session-tag JWT claims for AWS PrincipalTag | **RESOLVED IN-TREE** | The broker mints OIDC JWTs with `agentkeys_user_wallet` claim + `https://aws.amazon.com/tags` block; AWS STS exchanges for tagged sessions; S3 PrincipalTag policies enforce per-user isolation. Verified end-to-end in [`stage7-demo-and-verification.md` §4](../stage7-demo-and-verification.md). |
| 7 | Attested publication of issuer pubkey | **GAP — unchanged** | Stage 7 hardening follow-up; out of scope for v0.1. |
| 8 | `pallet-oidc-pubkeys` (URL-hijack defense) | **GAP — unchanged** | Stage 7b; depends on §3 having TEE-attested rather than on-disk keypair. |
| 9 | `pallet-enclave-successors` (MRSIGNER governance) | **GAP — unchanged** | Required only when MRSIGNER rotation lands; not a v0.1 blocker. |
| 10 | **(NEW)** Signer-edge contract for the per-user wallet key | **PARTIAL — wire shape pinned, dev-stage backend** | `signer-protocol.md` v0.1 ships the wire contract; `dev_key_service` is the dev-stage HKDF backend; issue #74 step 2 (TEE worker) closes the trust gap. |
| 11 | **(NEW)** Per-request crypto auth on the signer edge | **PLANNED** | Heima's `ClientAuth::EvmSiweSigned` / `BackendSigned` tier model is the prior art. Issue #74 step 1c (device-key auth) is a strict superset — see [`plans/issue-74-step-1c-device-key-auth.md`](plans/issue-74-step-1c-device-key-auth.md). |
| 12 | (tracking metadata) | n/a | Resolution log lives in §12 below. |

---

## 2. Gap: key derivation model — independent generation vs. SLIP-0010 HDKD from a sealed master seed

### Current (upstream `litentry/heima`)

Every long-lived TEE key is generated independently:

- **Shielding keypair** — generated at enclave startup from a hardware RNG, sealed in its own slot.
- **RSA JWT signing key** — generated via `RsaPrivateKey::new(&mut rng, 2048)` and persisted as a PKCS#1 DER file, on its own.
- **Per-user custodial wallet keys** — generated per-account via `pallet-bitacross` at account-creation time, each stored in its own sealed record keyed by `(chain, omni_account)`.

There is **no master seed**. OmniAccount *addresses* are deterministically derived via `OmniAccountConverter::convert(&identity, &client_id)`, but the underlying *private keys* are not.

### Desired (AgentKeys wiki + specs)

A single 256-bit master seed is generated once, at first enclave provisioning, from the hardware RNG and sealed. Every other long-lived key is deterministically derived from that seed via SLIP-0010 HDKD (BIP-32-style):

| Subkey                          | Derivation path                                     | Alg                                   | Consumer                               |
| ------------------------------- | --------------------------------------------------- | ------------------------------------- | -------------------------------------- |
| Shielding keypair               | `shielding/v1`                                      | Curve25519                            | Credential-blob encrypt/decrypt        |
| Session-JWT signing key         | `issuer/jwt/v1`                                     | ES256 (ECDSA P-256)                   | Sign 30-day session tokens (internal trust anchor; not on public JWKS). |
| OIDC-issuer signing key         | `oidc/issuer/v1`                                    | ES256 (ECDSA P-256)                   | Sign ≤5-min OIDC JWTs exchanged at AWS STS / GCP WIF / Ali RAM for cloud temp creds. Separate key so the rotatable public trust anchor is isolated from the session-JWT anchor. |
| Per-user wallet key             | `wallet/<chain>/<omni_account>/v1`                  | secp256k1 / ed25519 (per chain)       | Custodial wallet signing |
| Per-domain DKIM key             | `dkim/<domain>/v1`                                  | Ed25519                               | Outbound mail signing (Stage 6)        |

### Impact

- **New services multiply storage today.** Each new key surface (DKIM per domain, OIDC per audience, any future K8s / cloud-IdP signers) would have to add a new sealed-storage slot and its own key-lifecycle code. With HDKD, new surfaces are new derivation paths — no new storage, no new lifecycle.
- **Disaster recovery is painful.** If a sealed slot is lost or corrupted today, the affected key is gone and every downstream record has to be re-issued. With HDKD, a reprovisioned enclave that has the sealed master seed reconstructs every subkey deterministically.
- **Auditability is weaker.** With independent keys, the relationship between the root trust anchor and each operational key has to be tracked out of band. With HDKD, the root attestation + the derivation path is the proof.

### Migration path

**Option A — upstream patch (preferred).** Introduce a `TeeMasterSeed` sealed record; add a `derive_subkey(path)` helper in the TEE worker; port the shielding keypair, JWT signing key, and `pallet-bitacross` wallet key derivation to call through it. Existing independently-generated keys are grandfathered: the master seed is only consulted for newly-derived paths (DKIM, OIDC), so the migration is additive.

**Option B — AgentKeys fork.** If upstream is slow, keep the master-seed addition in our fork. This is the default for Stage 6 and Stage 7 if §2 + §5 haven't landed upstream by then.

**Option C — downgrade the spec.** We could drop HDKD from the desired architecture and live with independent keys forever. We're explicitly **not** choosing this — broker-not-proxy amplifies the key-surface problem (every new federated target is another key) and HDKD is the cheapest answer.

---

## 3. Gap: TEE does not expose an OIDC provider

### Current

The TEE issues JWTs for internal AgentKeys authentication, but:

- No `/.well-known/openid-configuration` discovery document is published.
- No JWKS endpoint is published.
- The `iss` claim on existing JWTs is not a resolvable HTTPS URL.
- The signing alg is RSA-2048 only; there is neither an ES256 path nor a separate OIDC-issuer key.

### Desired (Stage 7 — Generalized OIDC Provider)

The TEE's **OIDC-issuer signing key** (derivation path `oidc/issuer/v1`, alg **ES256**, separate from the session-JWT key at `issuer/jwt/v1`) backs a conforming OpenID Connect issuer:

- `iss = https://oidc.agentkeys.dev` (or per-tenant subdomain).
- `/.well-known/openid-configuration` served from a plain HTTPS endpoint (static file, no compute; just publishes the issuer URL, JWKS URL, supported algs).
- `/.well-known/jwks.json` serves the ES256 public key as a JWK.
- JWT claims include the user's OmniAccount wallet as a custom claim (`agentkeys_user_wallet`) so relying parties can gate access via `sts:TagSession` / `aws:PrincipalTag` conditions (see [`docs/wiki/tag-based-access.md`](../wiki/tag-based-access.md)).

### Impact

Without this, AWS / GCP / Azure / Ali Cloud / K8s cannot federate identity to the TEE. This is the single gating change for **every** broker-not-proxy integration the wiki describes: S3 knowledge base, SES inbound S3Action, cross-account AWS calls, everything. Stage 7 cannot ship without it.

### Migration path

- **Issuer key alg + key split:** migrate the session-JWT signing key from RSA-2048 to ES256 at `issuer/jwt/v1`, AND add a **separate** ES256 key at `oidc/issuer/v1` for OIDC federation. Two keys, same alg, different purposes: the session-JWT key is an internal TEE-only trust anchor (verified by TEE workers, not on a public JWKS); the OIDC-issuer key is on a public JWKS at `https://oidc.agentkeys.dev/.well-known/jwks.json`. Separation isolates OIDC-rotation cycles (driven by AWS cache windows) from session-token invalidation. (AWS IAM OIDC accepts RS256 and ES256, but not Ed25519 — verified directly from the AWS docs.)
- **Discovery document + JWKS:** static S3/CloudFront-served JSON; no TEE compute required for serving (compute is key-derivation-on-demand for JWKS rotation, which is rare).
- **Publish pipeline:** the TEE computes its own JWK from the derived OIDC public key; we mirror it to the discovery URL on rotation.
- **Session-JWT migration path:** existing RSA-2048 session tokens remain valid until their 30-day window expires; new tokens after the cut-over are ES256. Clients verify whichever matches the `alg` header. Two-week flag flip.

Depends on §2 (HDKD) landing first, because both the session-JWT key and the OIDC-issuer key are subkeys of the master seed.

---

## 4. Gap: no BYODKIM (TEE-held per-domain DKIM keys)

### Current

Outbound mail is not a Heima concern today — there is no DKIM signing anywhere in the TEE.

### Desired (Stage 6 — Federated Own Email)

- Per-domain Ed25519 DKIM signing keys (RFC 8463) derived at path `dkim/<domain>/v1`.
- Public key published as a DNS TXT record at `<selector>._domainkey.<domain>` (our hosted `agentkeys-email.io` zone for default users; the user's DNS for BYO domains).
- Outbound mail is DKIM-signed inside the TEE on the send path, then the DKIM-signed raw MIME is sent via AWS SES `SendRawEmail` (broker-not-proxy: SES is the delivery channel; signing is ours).

### Impact

Without BYODKIM in the TEE, the send path either (a) delegates signing to SES (AWS sees the plaintext content and controls the signing key — violates Rule #2) or (b) drops DKIM entirely (deliverability tanks and domain reputation is unclaimed).

### Migration path

Trivial once §2 lands: add the `dkim/<domain>/v1` derivation path, publish the pubkey via DNS at domain-provisioning time, wire a `sign_outbound_mail(mime, domain)` TEE entrypoint.

Depends on §2 (HDKD).

---

## 5. Gap: on-chain email pallets (`pallet-email-grants`, `pallet-email-audit`) do not exist

### Current

`pallet-bitacross` exists (for custodial wallets) and `pallet-secrets-vault` exists (for encrypted credential blobs), but there is no pallet for:

- **Email grants** — who is allowed to send from `<domain>` or read from `<inbox>` (the email equivalent of a credential scope).
- **Email audit** — per-operation append-only log of `send`, `read`, `attach-S3-key`, etc., keyed by `omni_account`.

### Desired

- `pallet-email-grants` — on-chain store of `(domain, omni_account, capability)` tuples; TEE consults it on every send/read before touching SES. Revocation is an extrinsic; enforcement is ≤ 1 block (same as credential revocation).
- `pallet-email-audit` — append-only audit log, identical shape to the credential audit log we already have. Every TEE-brokered email operation emits one extrinsic.

### Impact

Without these pallets, there is no on-chain source of truth for email authorization — violates Rule #1. We'd be running email with an in-TEE table, which (a) breaks the "chain is truth" invariant and (b) loses the public-verifiability property the credential pipeline depends on.

### Migration path

The shape of both pallets is mechanically similar to the existing credential-grants + credential-audit pallets, so this is mostly forking their code and renaming. Stage 6 blocker. No dependency on §2 or §3 — can land in parallel.

---

## 6. Gap: no session-tag propagation on TEE-minted JWTs into STS

### Current

The TEE mints JWTs with standard claims (`sub`, `typ`, `exp`, `aud`). There is no infrastructure for:

- Adding a custom `agentkeys_user_wallet` claim to the JWT (trivial — just claim encoding).
- Exposing that claim to AWS STS via `sts:TagSession` so AWS IAM can evaluate `aws:PrincipalTag/agentkeys_user_wallet` in bucket policies / KMS policies.

### Desired (Stage 6 + Stage 7)

The JWT the TEE mints carries `agentkeys_user_wallet = <child_wallet_address>` as a claim. The claim name is historical (from early design when the only identity was the user's OmniAccount); the value is the **child/agent wallet** so that per-agent compromise bounds the blast radius to that one agent's prefix rather than the whole user. When a client does `sts:AssumeRoleWithWebIdentity` with that JWT, STS extracts the claim and attaches it as a session tag. Downstream bucket policies and KMS policies pattern-match on `aws:PrincipalTag/agentkeys_user_wallet = ${aws:SourceIdentity}` or similar, giving us per-user (per-agent) isolation on shared cloud resources **without** per-user IAM roles.

See [`docs/wiki/tag-based-access.md`](../wiki/tag-based-access.md) for the full pattern.

### Impact

This is the mechanism that makes broker-not-proxy work on shared AWS resources. Without it, either (a) we provision one IAM role per user (doesn't scale — IAM role quotas + management overhead) or (b) we proxy every call through our infra (violates Rule #4).

### Migration path

- **TEE side:** extend the JWT claim set. Minor change.
- **AWS side:** role trust policies declare `sts:TagSession` is allowed; bucket/KMS policies reference `aws:PrincipalTag/agentkeys_user_wallet`. This is all AWS configuration, not Heima source.
- **OIDC side:** depends on §3 (OIDC provider) landing first so AWS IAM can trust the issuer at all.

---

## 7. Gap: no enclave-attested publication of issuer + shielding pubkeys to a public trust document

### Current

`register_enclave()` publishes pubkeys on chain, which is good for clients who can query the chain. It does **not** publish them in a form that arbitrary web-service trust stores (AWS IAM OIDC thumbprint list, GCP Workload Identity Federation issuer config, K8s OIDC discovery) can consume.

### Desired

- Per issuer pubkey, a JWK is published at a stable HTTPS URL.
- The JWK's signing attestation (DCAP quote) is either inline in the discovery document or served from a neighbouring URL, so a relying party can verify "this pubkey was generated inside an attested AgentKeys TEE" before adding it to their trust store.

### Impact

Without the discovery-side story, Stage 7 OIDC federation works but the security argument is weaker: AWS trusts our issuer URL, but a pivoted / compromised TEE could publish whatever pubkey it wants. With attested publication, compromise-to-impersonation requires also compromising the attestation pipeline.

### Migration path

Defer past Stage 7 — this is a hardening follow-up, not a Stage 6/7 blocker. Tracked here so it's not forgotten.

---

## 8. Gap: no `pallet-oidc-pubkeys` — OIDC trust is URL-only

### Current

Stage 7 OIDC federation's trust anchor is `https://oidc.agentkeys.dev` + TLS + JWKS signature. If the URL is hijacked (DNS compromise, CA misissuance, hosting takeover, deploy-pipeline compromise), an attacker can serve a rogue JWKS and mint arbitrary JWTs accepted by every downstream cloud. Heima has no on-chain authoritative registry of which OIDC-issuer pubkeys are currently valid. There is no way for a watchdog, a daemon, or a future chain-native relying party to check "is this JWKS still the legitimate one?"

### Desired (Stage 7b — URL-hijack defense)

A new pallet `pallet-oidc-pubkeys` holds the authoritative list:

```rust
// Storage
pub struct OidcKey {
    pub kid: BoundedVec<u8, ConstU32<64>>,
    pub pubkey: BoundedVec<u8, ConstU32<128>>,    // raw ES256 point, uncompressed
    pub attestation_quote: BoundedVec<u8, ConstU32<4096>>, // DCAP quote at registration time
    pub active_from: BlockNumber,
    pub active_until: BlockNumber,                // 0 = no expiry
    pub revoked_reason: Option<BoundedVec<u8, ConstU32<256>>>,
}

#[pallet::storage]
pub type OidcKeys<T: Config> = StorageMap<_, Blake2_128Concat, KeyId, OidcKey>;

// Extrinsics
fn register_oidc_key(
    origin: OriginFor<T>,
    kid: Vec<u8>,
    pubkey: Vec<u8>,
    attestation_quote: Vec<u8>,
    active_from: BlockNumber,
    active_until: BlockNumber,
) -> DispatchResult;
// Authorized origin: TEE-attested submitter only (reuse existing TEE-submitter check).

fn revoke_oidc_key(
    origin: OriginFor<T>,
    kid: Vec<u8>,
    reason: Vec<u8>,
) -> DispatchResult;
// Authorized origin: governance; intended for fast-track incident response.

// Queries (runtime API)
fn active_oidc_keys(at: BlockNumber) -> Vec<(KeyId, Pubkey)>;
fn get_oidc_key(kid: KeyId) -> Option<OidcKey>;

// Events
OidcKeyRegistered { kid, active_from, active_until }
OidcKeyRevoked    { kid, reason }
```

**Mock-server mirror** (for local dev and Stage 4/5 tests that must not require a real Heima node):

```
POST /mock/oidc-pubkeys/register   { kid, pubkey, quote, active_from, active_until }
POST /mock/oidc-pubkeys/revoke     { kid, reason }
GET  /mock/oidc-pubkeys/active     → [ { kid, pubkey } ]
GET  /mock/oidc-pubkeys/{kid}      → { kid, pubkey, quote, active_from, active_until, revoked_reason? }
```

The mock persists to SQLite (same pattern as the credential store). The daemon's dual-verify code path points at `/mock/oidc-pubkeys/active` under `AGENTKEYS_OIDC_REGISTRY_URL=http://127.0.0.1:8090/mock/oidc-pubkeys`.

### Impact

Without this pallet, `oidc.agentkeys.dev` is a single point of failure for the entire Stage 6/7 federation story. URL compromise is silent and total. Stage 7b's watchdog needs an authoritative "what should the JWKS say right now?" comparison source, and that source has to live somewhere trust can't be short-circuited by the same attack that compromised the URL. Chain is the only candidate.

### Migration path

- **Pallet landing:** net-new; no upstream grandfathering concerns. Heima-fork PR or upstream PR depending on Litentry's position on AgentKeys-specific pallets.
- **Deploy order:** pallet first, mock-server mirror second, watchdog third, daemon feature flag fourth. Each step is independently testable.
- **Rollback:** the feature is additive; disable the watchdog + flip the daemon feature flag off, and you're back at Stage 7's URL-only trust.

Depends on §3 (OIDC provider exists) landing first. No dependency on §2 (HDKD) — the pubkey field is algorithm-agnostic.

---

## 9. Gap: no `pallet-enclave-successors` — MRSIGNER rotation has no on-chain governance anchor

### Current

Heima has no on-chain list of authorized enclave MRSIGNERs. If we rotate the enclave-signing key (new MRSIGNER_B replaces MRSIGNER_A), the old enclave has no authoritative way to decide whether a peer claiming MRSIGNER_B is a legitimate successor during the attested-seed-handoff step. The choice devolves to hard-coded config or out-of-band operator coordination, both of which undermine Rule #1.

See the MRSIGNER-rotation discussion in earlier design review: under HDKD (gap §2), rotation reduces to a single attested seed handoff; the only thing it needs is a trusted answer to *"is MRSIGNER_B authorized?"*.

### Desired

A new small pallet `pallet-enclave-successors`:

```rust
pub struct AuthorizedMrSigner {
    pub mrsigner: [u8; 32],
    pub effective_from: BlockNumber,
    pub rationale_uri: BoundedVec<u8, ConstU32<256>>, // link to governance proposal / audit report
}

#[pallet::storage]
pub type AuthorizedMrSigners<T: Config> =
    StorageValue<_, BoundedVec<AuthorizedMrSigner, ConstU32<8>>, ValueQuery>;

fn authorize_mrsigner(
    origin: OriginFor<T>,
    mrsigner: [u8; 32],
    effective_from: BlockNumber,
    rationale_uri: Vec<u8>,
) -> DispatchResult;
// Authorized origin: governance (collective / referendum).

fn deauthorize_mrsigner(
    origin: OriginFor<T>,
    mrsigner: [u8; 32],
) -> DispatchResult;
// Authorized origin: governance. For removing a compromised signer.

fn authorized_mrsigners() -> Vec<[u8; 32]>;
```

**Mock-server mirror:**

```
POST /mock/enclave-successors/authorize   { mrsigner, effective_from, rationale_uri }
POST /mock/enclave-successors/deauthorize { mrsigner }
GET  /mock/enclave-successors              → [ mrsigner, ... ]
```

Used by the enclave startup code during MRSIGNER rotation: before the old enclave opens an attested TLS channel to a new enclave claiming MRSIGNER_B, it queries the chain's `authorized_mrsigners()` and confirms MRSIGNER_B is listed.

### Impact

Without the pallet, MRSIGNER rotation is either (a) impossible without a flag-day coordinated restart, or (b) gated on trust anchors that live outside the chain — both of which break Rule #1 and Rule #4. With the pallet, rotation is a routine governance extrinsic + attested seed handoff, and the derived-keys story (HDKD §2) makes everything downstream (JWKS, custodial wallets, DKIM DNS) continue working without changes.

### Migration path

- **Pallet landing:** net-new; small; governance-gated. No upstream compatibility concerns.
- **Usage deployment:** enclave startup code reads `authorized_mrsigners()` before accepting a successor's RA quote. This is a small change in the TEE worker — one pallet query + one comparison.
- **Companion doc:** "MRSIGNER rotation runbook" in Stage 7b's operator-facing documentation; covers governance proposal → pallet update → enclave coordination → grace window → old-enclave decommission.

Depends on §2 (HDKD) landing first, because the rotation is only cheap under HDKD (without HDKD, rotation is a full re-issuance of every sealed key).

---

## 10. Gap (NEW): signer-edge contract for the per-user wallet key

**Status:** PARTIAL — wire shape pinned, dev-stage backend deployed (PR #75); TEE-backed implementation tracked under issue #74 step 2.

### Current (post-PR #75)

The Heima TEE worker derives per-user custodial wallets internally
inside the enclave (per `pallet-bitacross` reference in §2). Outside
of Heima — in the AgentKeys broker / signer / daemon stack — there
was no equivalent service for an operator authenticated via
email/OAuth2 (no local crypto wallet) to obtain a deterministic EVM
wallet under the operator's `omni_account`.

PR #75 ([issue #74 step 1](plans/issue-74-dev-key-service-plan.md))
ships:
- The wire contract in [`signer-protocol.md`](signer-protocol.md):
  `POST /dev/derive-address` and `POST /dev/sign-message` with
  `omni_account` keying, error envelope, versioned HKDF derivation
  byte, future TEE attestation handshake.
- A dev-stage HKDF backend (`agentkeys-mock-server::dev_key_service`)
  loaded from `DEV_KEY_SERVICE_MASTER_SECRET`.
- A `SignerClient` trait + `HttpSignerClient` impl in
  `agentkeys-core` so the daemon treats the signer as opaque RPC.
- A TEE-stub conformance test that runs the daemon's assertions
  against an in-memory fixture mirroring the wire contract.

### Desired (Heima parity)

A TEE-derived custodial wallet keyed on `omni_account`:
- Master secret generated and sealed inside the enclave at first
  boot.
- Remote attestation so the daemon can verify the signer is genuine
  before sending its first request.
- Sealed-data persistence (no plain env-var master secret).
- Logs every signing operation with `(omni_account, message_hash)`,
  no secret material.

### Impact

- **Today's gap (post-PR #75):** the dev-stage signer's master
  secret lives in `/etc/agentkeys/dev-key-service.env` (mode 0600).
  Compromise of the broker host = full master-secret leak = every
  wallet for every operator is forge-able forever. This is the
  "DEV ONLY — replace with TEE" warning baked into the module-doc.
- **What closing the gap unlocks:** the same threat properties Heima
  TEE wallets have today (sealed seed, attested boot, host-root
  insufficient for compromise) become available to AgentKeys
  operators not authenticating against the Heima TEE. This is what
  makes the federated-cloud-broker story production-grade.

### Migration path

Issue #74 step 2 (separate issue, planned). Same wire shape; only
the backend behind `signer.<zone>` changes. Daemon, CLI, broker, and
operator-runbook stay unchanged at the swap.

The HKDF dev backend is intentionally short-lived. Production
deployments that ship before step 2 lands MUST treat
`DEV_KEY_SERVICE_MASTER_SECRET` as an incident-class secret and not
as a normal config value.

---

## 11. Gap (NEW): per-request crypto auth on the signer edge

**Status:** PLANNED — design in [`plans/issue-74-step-1c-device-key-auth.md`](plans/issue-74-step-1c-device-key-auth.md); CEO review pending.

### Current

PR #75 deploys `/dev/*` with no HTTP-layer auth (loopback-only, per
`signer-protocol.md` §"What's intentionally out of scope at v0").
Issue #74 step 1b will add bearer-JWT auth (broker mints session JWT
→ signer verifies signature against broker pubkey + asserts
`claim.omni_account == body.omni_account`). That is a strict
improvement over no auth, but the broker becomes a single point of
compromise: forge a session JWT at the broker → impersonate any
omni at the signer.

Heima already faced this design question. Its `ClientAuth` enum (in
`tee-worker/omni-executor/primitives/src/auth.rs:212-227` per
[`docs/research/option-a-port-dexs-backend.md`](../research/option-a-port-dexs-backend.md))
classifies operations into three tiers:

- `JwtBearer` — static long-lived TEE-RSA JWT (low-stakes reads).
- `BackendSigned` — backend signs the userOp; TEE verifies the
  backend ECDSA signature.
- `EvmSiweSigned` — caller produces a fresh EIP-191 signature on the
  request payload itself (high-stakes ops).

Each variant is deployed for a different stakes tier. Heima
recognized that bearer alone was insufficient for high-stakes
operations.

### Desired

Issue #74 step 1c proposes a single auth scheme that subsumes all
three Heima tiers:

- **Init**: daemon generates a device keypair locally; identity
  ceremony (email-link / OAuth2 / EVM-wallet / WebAuthn) binds the
  device pubkey to the omni at the broker.
- **Per request**: daemon signs `(omni || message_hex || nonce ||
  timestamp)` with the device key; signer verifies the per-request
  signature against the device pubkey extracted from the session JWT
  claim.
- **Trust shape**: signer never trusts the broker as a transitive
  authenticator. Broker compromise post-init does not enable
  forging new sign requests.

This is **strictly stronger** than all three Heima `ClientAuth`
variants:

| Heima variant | Step-1c equivalent | Why stronger |
|---|---|---|
| `JwtBearer` | Step-1b's bearer auth (replaced by 1c) | Per-request crypto kills the replay window. |
| `BackendSigned` | Step-1c device-key auth | The "backend" becomes the user's local device, not the broker — user-controlled key, not backend-controlled. |
| `EvmSiweSigned` | Step-1c init binding for `evm` omnis | Same crypto guarantees, but one-shot user-key sign at init then automatic device-key signing per call (no MetaMask popup per request). |

Identity-type uniform: same per-request signature shape works for
`evm`, `email`, `oauth2_google`, `passkey` — only the init-time
binding ceremony differs. Heima today only has the per-request crypto
path (`EvmSiweSigned`) for EVM identities; email/OAuth2 identities
fall back to `JwtBearer`.

### Impact

- **Closes the broker-as-SPOF risk on the signer call surface.**
  Broker can be fully owned and the attacker cannot sign as any
  user.
- **TEE swap-ready** (gap §10). The TEE worker (issue #74 step 2)
  inherits the device-key auth scheme without changes — the TEE
  doesn't need to call out to the broker on every sign request.
- **Aligned with web3 prior art:** WebAuthn / passkey, EIP-7702
  session keys, ERC-4337 session keys all use the same primitive
  (high-friction identity verification authorizes a low-friction
  signing key). The pattern is well-validated outside AgentKeys.

### Migration path

Issue #74 step 1c (separate issue, GitHub
[#76](https://github.com/litentry/agentKeys/issues/76)). Eleven
implementation stages laid out in the plan doc:

0. `signer-protocol.md` v0.2 — wire contract revision
1. `agentkeys-core::device_key` module
2-4. Broker session JWT mint + identity-ceremony device-pubkey binding
5. dev_key_service handlers — per-request sig verification
6. `init_flow` updates — device-key registration
7. `HttpSignerClient` — send JWT + device sig
8. Deprecate the bearer-JWT-only path (step 1b)
9. TEE-stub conformance test extended
10. Demo doc + operator runbook updated
11. Live broker host redeploy + smoke walkthrough

Rough total: ~1200 LOC + protocol-doc revision + 11 stage-gated test
waves. Blocks the TEE worker (gap §10) because step 2's threat
model assumes the signer can't be tricked by a compromised broker
— exactly what step 1c delivers.

---

## 12. Tracking

- Each gap is owned as a separate issue in the `litentry/agentKeys` repo. PR #75 / issue #76 close §10 and queue §11 respectively.
- When a gap closes, mark the section **RESOLVED** with the merge commit(s) and the resolution path (A/B/C from §2).
- When a new delta is discovered, append a new section here before revising the wiki, so the wiki stays "desired" and this doc stays "gap".

### Resolution log

| Gap | Date | Status change | Reference |
|---|---|---|---|
| §3 OIDC provider | 2026-04-28 | GAP → RESOLVED IN-TREE | PR #61 (broker phase 2 OIDC issuer) |
| §6 PrincipalTag JWT claim | 2026-04-28 | GAP → RESOLVED IN-TREE | PR #61 + cloud-setup §4.4 |
| §10 signer-edge contract | 2026-05-08 | (NEW) → PARTIAL | PR #75 (issue #74 step 1) |
| §11 device-key auth | 2026-05-09 | (NEW) → PLANNED | issue [#76](https://github.com/litentry/agentKeys/issues/76) |
