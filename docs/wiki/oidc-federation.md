# TEE as OIDC Identity Provider — Universal Federation Pattern

**Status:** design (2026-04-19)
**Scope:** how AgentKeys' TEE becomes a conforming OpenID Connect identity provider, letting the TEE's sealed signing key federate into any cloud that accepts external OIDC (AWS, GCP, Azure, Snowflake, Kubernetes, …) with no static secrets stored anywhere in AgentKeys.
**Companion specs:** `docs/spec/ses-email-architecture.md`, `docs/spec/email-signing-backends.md`
**Related wiki:** [email-system](email-system), [tag-based-access](tag-based-access), [hosted-first](hosted-first), [knowledge-storage](knowledge-storage), [blockchain-tee-architecture](blockchain-tee-architecture)

---

## TL;DR

**Architectural property delivered:** *"No static cloud credentials anywhere in AgentKeys infrastructure."*

We expose the TEE as a conforming OIDC identity provider at `https://oidc.agentkeys.dev` (or similar). The TEE holds one ES256 (ECDSA P-256) signing key, derived deterministically from the TEE master seed. Every cloud we integrate with — AWS, GCP, Azure, Snowflake, Kubernetes, and anything else that speaks OIDC federation — trusts this provider once; from then on, every credential for that cloud is minted on-demand, bound to a fresh attestation, and typically lives ≤1 hour.

One JWKS, one issuer URL, N consumers. We never hold AWS access keys, GCP service-account JSON, Azure client secrets, or anything similar at rest. Ever.

---

## Why this is the right generalization

Every major cloud accepts external OIDC tokens for workload federation. They standardized on the same model independently:

| Consumer | Federation primitive | Max session |
|---|---|---|
| **AWS IAM** | `CreateOpenIDConnectProvider` + `sts:AssumeRoleWithWebIdentity` | 12 h |
| **GCP Workload Identity Federation** | `iam.googleapis.com/.../workloadIdentityPools/.../providers/...` | 1 h (default) |
| **Azure AD Workload Identity Federation** | Managed identity with federated credential trust | 1 h |
| **Snowflake External OAuth** | `OAUTH_ISSUER` + `OAUTH_JWS_KEYS_URL` | configurable |
| **Kubernetes ServiceAccount projection** | `--oidc-issuer-url` kube-apiserver flag | 1 h |
| **GitLab/Terraform/Jenkins/CircleCI external identity** | Generic OIDC federation APIs | minutes to hours |

They all accept the same input: a JWT signed by a key listed in our JWKS, with standard claims (`iss`, `sub`, `aud`, `exp`, `iat`). Build once, integrate many.

---

## Key requirements — verbatim from AWS docs

AWS is the strictest of the consumers, so meeting AWS's requirements makes us compatible with the rest.

From [`IAM/id_roles_providers_create_oidc.html`](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html) and [`STS/API_AssumeRoleWithWebIdentity.html`](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html):

| Requirement | Constraint | Verbatim source |
|---|---|---|
| Issuer URL | Must begin with `https://`; path components allowed; **no query parameters**; **no port number**; case-sensitive | "URL must begin with https://" + "path components are allowed but query parameters are not" |
| Discovery endpoint | Must serve `/.well-known/openid-configuration` JSON per OIDC standard | "Add /.well-known/openid-configuration to the end of your OIDC identity provider's URL" |
| JWKS | Referenced via `jwks_uri` in discovery doc; max **100 RSA + 100 EC keys** per provider | "must contain at least one key and can have a maximum of 100 RSA keys and 100 EC keys" |
| **Signing algorithms** | **`RS256, RS384, RS512, ES256, ES384, ES512`** only. **Ed25519 / EdDSA is NOT accepted.** | "Tokens must be signed using either RSA keys (RS256, RS384, or RS512) or ECDSA keys (ES256, ES384, or ES512)" |
| TLS certificate | AWS uses its trusted-root-CA library first; falls back to thumbprint only when cert isn't public-CA-signed or TLS 1.3 is required | "AWS secures communication with OIDC identity providers (IdPs) using our library of trusted root certificate authorities (CAs) to verify the JSON Web Key Set (JWKS) endpoint's TLS certificate" |
| Required claims | `iss` (must match provider URL), `aud`, `iat`, `sub` | "Claims must include a value for iat that represents the time that the ID token is issued" |
| Token max size | 20,000 characters | "Maximum length of 20000" |
| Temp-cred duration | 900s (15m) – 43200s (12h); default 3600s (1h) | "The value can range from 900 seconds (15 minutes) up to the maximum session duration setting" |

### Critical finding: key algorithm

**AWS does not accept Ed25519 for OIDC federation.** The docs explicitly list RSA (RS256/384/512) and ECDSA (ES256/384/512) only. This forces the OIDC-issuer key to be **ECDSA P-256 (ES256)**, regardless of what we use for DKIM or other purposes.

ES256 is deterministically derivable from the TEE master seed via SLIP-0010 (the BIP-32 extension that covers secp256r1 / P-256 / NIST P-256). The same derivation mechanism the TEE already uses for custodial wallet keys. Performance: ~50 µs sign, ~150 µs verify. Sub-millisecond.

---

## Design: two derived key families, two purposes

```
TEE master seed  (sealed; one per enclave; disaster-recovery root)
 ├── derive("dkim/<domain>/<v>")    → Ed25519    (DKIM signing, per custom domain)
 │                                                 RFC 8463; we control the recipient side
 │                                                 Ed25519 is our choice (fast, clean)
 │
 └── derive("oidc/issuer/<v>")      → ES256      (OIDC-issuer JWT signing, singleton)
                                                   Forced by AWS/GCP/Azure OIDC specs
                                                   One key serves ALL cloud consumers
```

Both algorithms deterministically derivable. Both sealed inside the TEE. Both rotated via path-version bump. Different algorithms because different protocols demand them; the derivation pipeline is uniform.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         TEE ENCLAVE                                 │
│                                                                     │
│   Master seed (sealed)                                              │
│     └── derive("oidc/issuer/v1") → ES256 private key (never leaves) │
│                                                                     │
│   mint_oidc_jwt(claims) →                                           │
│     1. verify caller session                                        │
│     2. check grant authorizes this audience                         │
│     3. build JWT { iss, sub, aud, exp, iat, agentkeys_* claims }    │
│     4. sign with ES256 key                                          │
│     5. emit on-chain audit extrinsic                                │
│     6. return JWT                                                   │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ ES256 JWT (5 min TTL typical)
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  HTTPS proxy (thin, stateless, static content)                      │
│                                                                     │
│  Serves three static endpoints with Let's Encrypt cert:             │
│                                                                     │
│   https://oidc.agentkeys.dev/                                       │
│     /.well-known/openid-configuration   → static JSON               │
│     /.well-known/jwks.json              → static JWKS (ES256 pubkey)│
│                                                                     │
│  Does NOT hold any private key. Compromise = attackers see public   │
│  keys only (useless). TEE remains the only signer.                  │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ trusted once per consumer
                              ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  AWS IAM         │  │  GCP Workload    │  │  Azure / Snow /  │
│  OIDC Provider   │  │  Identity Fed    │  │  K8s / etc.      │
│                  │  │                  │  │                  │
│  sts:AssumeRole- │  │  federated       │  │  (each cloud's   │
│  WithWebIdentity │  │  credentials     │  │   OIDC endpoint) │
└──────────────────┘  └──────────────────┘  └──────────────────┘
          │                    │                     │
          ▼                    ▼                     ▼
   temp creds ≤12h      temp creds ≤1h        temp creds ≤varies
      │                    │                     │
      └────────────────────┴─────────────────────┘
                           │
                           ▼
              agent / daemon uses temp creds
              for actual service API calls (SES, etc.)
```

The TEE mints one JWT; the consumer mints temp creds for its own service. Credentials live minutes to hours, always tied to a fresh TEE-minted JWT.

---

## JWT shape

```json5
{
  "iss":  "https://oidc.agentkeys.dev",
  "sub":  "enclave:<mrenclave>:<mrsigner>:agent:<child_wallet>",
  "aud":  "sts.amazonaws.com",          // or "//iam.googleapis.com/..." for GCP, etc.
  "iat":  1745000000,
  "exp":  1745000300,                   // 5 minutes
  "nbf":  1745000000,

  // AgentKeys-specific claims — consumer's trust policy can condition on these
  "agentkeys_attested_at":   "2026-04-19T00:00:00Z",
  "agentkeys_enclave_tier":  "production",
  "agentkeys_child_wallet":  "0x...",   // which child the credential is for
  "agentkeys_grant_id":      "grant_...", // which grant authorized this mint
  "agentkeys_operation":     "ses.send", // what op the credential will be used for
}
```

`sub` is formatted to uniquely identify *which enclave* + *which agent inside it* requested the token. Consumer's trust policy can condition on `sub` patterns (*"only enclaves matching mrenclave=X can assume this role"*) and on `agentkeys_*` claims (*"only when operation=ses.send"*).

Claims are auditable on-chain via the audit extrinsic emitted at mint time — every OIDC JWT minted has a corresponding on-chain event.

### The `agentkeys_user_wallet` claim is load-bearing for per-user isolation

The `agentkeys_user_wallet` claim is **the key that unlocks per-user isolation on shared cloud resources**. Through AWS `sts:TagSession` (or GCP attribute mapping, or Ali RAM OIDC conditions), this claim surfaces in the assumed role's session as a PrincipalTag. Resource policies (S3 bucket policies, IAM role conditions, GCS IAM conditions) then condition on the tag to enforce "this session can only touch this user's prefix."

**One bucket, N users, cryptographic separation via the tag. One role, N users, one trust policy.** See [tag-based-access](tag-based-access) for the full mechanics — it's the companion pattern that makes this OIDC provider safe to point at a shared resource.

Without the tag claim, we'd either need one IAM role per user (doesn't scale past a few thousand) or one bucket per user (expensive, quota-limited) or our backend proxying every operation (violates Rule #4 broker-not-proxy). With the tag claim, none of those compromises are needed.

---

## Consumer-registration recipes

### AWS IAM

```bash
aws iam create-open-id-connect-provider \
  --url https://oidc.agentkeys.dev \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list '' # omit if using public-CA cert (Let's Encrypt etc.)

# Trust policy on the role to assume:
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::<acct>:oidc-provider/oidc.agentkeys.dev" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals":   { "oidc.agentkeys.dev:aud": "sts.amazonaws.com" },
      "StringLike":     { "oidc.agentkeys.dev:sub": "enclave:<mrenclave>:*" }
    }
  }]
}
```

### GCP Workload Identity Federation

```bash
gcloud iam workload-identity-pools providers create-oidc agentkeys-oidc \
  --workload-identity-pool=agentkeys-pool \
  --issuer-uri=https://oidc.agentkeys.dev \
  --attribute-mapping='google.subject=assertion.sub,attribute.enclave=assertion.agentkeys_enclave_tier'
```

### Azure / Snowflake / K8s

Same pattern — register `https://oidc.agentkeys.dev` as the issuer URL, trust the JWKS, condition on the claims our JWTs emit.

**One provider, N registrations.** No code changes per consumer.

---

## Rotation

```
ES256 key rotation:
  1. TEE starts deriving new key at oidc/issuer/v2 (old at v1 still usable)
  2. Update static JWKS to contain BOTH public keys (kid="v1" and kid="v2")
  3. All new JWTs signed with v2; sealed v1 key kept for grace window
  4. Consumers (AWS etc.) refresh JWKS on their cache cycle — both keys accepted
  5. After grace window (~24h), delete sealed v1; update JWKS to drop v1
```

Zero-downtime rotation. Same recipe as any OIDC provider's key rotation.

DKIM rotation works identically, independently, per-domain.

---

## Alignment with `blockchain-tee-architecture.md` rules

Verified end-to-end against the four architectural rules in the repo's [`wiki/blockchain-tee-architecture.md`](blockchain-tee-architecture):

| Rule | How this pattern preserves it |
|---|---|
| **#1 Chain stores everything persistent** | Every OIDC JWT mint emits an on-chain audit extrinsic with `(child, audience, operation, timestamp)`. Grants that authorize mints are on-chain. Revocations are on-chain. No persistent state lives only on our infrastructure. |
| **#2 TEE holds all private keys** | ES256 issuer key is sealed, derived from master seed at `oidc/issuer/v1`, never extractable. The thin proxy that serves the JWKS holds public keys only. |
| **#3 Clients hold only bearer tokens** | JWTs are 5-minute bearers; the daemon uses them once to mint temp cloud creds (≤1h) via the remote STS and discards them. No long-lived material on the daemon. |
| **#4 (proposed) Credential broker, not operation proxy** | The daemon calls AWS/GCP/Ali Cloud APIs directly using the temp creds. Our backend mints tokens; it does not proxy cloud operations. Per-operation compute on our side is zero. |
| **Per-user isolation** | Enforced via the `agentkeys_user_wallet` claim → session tag → resource-policy condition. Cryptographically hard-walled at the cloud level. See [tag-based-access](tag-based-access). |

## Threat model delta vs sealed long-lived credentials

| Threat | Sealed AWS IAM access keys inside TEE | TEE-backed OIDC federation |
|---|---|---|
| TEE fully compromised (hardware attack) | All cloud creds exposed; permanent blast radius | All JWT-signing capability exposed; attacker mints arbitrary JWTs for 12h at a time; STILL bad but bounded by temp-cred TTLs |
| TEE restart / redeploy | Keys restored from sealed storage; no disruption | Keys restored from master seed derivation; issuer URL + JWKS unchanged |
| JWKS proxy compromised | N/A | Attacker sees public key only (useless); TEE still controls signing |
| Single cloud's temp cred leaked | Full permanent AWS access | ≤12h window for that one role; all other clouds unaffected |
| Attacker learns an old OIDC JWT | Can use until its 5-min expiry on the one audience it was minted for | Same |
| Need to rotate credentials | Mint new IAM key per cloud, redeploy, migrate | Bump path version, update JWKS, done |

Net: **the "blast radius on TEE compromise" property is unchanged from the existing architecture**, but the "blast radius on anything short of TEE compromise" drops to near-zero for all cloud credentials.

---

## Build cost

Minimal, most of the primitives already exist:

| Component | Cost |
|---|---|
| ES256 key derivation inside TEE | Trivial — reuse the SLIP-0010 primitive the custodial wallet keys already use. 1 day. |
| JWT mint function inside TEE | Well-understood; libraries exist. Need to audit for constant-time. 2 days. |
| Thin HTTPS proxy (nginx + static files) + Let's Encrypt cert | 1 day including DNS setup. |
| `/.well-known/openid-configuration` + `/.well-known/jwks.json` static generation | 0.5 day. |
| First consumer registration (AWS) + end-to-end test | 1 day. |
| Second consumer registration (GCP) to validate the generalization | 0.5 day. |

**Total: ~1 week** for a fully generalized OIDC provider that replaces every static cloud credential we'd otherwise hold.

---

## What this enables beyond email

Every future cloud-service integration we build inherits this property for free:

- **Google Drive / Docs / Calendar** (v0.2+) — federate via GCP Workload Identity into a scoped Google service account
- **Snowflake / BigQuery** analytics — federate for per-agent data access
- **Third-party agent APIs** that accept OIDC — direct federation, no secret to store
- **On-chain payment rails** (x402 on Base) — the ES256 JWTs can also authenticate HTTP payments if we extend the pattern
- **Enterprise SSO integration** — customers can configure their IdP to trust our OIDC issuer for specific roles

The pattern is the final piece of the "no long-lived secrets" architecture story. Every service AgentKeys touches gets a credential minted on demand, attested at the TEE boundary, auditable on-chain, expiring within an hour.

---

## Open items

- **Issuer hostname decision.** `oidc.agentkeys.dev`? `tee.agentkeys.io/oidc/`? Needs to be a stable public-CA-certed HTTPS endpoint we control. Suggest: `oidc.agentkeys.dev` as a subdomain we never repurpose.
- **First-cut enclave identity format in `sub`.** Propose `enclave:<mrenclave>:<mrsigner>:agent:<child_wallet>` as the concrete form. Consumer trust policies condition on `enclave:<mrenclave>:<mrsigner>:*` to pin a specific enclave build.
- **Multi-tenant enterprise deployments.** Do enterprises want their own OIDC-issuer key? Probably yes. Extension: `derive("oidc/tenant/<id>/v1")` gives each tenant their own issuer URL (`https://oidc.agentkeys.dev/tenant/<id>/`) with its own JWKS. Same mechanism, bounded blast radius per tenant.
- **Kubernetes-native audience** — our JWTs might also directly satisfy K8s ServiceAccount projection, enabling pods to inherit our enclave identity without any wrapper. Worth exploring in v0.2.
- **On-chain record of active OIDC-issuer keys.** Should the current JWKS fingerprint be recorded on-chain so external verifiers can validate "this JWT was signed by the correct TEE-era key"? Adds an extra audit anchor. Tracked as a future enhancement.

---

## Cross-references

- `docs/spec/ses-email-architecture.md` §9 (AWS SES primitives) — inherits this federation pattern for SES access
- `docs/spec/ses-email-architecture.md` §11 (three-layer abstraction) — the OIDC broker is a TokenAuthority operation
- `docs/spec/email-signing-backends.md` — SES backend's authority layer uses this federation
- [email-system](email-system) — high-level email system architecture
- [blockchain-tee-architecture](blockchain-tee-architecture) §1 rule #2 — "TEE holds all private keys"; this spec makes it literally true for cloud credentials too
- [session-token](session-token) — the 30-day bearer token at the AgentKeys layer; OIDC JWTs are ~5-minute tokens at the federation layer
- [key-security](key-security) — two-tier storage model; OIDC-issuer key is another TEE-sealed key alongside shielding + JWT + DKIM + custodial wallets

### AWS primary sources

- [`IAM/id_roles_providers_create_oidc.html`](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html) — OIDC provider creation, discovery-doc requirements, JWKS constraints
- [`STS/API_AssumeRoleWithWebIdentity.html`](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html) — federation API, accepted signing algorithms, session duration
- RFC 8037 — CFRG elliptic curves for JOSE (defines EdDSA/Ed25519 JWS; AWS chose not to support)
- RFC 8463 — Ed25519 DKIM (what we do use for outbound mail)
- SLIP-0010 — deterministic key derivation for ECDSA P-256 and Ed25519 from a master seed

