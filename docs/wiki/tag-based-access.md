---
title: "Tag-Based Access Control — PrincipalTags from JWT Claims for Per-User Isolation"
tags: ["tag-based-access-control", "principal-tag", "session-tag", "oidc", "aws", "iam", "gcp", "per-user-isolation", "security", "attack-surface"]
created: 2026-04-19T10:08:52.043Z
updated: 2026-04-19T10:08:52.043Z
sources: []
links: ["hosted-first.md", "oidc-federation.md", "email-system.md", "knowledge-storage.md"]
category: pattern
confidence: medium
schemaVersion: 1
---

# Tag-Based Access Control — PrincipalTags from JWT Claims for Per-User Isolation


**Status:** pattern (2026-04-19)
**Scope:** how AgentKeys enforces per-user isolation on shared cloud resources (one S3 bucket, one GCS shared drive, one OSS bucket) when many users' data coexists — **without** needing per-user IAM roles or per-user buckets.

---

## TL;DR

> **JWT carries the user's wallet as a claim → AWS STS maps it to a session tag → bucket policy conditions on the tag.** One bucket holds every user's data, but each user can only access their own prefix. The cloud enforces it, not our code.
>
> Same mechanism exists in GCP (Workload Identity Federation attribute mapping), Ali Cloud (RAM OIDC condition), Azure AD (federated credential + RBAC conditions). Our OIDC provider emits the claim once; each cloud consumer enforces via its native primitive.

This is the mechanism that makes [hosted-first](hosted-first) secure at scale. Without it, either (a) every user needs their own IAM role (doesn't scale past a few thousand users), (b) every user needs their own bucket (expensive at scale), or (c) our backend proxies every op (violates the broker-not-proxy principle).

---

## The shape of the pattern

```
TEE Authority (mint step):
  {
    iss: "https://oidc.agentkeys.dev",
    sub: "enclave:<mrenclave>:<mrsigner>:agent:0xABC",   // child wallet; three-segment enclave identity (build hash + signer hash) lets relying parties pin to a specific build, a specific signer, or both — see §"Why three segments in sub"
    aud: "sts.amazonaws.com",
    agentkeys_user_wallet: "0xABC",            // <<<< tag-claim
    agentkeys_inbox:       "xyz123@agentkeys-email.io",
    agentkeys_operation:   "s3.read"
  }
  → signed ES256 JWT

AWS STS (exchange step):
  POST sts:AssumeRoleWithWebIdentity
    WebIdentityToken = <JWT>
    RoleArn = arn:aws:iam::<acct>:role/agentkeys-data-role
  → validates JWT via our JWKS
  → maps JWT claim agentkeys_user_wallet → session tag (PrincipalTag)
  → returns temp creds (AccessKey, SecretKey, SessionToken)

Daemon (use step):
  s3.getObject(Bucket="agentkeys-mail", Key="0xABC/inbox/msg-1.eml")
  → SigV4-signed with temp creds

S3 (enforce step):
  looks up the session's tags → PrincipalTag/agentkeys_user_wallet = "0xABC"
  evaluates bucket policy:
    Condition: StringLike {
      "s3:prefix": "${aws:PrincipalTag/agentkeys_user_wallet}/*"
    }
  → matches → allowed
  → if user attempted "0xB.../..." prefix, fails → denied
```

At no point does our backend check "does user A own this prefix?" — AWS does it by cryptographic comparison of the session tag to the resource prefix. One bucket, N users, hard-walled.

---

## Concrete AWS configuration

### 1. OIDC provider with tag-supporting claim

Our discovery doc lists the custom claims:

```json
{
  "issuer": "https://oidc.agentkeys.dev",
  "jwks_uri": "https://oidc.agentkeys.dev/.well-known/jwks.json",
  "claims_supported": [
    "aud", "iat", "iss", "sub", "exp",
    "agentkeys_user_wallet",
    "agentkeys_inbox",
    "agentkeys_operation",
    "agentkeys_grant_id"
  ],
  "id_token_signing_alg_values_supported": ["ES256"]
}
```

### 2. IAM role trust policy — allow JWT if claim is present

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.agentkeys.dev"
    },
    "Action": [
      "sts:AssumeRoleWithWebIdentity",
      "sts:TagSession"
    ],
    "Condition": {
      "StringEquals": {
        "oidc.agentkeys.dev:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "oidc.agentkeys.dev:sub": "enclave:<mrenclave>:<mrsigner>:*"
      },
      "StringNotEquals": {
        "aws:RequestTag/agentkeys_user_wallet": ""
      }
    }
  }]
}
```

Key points:

- `sts:TagSession` is required to grant the role permission to receive tags from the JWT claim.
- `StringNotEquals aws:RequestTag/agentkeys_user_wallet ""` — reject JWTs that don't carry the isolation claim (belt-and-suspenders; our TEE always sets it, but this catches misconfigurations).
- `sub` pattern-match pins the JWT to a specific enclave build (`mrenclave`) *and* signer (`mrsigner`). Attackers with a different enclave or a different signer can't assume the role. See §"Why three segments in `sub`" below for the three pin-modes operators can choose.

### 2a. Why three segments in `sub` (`mrenclave` + `mrsigner`)

Intel SGX enclaves carry two identities:

- `mrenclave` — hash of the enclave binary. Changes every build.
- `mrsigner` — hash of the public key that signed the enclave. Stable across builds from the same signing identity.

Publishing both in `sub` lets each relying party pick its pin policy without any change on our side:

| Pin policy | Trust-policy pattern | Effect |
|---|---|---|
| **Strict (exact build)** | `"enclave:<mrenclave_v1>:*:*"` | Only enclave build v1 can assume the role. Every upgrade requires policy update. |
| **Loose (any build from our signer)** | `"enclave:*:<mrsigner>:*"` | Any signed build auto-accepts. Upgrades roll without policy changes — but a compromised build still signed by us would also pass. |
| **Explicit (both, belt-and-suspenders)** | `"enclave:<mrenclave_v1>:<mrsigner>:*"` | Exact build from exact signer. Strongest. |

If `mrsigner` were omitted from `sub`, relying parties lose the *"any build from our signer"* option — every enclave upgrade becomes a fleet-wide trust-policy rewrite. Including it costs nothing (an extra 32-hex-char segment in one claim) and hands the operator the full policy spectrum.

### 3. Role's attribute-mapping for session tags

During `AssumeRoleWithWebIdentity`, AWS maps principal tags declared in the OIDC provider to session tags automatically when the provider's `claims_supported` includes them and the role permits `sts:TagSession`. Alternatively, attributes can be mapped explicitly in the IAM identity provider configuration.

### 4. Bucket policy on the shared `agentkeys-mail` bucket

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowListOwnPrefix",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/agentkeys-data-role" },
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::agentkeys-mail",
      "Condition": {
        "StringLike": {
          "s3:prefix": [
            "${aws:PrincipalTag/agentkeys_user_wallet}/*"
          ]
        }
      }
    },
    {
      "Sid": "AllowCrudOwnPrefix",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/agentkeys-data-role" },
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::agentkeys-mail/${aws:PrincipalTag/agentkeys_user_wallet}/*"
    },
    {
      "Sid": "DenyEverythingElse",
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/agentkeys-data-role" },
      "NotAction": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
      "Resource": "*"
    }
  ]
}
```

Every user assumes the **same role** — `agentkeys-data-role`. But each session carries a different PrincipalTag derived from their JWT claim, and the bucket policy expands `${aws:PrincipalTag/agentkeys_user_wallet}` per session. User A with tag `0xABC` sees only `agentkeys-mail/0xABC/*`. User B with tag `0xBEEF` sees only `agentkeys-mail/0xBEEF/*`. Cryptographic separation, zero code on our side.

---

## Equivalent mechanisms across clouds

| Cloud | Claim → tag mapping | Condition key |
|---|---|---|
| **AWS IAM + STS** | `sts:TagSession` action + `id_token_signing_alg_values_supported` includes claim | `aws:PrincipalTag/<claim>` |
| **GCP Workload Identity Federation** | Attribute mapping in the provider config: `attribute.user_wallet = assertion.agentkeys_user_wallet` | Resource IAM condition: `request.auth.claims['agentkeys_user_wallet']` or `request.auth.claims.agentkeys_user_wallet` |
| **Ali Cloud RAM OIDC** | `oidc:token.iss` and `oidc:token.sub` exposed natively; custom claims via `oidc:iss/<claim-name>` | `oidc:<claim-name>` in condition |
| **Azure AD Federated Credential** | Claims from external OIDC tokens surface through `x-ms-edov` or equivalent; role assignments via RBAC conditions | RBAC condition: `@Resource[...].Principal.UserId` |

One OIDC JWT with the `agentkeys_user_wallet` claim works across all four. Each cloud enforces per-user isolation with its native condition primitive on whatever resource (S3 bucket, GCS bucket, OSS bucket, Blob Storage container) we point it at.

The abstraction we expose to agents is identical — *"read your inbox"* / *"write your memory"* — and the cloud they land on is a deployment-config choice, not an architectural branch.

---

## What this solves vs alternatives

| Approach | Per-user isolation | Per-user state on our side | Ops burden | Scales to |
|---|---|---|---|---|
| **PrincipalTag via OIDC claims (this pattern)** | Enforced cryptographically by the cloud | Zero — one role, one bucket, N claims | Zero per-user | Millions |
| Per-user IAM role | Enforced by IAM | One role per user | O(users) role creation | Thousands (AWS role count limits) |
| Per-user bucket | Enforced by bucket ownership | One bucket per user | O(users) bucket creation + policy | Limited by AWS bucket-count quotas |
| Our backend proxies every op | App-layer check | All ops flow through our code | Compute cost grows with ops | Unbounded only if we throw money at Lambda |
| Per-user OAuth app | Each user has own credential | Encrypted refresh token per user | Per-user OAuth flow | Millions (but adds per-user consent step) |

Tag-based access control is the only option that gives (a) zero ops burden per user, (b) zero per-user state on our side, (c) cryptographic enforcement by the cloud, and (d) scales to our target user count.

---

## Security properties and attacker surface

### What this gives us

- **Per-user boundary is cryptographic.** User A with wallet `0xA` cannot access user B's prefix even if A compromises their own daemon. The session tag is locked to A's wallet by the JWT signature at mint time; A cannot forge a JWT claiming to be B (would require the TEE's ES256 key, which is sealed).
- **Least privilege by default.** Bucket policy uses an explicit `Deny` on `NotAction`; if a future operation is added to the role without a corresponding bucket-policy `Allow`, it fails closed.
- **Audit attribution is cryptographic.** CloudTrail records the session's PrincipalTag on every access. Forensic investigators trace every S3 read back to a specific user wallet without needing our chain audit (though our chain audit is the authoritative source).
- **Revocation is ≤6 s.** Revoke the on-chain grant → TEE stops minting JWTs for that `(user, scope)` pair → last minted JWT expires in ≤5 min → no further access. No bucket-policy change needed.

### What can still go wrong

| Attack | Mitigation |
|---|---|
| Attacker steals a valid short-lived JWT | JWT expires ≤5 min (we set short `exp`); chain revocation invalidates the grant that minted it within ≤6 s; full blast radius ≤5 min access to one user's prefix |
| Attacker compromises our AWS root account | All users' data accessible; this is the catastrophic scenario hosted-first tolerates. Mitigation: isolated AWS account for SES/S3 stack, CloudTrail → chain audit for tamper-evidence, SCPs restricting destructive actions |
| Attacker compromises the TEE | Can mint arbitrary JWTs for any user → all users' data compromised. Same as any root-key compromise in the system. Mitigated by enclave attestation + out-of-band rotation of the ES256 key |
| Role trust policy misconfigured (missing `NotEquals ""` on claim) | JWT without `agentkeys_user_wallet` claim could assume role and access any/no prefix. Mitigation: policy-as-code CI check; integration test that fires a JWT without the claim and asserts denial |
| IAM bucket policy misses the `Deny` clause on `NotAction` | New S3 actions added to the role leak. Mitigation: explicit deny; IAM Access Analyzer scan |
| Attacker replays a valid JWT for another user's operation | Each JWT has `aud=sts.amazonaws.com` and short `exp`; can only exchange for temp creds once (STS returns session); temp creds are scoped to the specific PrincipalTag at issuance |

The failure-mode surface is ~identical to AWS's own AssumeRoleWithWebIdentity pattern (used by GitHub Actions, etc.). We inherit AWS's hardening of the primitive.

---

## Alignment with the architectural rules

From `wiki/blockchain-tee-architecture.md`:

- **Rule #1 (chain is truth):** The `agentkeys_user_wallet` claim in the JWT is the wallet of an on-chain account; the grant that authorized this JWT mint is an on-chain extrinsic; every mint emits an on-chain audit event. The tag's authority derives from chain state.
- **Rule #2 (TEE holds all keys):** The ES256 OIDC-issuer key that signs the JWT is TEE-sealed. Attackers cannot mint tags they don't own without compromising the TEE.
- **Rule #3 (clients hold only bearer tokens):** The daemon receives a short-lived AWS session token with the tag baked in; it never holds the signing key, never holds a long-lived AWS access key.
- **Rule #4 (broker, not proxy):** The daemon calls S3/GCS/OSS directly using the tagged session; our backend mints, doesn't proxy.

Tag-based access control is the **technical mechanism that lets rule #4 (broker-not-proxy) coexist with per-user isolation**. Without it, we'd be forced back to either per-user buckets (expensive) or operation proxying (compute cost, rule-#4 violation).

---

## Implementation checklist for Stage 6

- [ ] Include `agentkeys_user_wallet` in the TEE's JWT claim-set (parallel with existing `sub`)
- [ ] Update OIDC discovery doc to list the claim in `claims_supported`
- [ ] Register the OIDC provider in each AWS account we operate
- [ ] Create the `agentkeys-data-role` role with trust policy requiring the claim + pinned to enclave mrenclave
- [ ] Apply the shared-bucket policy using `${aws:PrincipalTag/agentkeys_user_wallet}`
- [ ] Integration test: mint two JWTs for two different wallets; verify each can access only its prefix; verify `agentkeys_user_wallet=""` is denied
- [ ] Chain-audit extrinsic at mint time includes the claim values (redacted appropriately)
- [ ] Repeat for GCP (when Drive backend ships) and Ali Cloud (when OSS backend ships)

---

## Cross-references

- [oidc-federation](oidc-federation) — the OIDC-provider design that mints JWTs carrying the tag claim
- [email-system](email-system) — the email system that uses PrincipalTag to isolate per-user inboxes on the shared `agentkeys-mail` bucket
- [knowledge-storage](knowledge-storage) — every candidate backend uses an equivalent tag-condition mechanism natively
- [hosted-first](hosted-first) — why per-user isolation on a shared bucket matters (hosted default can't afford per-user AWS resources)
- `wiki/blockchain-tee-architecture.md` (repo) — rules this pattern is designed to preserve

### AWS primary sources

- [Session tags in STS](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html)
- [AssumeRoleWithWebIdentity and passing session tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html#id_session-tags_adding-assume-role-idp)
- [S3 condition keys and principal tags](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html)

