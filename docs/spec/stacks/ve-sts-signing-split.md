# VE STS signing split — the signer holds the AK/SK and validates before signing

**Status:** DESIGN DECISION (proposed, not yet implemented). Tracked as
[#509](https://github.com/litentry/agentKeys/issues/509) — phase 1 same-host
(incl. M1 per-data-class VE roles), phase 2 production host split. Guiding
principle: **the platform is a resource provider, never the authorizer** —
credential *form* varies per service (scoped STS / gate-held app token /
gate-held API key: Doubao Voice rejects STS while ARK accepts it, so no
platform mechanism is uniform even within one cloud), but the issuance
*decision* is always ours. Supersedes the
"accepted residual risk" framing of the layer-3 gap in
[`ve-broker-runtime-port.md`](../ve-broker-runtime-port.md) — the gap is closed by
design, not accepted.
**Scope:** the VE credential plane only (`AssumeRoleWithOIDC` → TOS). AWS is
unchanged; the AWS path stays anonymous `AssumeRoleWithWebIdentity`.

## Context — what the VE seam actually breaks

AWS and VE differ on one primitive with a large blast radius:

| | AWS | VE |
|---|---|---|
| STS federation call | `AssumeRoleWithWebIdentity`, **anonymous** | `AssumeRoleWithOIDC`, **SigV4-signed** — caller must hold an AK/SK |
| Per-actor isolation | static bucket policy on `${aws:PrincipalTag/agentkeys_actor_omni}` — provisioned out-of-band, **broker cannot change it** | inline session `Policy` **authored by the caller at mint time** (VE has no OIDC-token→session-tag mechanism) |

Consequence in the naive port: the broker mints the OIDC JWT, authors the
session policy, **and** signs the STS call. Authorizer and credential-issuer
collapse into one component, and the separation of duties AWS gets for free —
identity asserted by one party, authorization enforced by infrastructure a
different party provisioned — is lost.

**What is NOT broken (correcting a common misreading).** Every VE mint already
attaches a per-actor session policy (`ve_sts.rs` → `ve_session_policy`), and a
session policy is baked into the issued credential. So a *normally minted*
credential that later leaks is confined to `bots/<actor>/*`, exactly like the
AWS outcome. A mint with no derivable actor errors rather than minting
unscoped. The residual risk is narrower than "leaked credentials": it is
**a broker that authors a deliberately wide policy** (compromise), or a
policy-construction bug (largely covered — `ve_session_policy` is a pure,
unit-tested function).

## Decision

**Move the VE AK/SK out of the broker and into the signer, and make the signer
validate what it is asked to sign.**

The broker keeps what it legitimately owns — minting the OIDC JWT and proposing
a session policy. It loses the ability to unilaterally turn those into
credentials. Signing becomes a second, independent decision.

**One signer codebase, two deployments.** The endpoint lands in the shared
signer binary (`agentkeys-mock-server --signer-only`) that both stacks already
run — `signer.litentry.org` on AWS (#443 re-federates that stack onto
`agentterrier.ai`) and `signer.agentterrier.cn` on VE. Cloud-specific behavior
enters only through the `StsClient` driver and the policy renderer, selected by
config; the phase-2 host split changes deployment topology, never code.

Rejected alternative — **signer as a dumb signing oracle** (broker sends a
pre-built request, signer blindly SigV4-signs it): removes the standing AK/SK
from the broker, but a compromised broker still obtains any credential it asks
for. It buys credential-at-rest hygiene and no isolation. Not sufficient.

### The validation rule

The signer refuses to sign unless **all** hold:

1. The presented session JWT verifies against the broker session pubkey the
   signer already loads (the existing `/dev/*` bearer check).
2. The proposed policy's resource prefixes are a subset of
   `bots/<actor_omni>/*` for the `actor_omni` **derived from the JWT** — never
   from a caller-supplied field.
3. **(B+ only)** The actor's grant for the requested data class **exists on
   chain** — see Variant B+ below; Variant B omits this rule.
4. The requested role TRN is the per-data-class role matching the policy's
   bucket (see M1 below); cross-data-class combinations are refused.
5. TTL ≤ the configured ceiling (900s, the #441 number).

Rule 2 is the load-bearing one: it is mechanically checkable, and it is exactly
the invariant `ve_session_policy` already constructs — the signer re-derives it
independently rather than trusting the broker's string.

### Wire shape

`POST /dev/sign-sts` on the signer (signer-only listener, loopback), bearer =
the session JWT, mirroring `/dev/sign-message`:

```jsonc
// request
{ "omni_account": "0x<actor>",      // cross-checked against the JWT, as today
  "role_trn":     "trn:iam::<acct>:role/agentterrier-<class>-role",
  "policy":       "{\"Statement\":[…]}",   // broker's proposal, re-validated
  "oidc_token":   "<broker-minted OIDC JWT>",
  "ttl_seconds":  900 }
// response
{ "access_key_id": "…", "secret_access_key": "…",
  "session_token": "…", "expiration": "…" }
```

The signer performs the `AssumeRoleWithOIDC` call itself (it holds the AK/SK);
the broker never sees a VE credential it did not go through the signer to get.

**Refinement (preferred final shape): pass intent, not policy.** The `policy`
string above exists only because the broker historically authors it. Stronger:
the broker sends the *intent* — `{data_class, verbs, ttl_seconds}` (actor
implied by the JWT) — and the **signer renders the policy itself** through a
per-cloud dialect renderer. Rule 2 then holds **by construction** (there is no
caller-authored policy left to validate) and `policy_scope_violation` becomes
an internal invariant rather than a reachable error. It also makes the
endpoint cloud-portable: intent is dialect-free; only the signer's renderer
knows `tos:`/`trn:` vs `s3:`/`arn:`.

### Failure modes — all loud, none silent

| Condition | Response | Rationale |
|---|---|---|
| JWT invalid/expired | `401` | existing `/dev/*` behaviour |
| JWT actor ≠ `omni_account` | `403 actor_mismatch` | existing cross-check |
| Policy resource ⊄ actor prefix | `403 policy_scope_violation` | **the new gate** — log the offending policy |
| No on-chain grant for (actor, class) — B+ | `403 grant_not_found` | a forged JWT alone is no longer sufficient |
| Role TRN ↔ bucket class mismatch | `403 role_class_mismatch` | cross-data-class attempt |
| TTL over ceiling | `400 ttl_too_long` | |
| AK/SK unset | `503 sts_signing_not_configured` | no-silent-fallback policy |

A `policy_scope_violation` is a **security event**, not a validation nit: in
normal operation it cannot occur. It must emit an audit envelope and alert.

## Why this is the right shape — the ArkClaw cross-check

`docs/research/bytedance.md` (private repo — not in the OSS mirror) reconstructs ByteDance's own
enterprise agent-IAM stack (ArkClaw) — i.e. how the cloud vendor expects this
to be done on their own platform. Its access chain is:

> local plugin → **enterprise IdP signs a short OIDC token** → **cloud STS
> `AssumeRoleWithOIDC` maps it to a Role via the Trust Policy** → short-lived
> credentials (15 min–1 h) → Gateway.

The load-bearing property is that the **IdP asserts identity** while the
**Trust Policy performs the authorization mapping** — two parties. The naive VE
port collapses both into the broker; this decision restores the split. So
Variant B is not a workaround for a missing AWS feature, it is the shape the
platform's own reference architecture uses.

The research also records ArkClaw's weakness, and it is a warning label for the
naive form of this decision:

> "Centralized trust root — Enterprise IdP + Root CA. Compromise the IdP or the
> CA and you can **forge any agent identity org-wide. No independent
> re-verification layer behind it.**"

If the signer validates only a **broker-minted** JWT, the broker *is* that IdP:
it holds the session keypair, so it can forge a J1 for any actor and the signer
will faithfully sign for the victim. That yields **parity with AWS** (where a
compromised broker can likewise mint a JWT for any actor and AWS honours it) —
but it reproduces precisely the centralization the same research names as
AgentKeys' differentiator:

> AgentKeys: "trust root is an **on-chain registry** that the broker *and* every
> worker **independently re-verify**."

### Variant B+ (recommended target): the signer verifies the chain, not the broker

Rule 3 above is the B+ upgrade: the signer re-checks the actor's on-chain
scope directly, exactly as the worker does in layer 2.

This is not a new pattern; it is the existing **worker chain-verify** (§17.5
layer 2) applied one step earlier, at credential issuance instead of data
access. Its effect is qualitative: a compromised broker can forge a JWT, but it
cannot forge the chain, so it can no longer obtain credentials for an actor
whose grant does not exist or whose scope does not cover the request.

**This is strictly better than the AWS posture**, where a compromised broker
minting a JWT with an arbitrary actor tag is honoured by AWS without any
independent re-verification. It is the one place the VE port can end up ahead.

Trade-off to size before committing: a chain read on the credential-mint path
adds RPC latency. Mitigations, in preference order — mint per data *session*
rather than per op (credentials already carry a TTL clients reuse); accept the
latency given short TTLs; **do not** cache grant state in the signer without an
explicit decision, as that reintroduces the server-side state the stateless
posture forbids.

### Also borrowed from the research

- **Explicit signed `delegation_path`** (RFC 8693 token exchange) — the
  research's highest-leverage borrow, tracked as
  [#361](https://github.com/litentry/agentKeys/issues/361). The sign-STS request
  should carry the delegation context (`initiator`, `delegated_agent`,
  `delegation_path`, `scope`, `expiry`) so a signature is auditable with full
  provenance from one object, rather than reconstructed from cap fields + audit
  rows.
- **全链路可审计 / full-chain auditable** — the signer is a natural credential-
  issuance audit point. Emit an envelope per signature. This is a capability
  AWS's anonymous path **structurally cannot** provide, since the broker there
  never observes the exchange.

## Open probe that could obviate part of this

The port spec hedges: *"exact TRN/condition-key names: CONFIRM live."* Two
unknowns are worth a live probe before building, because a positive answer
restores infrastructure-side enforcement and shrinks this work:

1. Does VE IAM support **policy variables** in a role's permission policy
   (an equivalent of `${aws:PrincipalTag/…}` or `${oidc:sub}`)? If yes, layer 3
   can be pinned in the *role*, broker-independently — the true AWS equivalent.
2. Do VE **trust policies support conditions on OIDC claims** (e.g. `sub`)? If
   yes, per-actor or per-class role mapping is enforceable out-of-band.

VE is documented as having no session-**tag** mechanism; that is not the same
statement as having no policy variables. Neither has been probed. Variant B+
works regardless, so this is an optimisation, not a blocker.

## Consequences

**Restored.** Authorizer ≠ credential-issuer. Layer 3 reaches AWS parity
(Variant B) or exceeds it (Variant B+). The broker no longer holds a standing
cloud credential.

**Relocated, not eliminated.** The AK/SK moves to the signer, already the KEK
root and thus the most sensitive component. This is judged the right direction:
the signer is loopback-only and session-JWT-gated, while the broker carries the
public HTTP surface — the standing credential belongs on the *less exposed*
component. Keep the new endpoint narrow: one operation, one validation rule.

**Caveat — co-location undercuts the split today.** The VE signer runs on the
**same host** as the broker (`:8092` loopback). The separation is therefore
logical, not physical: it defends against broker *process* compromise, not
host-root compromise. Separating the hosts is required for the full benefit and
should be sequenced with this work.

**Not addressed here.** Encryption protects confidentiality, not integrity — a
wide credential could still delete or overwrite objects. Deny `Delete` in the
session policy and enable TOS bucket versioning (tracked as M11). KEK
derivation (`/dev/sign-message`) stays gated only on the — broker-forgeable —
session JWT, so a compromised broker can still decrypt what it fetches for
actors that pass rule 3; extending the chain-verify (or a K11-bound proof) to
KEK derivation is a candidate follow-up that lifts both clouds. Related and
independent: per-data-class VE roles (M1), memory client-side encryption (M2),
and eliminating the AK/SK entirely via instance-role/IMDS (port-spec follow-up
6), which would subsume the custody question this decision relocates.

## Companion changes

- [`ve-broker-runtime-port.md`](../ve-broker-runtime-port.md) — the isolation-fork
  section's "asserted at mint time" trade-off is superseded by this document.
- [`../../arch.md`](../../arch.md) §17.5 — the four-layer table states layer 3 as "AWS
  IAM PrincipalTag" and layer 4 as "each role reaches only its own bucket" with
  **no per-cloud qualification**, so the single source of truth currently
  implies the VE stack has properties it does not yet have. Amend with the
  per-cloud posture in the same change as any VE data-plane work.
- [`threat-model-key-custody.md`](../threat-model-key-custody.md) — the canonical
  position *"per-user isolation is cloud-enforced via PrincipalTag"* is not
  portable and is false on VE. Restate in cloud-neutral terms: per-user
  confidentiality from the client-side per-actor KEK, per-user authorization
  from the on-chain grant + independent re-verification, cloud IAM as
  defence-in-depth.
- [`signer-protocol.md`](../signer-protocol.md) — gains the fourth signer
  operation (`/dev/sign-sts`) and its validation rule.
