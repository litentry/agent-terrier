**Status:** decision (2026-04-19)
**Scope:** how AgentKeys onboards non-developer users vs enterprise / advanced users across email, knowledge base, and OIDC identity.

---

## TL;DR

> **Default path: AgentKeys-hosted.** Non-developer users get throwaway identities on our domains (e.g. `xyz123@agentkeys-email.io`) with zero setup. No DNS, no admin console, no Workspace subscription, no custom domain.
>
> **Advanced path: Bring-Your-Own.** Enterprises or power users who already run a Workspace domain / custom GitHub org / corporate AWS account plug those in through the same architecture, same trait interfaces, same ephemeral-credential minting. **Deferred to post-Stage 7.**

The split exists because onboarding friction is the dominant user-acquisition cost for non-developers, and DNS / admin-console steps are exactly the kind of friction most users bounce off.

---

## User segments and the default that fits each

| Segment | Default email | Default knowledge base | OIDC provider |
|---|---|---|---|
| **Non-developer, first-time user** (our primary v0.1 target) | `xyz123@agentkeys-email.io` — we host, we own the domain, agent fully controls the inbox | AgentKeys-hosted on AWS S3 (non-China) or Ali Cloud OSS (China), both bucketed under our accounts | AgentKeys' OIDC issuer (our domain, our TEE); user doesn't configure anything |
| **Developer, technical user** | Same hosted default available; may upgrade to GitHub-repo-as-knowledge-base when useful | **GitHub App installation** into their own repos (preferred) | Same hosted OIDC (except for cases where they want to integrate with their own CI) |
| **Enterprise buyer** (Stage 7+) | Bring own Workspace domain; federated via the existing DWD or custom-OIDC path | Bring own AWS/GCP org; we federate into their identity pool | Possibly operate their own OIDC issuer trusted by their cloud |
| **Chinese non-developer** | Same hosted email (or a `.cn` variant we operate if data-residency requires) | Hosted Ali Cloud OSS | Hosted OIDC (potentially with Chinese-region issuer) |

Every segment uses the same architecture; the only variable is **whose resources host the primitives**. AgentKeys's by default; the user's by upgrade path.

---

## Why hosted-first

### The non-developer's experience

Compare the two onboarding flows we could offer today:

**BYO (what Stage 5's Workspace DWD doc described):**
1. Sign up for Google Workspace ($6/user/month, credit card)
2. Verify domain ownership via DNS TXT record (~30 min for DNS propagation)
3. Super-admin logs into admin console
4. Create custom admin role with 4 specific privileges
5. Create `/Automation` OU
6. Assign custom role to `agent@yourdomain` scoped to OU
7. Create GCP project, enable APIs
8. Create service account
9. Authorize domain-wide delegation in admin console (super-admin action again)
10. Generate service account key JSON
11. Store the JSON in secret manager
12. Export env vars and run agent

~1 hour of admin-console clicking for someone who's never seen Workspace's admin UI. Hard-blocking on "is the user a Google Workspace admin?"

**Hosted default:**
1. Sign in to AgentKeys
2. Agent is created; it has inbox `xyz123@agentkeys-email.io`
3. Go.

**10 minutes vs 10 seconds.** The hosted-first posture takes the second path as the default for the 95% of users who aren't enterprise buyers.

### What hosting costs us (and why it's fine)

On the AgentKeys side, operating `agentkeys-email.io` means:

- One domain registration (~$15/year)
- SES domain verification (one-time)
- MX record to SES inbound (one record)
- DKIM / SPF / DMARC (three records; Ed25519 DKIM key derived from TEE master seed per [email-system](email-system))
- SES receipt rule writing every inbound to S3 `agentkeys-mail/<user_wallet>/<inbox>/`
- S3 bucket policy conditions on `aws:PrincipalTag/agentkeys_user_wallet` per [tag-based-access](tag-based-access)

Cost scales with mail volume, not user count:

| User count | Monthly inbound emails | Monthly cost (approx) |
|---|---|---|
| 1,000 | 10,000 | < $5 |
| 10,000 | 100,000 | < $50 |
| 100,000 | 1,000,000 | < $500 |

Per-user cost: **fractions of a cent per month** at realistic scale. No per-seat cost, no per-inbox fee. Dramatically cheaper than asking each user to buy a Workspace seat.

The cost profile is exactly why we chose SES over Gmail DWD as the default — we control the infrastructure, our costs are AWS-native, and the scaling curve is flat.

---

## What hosted-first covers (Stage 6)

### Email — `xyz123@agentkeys-email.io`

- Inbox ID is an address under our domain, allocated deterministically at agent-create time (e.g. derived from `agent_wallet`)
- Inbound mail via SES MX → S3 drop to user-prefixed path
- Outbound via SES `SendRawEmail`, signed with TEE-held Ed25519 DKIM key for `agentkeys-email.io`
- Per-user isolation enforced by AWS via PrincipalTag from JWT claim `agentkeys_user_wallet`
- No DNS on user's side. No admin console. Nothing.

### Knowledge base — deferred per [knowledge-storage](knowledge-storage)

When we commit, the hosted-default will be:

- **Non-Chinese non-dev users**: our S3 bucket, per-user prefix, PrincipalTag isolation
- **Chinese non-dev users**: our Ali Cloud OSS bucket, equivalent isolation
- **Developer users**: option to plug their own GitHub (via GitHub App install), falling back to hosted S3 if they skip

Same broker-not-proxy architecture. Same TEE-derived keys. Same chain audit. Hosted vs BYO is only about *which cloud account the storage bucket sits in*.

### OIDC identity — our issuer

- `https://oidc.agentkeys.dev` with a TEE-derived ES256 key
- Every cloud consumer trusts this once (per [oidc-federation](oidc-federation))
- User never registers an OIDC provider; they inherit ours
- Every user's JWT mints temp creds scoped to their wallet via PrincipalTag

---

## What's deferred (Stage 7+)

### Bring-your-own email domain

- User's own domain (`bots.theircompany.com`) verified in our SES
- Still TEE-held DKIM key, different derivation path per custom domain (`derive("dkim/theircompany.com/v1")`)
- User configures DNS once (MX, DKIM CNAMEs, DMARC)
- Same per-user isolation + chain audit
- Deferred because:
  - Most v0.1 users don't own a domain they want agents using
  - The operator-side complexity (managing an unbounded domain list) is non-trivial
  - The current Workspace DWD runbook at `docs/stage5-workspace-email-setup.md` is a partial blueprint for the enterprise variant

### Bring-your-own Workspace / GCP

- User operates their own Google Workspace; we federate via DWD or OIDC
- See existing docs in `docs/stage5-workspace-email-setup.md` — still valid for this advanced path, just not the default anymore
- Deferred to Stage 7+ once the hosted default has paying users

### Bring-your-own GitHub organization

- User's own GitHub org where the agent has its own repo for memory
- Our GitHub App installation into their org (we author the app; they install)
- Per-installation token scoping
- Deferred to Stage 7+ as a developer-only advanced backend

### Bring-your-own AWS / Ali Cloud account

- User's AWS/Ali account hosts the S3/OSS bucket for their agent's knowledge base
- Our OIDC provider federates into their IAM role
- User configures one role trust policy in their account
- Deferred to Stage 7+ for enterprises with data-residency requirements

---

## Parity guarantee: hosted and BYO share one architecture

Every element listed in the "advanced" column above can be reached from the "hosted default" column by **swapping the cloud account, not rewriting the code**. The handler categories (OIDC federation, app-level signing, static-key unwrap) are identical; only the trust configuration on the remote side differs.

Concretely:

| Aspect | Hosted default | BYO advanced | What changes |
|---|---|---|---|
| DKIM key source | TEE master seed `derive("dkim/agentkeys-email.io/v1")` | TEE master seed `derive("dkim/<user-domain>/v1")` | Just the derivation path |
| OIDC issuer | `https://oidc.agentkeys.dev` (ours) | Same (we run it; our cert) | Nothing |
| Federation target (AWS S3) | Our AWS account, role in our account | User's AWS account, role in their account, our OIDC trusted there | Trust policy in user's account |
| Isolation mechanism | `aws:PrincipalTag/agentkeys_user_wallet` on our bucket | Same in their bucket | Policy author |
| Chain audit | Same | Same | Nothing |

**A user migrating from hosted to BYO doesn't change their agent code, their grants, their credentials, or their audit trail.** They change the cloud account that hosts their bucket, period. Clean migration story.

---

## Alignment with the three architectural rules

From `wiki/blockchain-tee-architecture.md` (repo wiki), cross-referenced here to make sure hosted-first doesn't violate anything:

| Rule | Hosted-first posture | Preserved? |
|---|---|---|
| **#1 Chain stores everything persistent** | Every grant, inbox-create, credential-mint is on chain. Hosted vs BYO doesn't affect this. | ✓ |
| **#2 TEE holds all private keys** | DKIM key, OIDC issuer key, GitHub App key — all derived from TEE master seed. Hosted-first makes this LITERALLY true end-to-end (we don't hold third-party Workspace/SA keys at rest). | ✓ *strengthened* |
| **#3 Clients hold only bearer tokens** | Daemon holds 30-day AgentKeys bearer + short-lived minted creds from our broker. Same in hosted or BYO mode. | ✓ |
| **#4 (proposed) Credential broker, not operation proxy** | Daemon talks to SES / GitHub / S3 directly via MCP using minted creds. Our backend mints; does not proxy. Hosted mode doesn't change this. | ✓ |
| **Per-user isolation** | Enforced by AWS PrincipalTag from JWT claim. Single shared bucket, hard-walled per-user prefix. See [tag-based-access](tag-based-access). | ✓ |

Hosted-first strictly strengthens rule #2: by operating our own infrastructure, we never need to hold a user's own Google SA key or Workspace admin credential. The TEE's inventory stays clean. BYO re-introduces (optional) trust on user-side admin steps but doesn't compromise anything on our side.

---

## Attacker surface

Relative to the BYO path:

| Attack | Hosted default (our infra) | BYO (user infra) | Net change |
|---|---|---|---|
| Attacker compromises TEE | All users' creds compromised (same in both modes) | Same | None |
| Attacker compromises our AWS account | All users' S3 prefixes accessible to attacker | Only AgentKeys' domain/infra, user's own AWS untouched | **Hosted is worse** — per-user isolation via PrincipalTag still holds cryptographically but attacker has root-account keys |
| Attacker compromises one user's bearer token | Can impersonate that user for ≤30 days (until grant revoke or bearer expire) | Same | None |
| Attacker spoofs email from another user's inbox | Blocked by SES receipt rule + DKIM + our bucket-policy PrincipalTag | Same (on user's infra) | None |
| Regulator demands access to mail | Our legal team responds; user is subject to our jurisdiction | User's legal team responds; they control disclosure | **Hosted is worse** for users with strict regulatory or adversarial environments |

Mitigations for the "hosted is worse" rows:

- **AWS account compromise** — tight IAM boundary around the SES/S3 stack (isolated AWS account, limited IAM users, SCPs restricting dangerous actions, CloudTrail → our chain audit). Rule #2 still applies to the sensitive keys (they live in TEE), so account compromise gives attacker *AWS-level* access to user prefixes but no long-lived AgentKeys identity.
- **Regulatory / jurisdictional** — users with this concern are exactly the "advanced / enterprise" segment who should go BYO anyway. We offer BYO as the opt-out.

The tradeoff is correct for the user segment: non-dev users accept "trust AgentKeys" as the onboarding floor; power users who don't can opt out via BYO.

---

## Stage mapping

- **Stage 5 (current)** — Quick email demo via dedicated personal Gmail. Proves the provisioner end-to-end before we build real infra.
- **Stage 6 (next)** — Federated Own Email: hosted `agentkeys-email.io`, SES + PrincipalTag + TEE-held DKIM, available to all users without setup.
- **Stage 7** — Generalized OIDC Provider: the federation pattern exposed publicly; accepts external consumers; enables the BYO AWS / GCP / GitHub / etc. advanced paths.
- **Later** — BYO custom-domain email, BYO Workspace DWD (existing `docs/stage5-workspace-email-setup.md` becomes the runbook), BYO GitHub org, enterprise SSO integration.

See `docs/archived/development-stages-v2-2026-04.md` for the authoritative stage list.

---

## Cross-references

- [email-system](email-system) — how SES + hosted `agentkeys-email.io` works end-to-end
- [oidc-federation](oidc-federation) — the federation pattern the hosted OIDC provider exposes
- [tag-based-access](tag-based-access) — how one bucket safely holds all users' memories
- [knowledge-storage](knowledge-storage) — the per-segment storage backend options
- `docs/spec/ses-email-architecture.md` — spec for the SES-backed hosted path
- `docs/stage5-workspace-email-setup.md` — the BYO Workspace runbook (advanced, deferred)
- `wiki/blockchain-tee-architecture.md` (repo) — the three rules hosted-first preserves
- `docs/archived/development-stages-v2-2026-04.md` §Stage 6 — federated own email stage plan

