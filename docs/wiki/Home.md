> **This wiki is auto-generated from the `docs/wiki/` folder in the main repo.** Edit the source files there, not through the web UI — direct edits will be overwritten on the next push to `main`. The canonical source is [`docs/wiki/` in `litentry/agentKeys`](https://github.com/litentry/agentKeys/tree/main/docs/wiki).

AgentKeys is a credential custody service: a TEE-backed vault that issues long-lived bearer tokens for per-agent credential access, with on-chain audit. **We mint ephemeral credentials; daemons use them to call remote services directly.** Credential broker, not operation proxy.

---

## The four rules

Every spec and every service on top of AgentKeys preserves these four invariants (details in [Blockchain TEE Architecture §6](blockchain-tee-architecture#6-summary-the-four-rules)):

1. **Chain stores everything persistent** — single source of truth for ownership, grants, audit, revocation, and ciphertext hashes. **Not bulk encrypted bytes** ([threat-model-key-custody](https://github.com/litentry/agentKeys/blob/main/docs/spec/threat-model-key-custody.md)).
2. **TEE holds key-derivation roots and per-request decryption capability** — never bulk plaintext, never persistent per-user material beyond what the master seed reproduces.
3. **Clients hold only a JWT, not private keys** — bearer tokens, short blast radius.
4. **AgentKeys brokers credentials, not operations** — daemons call remote services directly; our compute scales with user count, not operation frequency.

---

## Wiki tree

### Foundations (canonical, published wiki)

- **[Blockchain TEE Architecture](blockchain-tee-architecture)** — chain + TEE + clients; the four rules in §6
- **[Session Token](session-token)** — 30-day JWT bearer; issuance, storage, revocation
- **[Key Security](key-security)** — TEE keys, master session key, storage tiers, threat model
- **[Master Recovery and Guardians](master-recovery-and-guardians)** — M-of-N guardian social recovery executed on-chain (`P256Account.recover`); control vs. secrets; why spend caps stay off-chain
- **[Open-Source Frontend Security](open-source-frontend-security)** — why the keyless web frontend is safe to open-source; malicious-clone + magic-link-phishing analysis (keys never touch the browser)
- **[Data Classification](data-classification)** — data classes, where each lives, retention policy
- **[Threat Model: Key Custody](https://github.com/litentry/agentKeys/blob/main/docs/spec/threat-model-key-custody.md)** *(spec)* — why nothing sensitive lives on chain or persistently in TEE; off-chain ciphertext + forward-secret epoch rotation (Stage 8)

### Credential lifecycle (canonical, published wiki)

- **[Credential Usage](credential-usage)** — store → run/read → revoke
- **[Serve and Audit](serve-and-audit)** — Pattern-4 per-read audit flow

### Service architectures (published wiki, Stage 6/7)

Design docs for specific services built on top of the foundations:

- **[Overview](overview)** — tree + reading order for the service-architecture pages
- **[Hosted-First](hosted-first)** — Stage 6 default (`xyz@agentkeys-email.io` on our infra) vs bring-your-own (advanced)
- **[Tag-Based Access](tag-based-access)** — `agentkeys_user_wallet` JWT claim → AWS PrincipalTag → per-user isolation on shared buckets
- **[OIDC Federation](oidc-federation)** — TEE as a conforming OIDC issuer; one ES256 key federates into AWS / GCP / Azure / Ali / K8s
- **[Email System](email-system)** — Stage 6 email architecture on AWS SES; broker-not-proxy; zero per-operation compute
- **[Knowledge Storage](knowledge-storage)** — deferred backend decision between GitHub / AWS S3 / Google Drive / Ali Cloud OSS, by user segment

---

## Reading order by role

| Role | Start here | Then | Then |
|---|---|---|---|
| New engineer | [Blockchain TEE Architecture](blockchain-tee-architecture) | [Session Token](session-token) | [Email System](email-system) |
| Product / roadmap | This page, §Wiki tree | `docs/plan/milestones-roadmap.md` | [Hosted-First](hosted-first) |
| Operator / infra | [Key Security](key-security), [Serve and Audit](serve-and-audit) | `docs/spec/ses-email-architecture.md` | [OIDC Federation](oidc-federation) §Consumer-registration recipes |
| Security reviewer | [Blockchain TEE Architecture](blockchain-tee-architecture) §6 (four rules) | [Data Classification](data-classification) | [Tag-Based Access](tag-based-access) §Security and attacker surface |

---

## Specs (outside the wiki)

Canonical design records live in `docs/spec/`:

- **`docs/archived/development-stages-v2-2026-04.md`** — build plan (archived). Stages 0–5 shipped; **Stage 6 = federated own email**; **Stage 7 = generalized OIDC provider**; remaining stages postponed.
- **`docs/spec/ses-email-architecture.md`** — Stage 6 SES email spec.
- **`docs/spec/email-signing-backends.md`** — generalized backend comparison (SES / DWD / SaaS).
- **`docs/spec/credential-backend-interface.md`** — the `CredentialBackend` trait.
- **`docs/arch.md`** — 13-component system architecture.
- **`docs/spec/heima-gaps-vs-desired-architecture.md`** — living gap list: where current upstream `litentry/heima` differs from what the wiki describes (HDKD master seed, OIDC provider, BYODKIM, email pallets, session-tag propagation).

Demo / operator docs:

- **`docs/manual-test-stage4.md`** — Stage 4 end-to-end walkthrough
- **`docs/manual-test-stage5.md`** — Stage 5 demo (dedicated-Gmail quick path)
- **`docs/stage5-workspace-email-setup.md`** — advanced BYO Workspace runbook (deferred past Stage 7)
- **`docs/contradictions.md`** — living tracker of cross-doc contradictions

---

## How to edit this wiki

1. Open `docs/wiki/<Page>.md` in the main repo.
2. Make changes in a PR.
3. Merge to `main`.
4. The `Publish wiki` GitHub Action mirrors `docs/wiki/**` to the wiki repo.

A maintainer can also trigger the mirror manually from the repo's Actions tab — the workflow exposes `workflow_dispatch`.

See `.github/workflows/publish-wiki.yml` for the implementation.
