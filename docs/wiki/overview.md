# AgentKeys Wiki — Index and Reading Order

The tree. Every wiki page in this repo, grouped by concern, with a one-line description so you can pick where to start.

---

## Tree

```
AgentKeys wiki
├── 0  Overview
│   └── 0.1  This index (you are here)
│
├── 1  Architectural principles
│   ├── 1.1  Hosted-first vs bring-your-own user segmentation
│   ├── 1.2  Tag-based access control (PrincipalTag → per-user isolation)
│   └── 1.3  Broker-not-proxy — our backend mints credentials; daemons do the ops
│           (principle inline across every page; no dedicated wiki yet)
│
├── 2  Identity and federation
│   └── 2.1  TEE as OIDC identity provider (universal federation pattern)
│
├── 3  Services
│   └── 3.1  Email system — architecture, backends, usage isolation
│
└── 4  Deferred decisions
    └── 4.1  Knowledge-base storage options
```

---

## By category

### Architectural principles

| Page | One-line summary |
|---|---|
| [hosted-first](hosted-first) | Default path: `xxxxx@agentkeys-email.io` on our infra. BYO custom domain is opt-in, deferred past Stage 7. |
| [tag-based-access](tag-based-access) | JWT claim `agentkeys_user_wallet` → AWS session tag → bucket-policy condition. One bucket, N users, cryptographic separation. |

### Identity and federation

| Page | One-line summary |
|---|---|
| [oidc-federation](oidc-federation) | TEE exposes `https://oidc.agentkeys.dev` as a conforming OIDC issuer. Federates into AWS, GCP, Ali Cloud, Azure, Snowflake, K8s. ES256 signing key sealed in enclave. |

### Services

| Page | One-line summary |
|---|---|
| [email-system](email-system) | Three email channels (agent / user / approval). Hosted default on SES. Broker-not-proxy: daemon calls SES directly with minted creds. |

### Deferred decisions

| Page | One-line summary |
|---|---|
| [knowledge-storage](knowledge-storage) | Four candidates (GitHub / S3 / Drive / Ali Cloud) mapped to user segments. Commit when first real user forces the choice. |

---

## Reading order by role

| If you're a… | Start with | Then | Then |
|---|---|---|---|
| New engineer on the team | `wiki/blockchain-tee-architecture.md` (repo) | [hosted-first](hosted-first) | [email-system](email-system) |
| Product / roadmap reviewer | [hosted-first](hosted-first) | `docs/archived/development-stages-v2-2026-04.md` §Stage 5–7 roadmap update | [knowledge-storage](knowledge-storage) |
| Operator / infra setup | `docs/spec/ses-email-architecture.md` | [oidc-federation](oidc-federation) §Consumer-registration recipes | [tag-based-access](tag-based-access) §Concrete AWS configuration |
| Security reviewer | `wiki/blockchain-tee-architecture.md` (repo) | [tag-based-access](tag-based-access) §Security properties and attacker surface | [oidc-federation](oidc-federation) §Threat model |

---

## Architectural principles — the short version

Every page below assumes these four principles, from `wiki/blockchain-tee-architecture.md` (repo):

1. **Chain is the source of truth.** Every grant, credential mint, audit event is on-chain.
2. **TEE holds all private keys.** Derived from master seed; never extractable.
3. **Clients hold only bearer tokens.** Short-lived; no long-lived secrets.
4. **Broker, not proxy.** We mint ephemeral credentials; daemons use them to call remote services directly via MCP. We never proxy per-operation reads/writes.

All five wiki pages and all the `docs/spec/*` specs are derivations of these four rules into concrete services (email, knowledge base, identity federation).

---

## Specs (outside the wiki)

Living in `docs/spec/`:

| Spec | Covers |
|---|---|
| `ses-email-architecture.md` | The SES-backed email backend (v0.1 default on `agentkeys-email.io`) |
| `email-signing-backends.md` | Generalized backend comparison (SES / DWD / AgentMail-style SaaS) |
| `credential-backend-interface.md` | The `CredentialBackend` trait that every backend implements |
| `../archived/development-stages-v2-2026-04.md` | The stage roadmap (archived; Stages 0–5 shipped; Stage 6 = hosted email; Stage 7 = OIDC provider) |

And operator-facing docs:

| Doc | Covers |
|---|---|
| `manual-test-stage5.md` | Stage 5 demo recipe (dedicated personal Gmail for the quick path) |
| `stage5-workspace-email-setup.md` | **Advanced / deferred:** BYO Workspace DWD for enterprise users |

---

## Conventions

- `[slug](slug)` links to another wiki page.
- `path/to/file.md` (no wiki brackets) links to a spec or doc outside the wiki.
- Every page starts with a "Status" line naming what stage it targets and whether it's current or deferred.
- We try to cut rather than add — if a page grows past ~300 lines of prose, it probably has SaaS-shape rot that should be removed.

