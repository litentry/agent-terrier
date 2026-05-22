---
title: "Knowledge Base Storage Options — Deferred Decision Matrix"
tags: ["knowledge-base", "storage", "deferred", "github", "s3", "google-drive", "alicloud", "jurisdictional", "user-segmentation"]
created: 2026-04-19T10:06:02.153Z
updated: 2026-04-19T10:06:02.153Z
sources: []
links: ["email-system.md", "tag-based-access.md", "blockchain-tee-architecture.md", "oidc-federation.md", "hosted-first.md"]
category: decision
confidence: medium
schemaVersion: 1
---

# Knowledge Base Storage Options — Deferred Decision Matrix


**Status:** deferred (2026-04-19)
**Scope:** which backend(s) AgentKeys will support as the agent's "memory" / knowledge-base storage layer once we commit.
**Why deferred:** no single choice fits all users; the best backend depends on developer/non-developer split and jurisdictional constraints (China vs non-China). Decision is held open so we don't prematurely commit infrastructure before user segments are clearer.

> **Important architectural point.** Whichever backend(s) we eventually pick, the shape is identical under AgentKeys' credential-broker thesis: **storage is just another credential type in the vault, operations happen client-side via MCP, our backend never proxies reads/writes.** See [email-system](email-system) for the analogous email path that informed this decision and the broker-not-proxy principle.

---

## The four candidates

| Backend | Primary user fit | Auth pattern | Handler category | Per-user isolation primitive |
|---|---|---|---|---|
| **GitHub** (repos as knowledge store) | **Developers** — docs-as-code, markdown, PR review | GitHub App (installation tokens, 1h auto-rotating) | App-level signing (our derived ECDSA key signs app JWTs) | GitHub App installed per-repo; installation_id scopes access |
| **AWS S3** | **Non-Chinese non-technical users** | OIDC federation via our TEE (no per-user cred storage) + bucket policy + [tag-based-access](tag-based-access) | OIDC federation | `aws:PrincipalTag/agentkeys_user_wallet` in bucket policy |
| **Google Drive** (shared drives) | Non-Chinese Workspace users who already live in Google | Workload Identity Federation + shared drive membership | OIDC federation | Per-user shared drive; user adds our SA as member |
| **Ali-Cloud OSS** (Alibaba Object Storage) | **Chinese non-technical users** (regulatory + latency) | OIDC federation via Alibaba RAM OIDC provider | OIDC federation | RAM role condition on `oidc:sub` matching wallet pattern |

All four fit the same architectural shape — **just four different handler routes inside the Authority**, dispatching the ephemeral credential to a different remote service. The daemon uses the resulting credentials directly via MCP, talking to the vendor's API. Our infrastructure does zero per-operation compute.

---

## Why the segmentation matters

### Developer vs non-developer

- **Developers** (our early adopters) live in Git already. Agents storing their memory as commits, branches, and PRs matches how developers think about state. A markdown file in a GitHub repo is the most familiar knowledge primitive in that world. **→ GitHub preferred.**

- **Non-developers** don't use Git and wouldn't recognize a repo as a knowledge base. They expect files and folders. Blob storage (S3, OSS) presented as files through a simple MCP feels native. **→ Object storage preferred.**

### Non-Chinese vs Chinese users

China's regulatory environment has repeatedly restricted cross-border data transfer and penalized unregistered international cloud use. Storing Chinese users' memory in AWS S3 creates compliance risk for the user and operational risk for us (potential blocked traffic, forced migrations later).

- **Non-Chinese users**: AWS S3 in `us-east-1` or `eu-west-1`. Low latency, mature tooling, our OIDC federation already lands there.
- **Chinese users**: Alibaba Cloud OSS in `cn-hangzhou` or `cn-beijing`. Ali Cloud RAM supports OIDC providers in the same way AWS IAM does (we register our OIDC issuer URL; they accept JWTs). Latency inside China is acceptable; compliance handled.

The two buckets share every architectural element except the cloud provider's URL. Our TEE's ES256 OIDC-issuer key federates into both.

---

## One-line user pick

A simple selection rule the onboarding flow can use:

| If user is... | Default backend | Why |
|---|---|---|
| Developer (any region) | GitHub | Matches their mental model; per-repo scoping via GitHub App |
| Non-developer, not in China | AWS S3 | OIDC federation, PrincipalTag isolation, mature |
| Non-developer, in China | Alibaba Cloud OSS | Same architecture as AWS, compliant jurisdiction |
| Has custom preference / enterprise deal | (advanced) — their choice; plug-in as another handler | Supported via any of the four, or a custom fifth |

No forced choice. Each user flows into the path that matches their existing operational reality.

---

## Per-option architectural detail

### GitHub (developers)

```
TEE master seed
  └── derive("github-app/v1") → ECDSA P-256 (GitHub App signing key)

Flow:
  1. We register a "AgentKeys Memory" GitHub App one-time
  2. User installs app into specific repo(s) they want agents to use
  3. Agent: daemon asks TEE for GitHub installation token
     → TEE signs app-level JWT with derived ECDSA key
     → Calls POST /app/installations/<id>/access_tokens
     → Returns installation token (1h) to daemon
  4. Daemon uses token with GitHub MCP server (existing in MCP ecosystem)
  5. Chain audit extrinsic at mint time
```

Per-user isolation: each user's repo installs are separate `installation_id`s. One installation = one user's repo scope. GitHub enforces at installation level.

### AWS S3 (non-Chinese non-devs)

```
TEE master seed
  └── derive("oidc/issuer/v1") → ES256 (reused from email path)

Flow:
  1. We provision S3 bucket agentkeys-memory (region per operator choice)
  2. Bucket policy:
     - Allow s3:* on arn:aws:s3:::agentkeys-memory/${aws:PrincipalTag/agentkeys_user_wallet}/*
     - Deny everything else
  3. Agent: daemon asks TEE for S3 temp creds
     → TEE signs OIDC JWT with claims {agentkeys_user_wallet: 0xABC}
     → sts:AssumeRoleWithWebIdentity → session tags from JWT claim
     → Returns temp AWS creds (1h) to daemon
  4. Daemon uses creds to call S3 directly (aws-sdk or MCP)
  5. Chain audit extrinsic at mint time
```

Per-user isolation: `${aws:PrincipalTag/agentkeys_user_wallet}` expands to the JWT-claim value AWS STS mapped to a session tag. User A cannot read user B's prefix because the condition fails. Single role, N users, hard-walled. See [tag-based-access](tag-based-access) for the full mechanics.

### Google Drive (alternative for Workspace users)

```
Same ES256 OIDC key; different cloud consumer.

Per-user isolation: per-user shared drive. User creates their agent's
shared drive; adds our SA as a member; drive ID becomes the scope boundary.
```

### Alibaba Cloud OSS (Chinese non-devs)

```
TEE master seed
  └── derive("oidc/issuer/v1") → ES256 (same key, federating into Ali RAM)

Ali RAM supports external OIDC identity providers just like AWS IAM does:
  1. Register our OIDC issuer URL in RAM (one-time, per region)
  2. Create a RAM role with condition: oidc:sub matches "enclave:<mrenclave>:<mrsigner>:agent:*"
     and oidc:aud = sts.aliyuncs.com
     (three-segment enclave identity — see tag-based-access §"Why three segments"
      for the mrenclave/mrsigner pin-mode options)
  3. Role policy: s3-equivalent OSS permissions on per-user prefix
  4. Agent flow: TEE signs JWT → AssumeRoleWithOIDC → temp OSS creds

Per-user isolation: OSS bucket policies condition on oidc:sub prefix,
same mechanism as AWS PrincipalTag, different attribute mapping name.
```

---

## What this means for our codebase

The credential vault picks up one more handler category for each backend we eventually ship:

| Handler | Long-lived TEE material | Ephemeral output | Remote service |
|---|---|---|---|
| App-level signing (GitHub) | Derived ECDSA app key at `derive("github-app/v1")` | GitHub installation token (1h) | GitHub API |
| OIDC federation (AWS S3) | Derived ES256 issuer key at `derive("oidc/issuer/v1")` | AWS temp creds (≤1h) with session tag | S3 API |
| OIDC federation (GCP Drive) | Same ES256 key | GCP SA token (~1h) | Drive API |
| OIDC federation (Ali Cloud OSS) | Same ES256 key | Ali STS token (~1h) | OSS API |

All four handlers drop into the existing `TokenAuthority::execute(op)` dispatcher — no architectural branching. When we eventually commit, adding a backend is ~1 week of work to:

1. Write the handler
2. Register the remote cloud's trust for our OIDC provider (or register a GitHub App)
3. Add operator runbook for the backend's DNS / policy setup
4. Validate per-user isolation via tag-based conditions

---

## Triggers that would move us off "deferred"

Commit to a backend when any of these fire:

- First paying customer in one of the user segments → build their preferred backend
- Regulatory need forces early commitment (e.g. enterprise buyer requires S3 in a specific region)
- An agent use case emerges where storage shape materially matters (e.g. "agent needs rich metadata / search across documents" → S3 or OSS favored; "agent needs PR-based review workflow" → GitHub favored)
- We see demand for cross-backend migration tooling

Until one of those fires, the deferred state is fine. The credential-broker architecture already accommodates every candidate — we're only deferring *which handler(s) to build first*, not any architectural decision.

---

## Alignment with [blockchain-tee-architecture](blockchain-tee-architecture)

This deferred decision preserves all four rules:

- **Rule #1** (chain is source of truth): every knowledge-base grant is an on-chain extrinsic regardless of which backend; every credential mint is an on-chain audit event.
- **Rule #2** (TEE holds all private keys): whether it's the GitHub App ECDSA key, the ES256 OIDC-issuer key, or anything else, every long-lived key is derived from the TEE master seed and never extracted.
- **Rule #3** (clients hold only bearer tokens): the daemon holds a short-lived GitHub installation token / AWS temp creds / OSS STS token — all ≤1h, no long-lived secrets, same posture as existing credentials.
- **Rule #4** (broker, not proxy): our backend mints credentials; the daemon uses them to talk to the vendor directly via MCP. We never run `read_document` / `write_document` on the user's behalf. Applies end-to-end across all four candidate backends.

---

## Cross-references

- [email-system](email-system) — the same deferred-decision pattern landed for email with SES as the v0.1 default
- [oidc-federation](oidc-federation) — how our OIDC provider federates into AWS, GCP, Ali Cloud, any compliant cloud
- [tag-based-access](tag-based-access) — how AWS (and equivalent-mechanism clouds) enforce per-user isolation on shared buckets via JWT-claim-derived session tags
- [hosted-first](hosted-first) — the broader user-segmentation principle this decision follows
- [`wiki/blockchain-tee-architecture.md`](blockchain-tee-architecture) — the four architectural rules all candidates preserve
- Issue [#11](https://github.com/litentry/agentKeys/issues/11) — biometric gate (applies to each backend's grant creation)

