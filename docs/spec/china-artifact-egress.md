# China artifact + egress model — ADR (Option B: domestic mirrors + a github-only Singapore relay)

**Status:** DECIDED + LIVE (2026-07-14; recorded here 2026-07-18). Adopt **Option B** as the current standard; **defer Option A** (self-hosted artifact cache) behind explicit triggers. Tracked by [#451](https://github.com/litentry/agentKeys/issues/451) (China infra), under epic [#445](https://github.com/litentry/agentKeys/issues/445); the Singapore relay is [#442](https://github.com/litentry/agentKeys/issues/442).
**Scope:** developers + cloud/CI colleagues. This is the **why + when-to-revisit**; the operational **how** (relay host, tunnel, per-tool config) lives in the operator-internal China-proxy runbook, which carries the concrete IP / instance-id / SSH aliases this ADR deliberately does not.
**Relates to:** [`arch.md`](../arch.md) §5 ("**ap-southeast-1 (Singapore) hosts the VE git/package relay and NOTHING else**", #442).

## Context

The VE/China stack (Volcano Engine, cn-beijing) builds and rebuilds hosts inside mainland China, where npm, crates.io, Docker Hub, Ubuntu mirrors, and GitHub release assets are slow or unreachable across the border. #451 proposed a two-tier distribution path — a self-hosted mainland artifact service (Nexus/Artifactory + Harbor) backed by a tightly-scoped Singapore AWS egress/sync node ("Option A"). The #397/#449 VE-website bring-up became the empirical study that let us decide instead of over-building.

## Decision

**Route dependency traffic by destination** — the earlier mistake was one blanket relay for everything. Each class takes the fastest domestic path; only GitHub, which has no good domestic mirror, rides the overseas relay:

| Traffic | Source | Transport |
|---|---|---|
| OS / apt | `mirrors.ivolces.com` (VE-own) | direct |
| node + npm | `npmmirror.com` | direct (a blanket proxy leaked into the registry→CDN redirect — do **not** front npm with the relay) |
| cargo + rustup | `rsproxy.cn` | direct |
| **git / GitHub** | GitHub SSH-over-443 | **the #442 Singapore relay** (ssh `ProxyCommand`) |

Measured live on the VE host: npm install **16 s** (from a 40-min ECONNRESET failure), cargo ~19% faster than direct, git auth ~5 s; the website builds, gets its Let's Encrypt cert, and serves `https://www.agentterrier.cn` (200, valid cert). The routing is wired into the VE host-setup scripts and driven by the canonical `setup-broker-host.sh --cloud ve` entry; the operator how-to is the runbook named above.

## Why defer Option A

Nexus + Harbor + an SG-AWS egress node is real infrastructure to stand up **and operate** (patch, backup, monitor, ACL, audit, HA). At the current host count and trust posture that is disproportionate: the public domestic mirrors (Alibaba / ByteDance / VE-own) are the de-facto China standard, and lockfiles (`package-lock.json`, `Cargo.lock`) already pin versions **and** integrity hashes, so the supply-chain surface the cache would harden is already bounded by the lockfiles.

## Honest deferred gaps (what Option B does NOT do)

These are #451's Option-A acceptance items, consciously **not** met by Option B — recorded so a future reader sees the trade, not a silent omission:

- **"No direct public-registry access from prod"** — not met *by design*; we use public mirrors directly.
- **Central pre-sync / retention / cache-miss→egress routing / artifact-service monitoring** — N/A; the public mirrors *are* the cache, with no company-owned pre-sync or audit layer.
- **Digest-pinned OCI images** — N/A today; no container image sits in a VE prod deploy path (that condition is trigger 4 below).

## Triggers — build Option A when ANY fires

1. A supply-chain / compliance mandate to **not trust public mirrors** in prod.
2. A reproducibility / air-gap mandate.
3. The public mirrors proving **unreliable at scale**.
4. **Docker/OCI enters a VE prod deploy path** → stand up Harbor + digest-pinned references.
5. **More than a couple of China hosts / CI runners** — per-host mirror config drift outweighs the cost of a central service.

Until one fires, Option B is the standard. Reopen #451 (or file a scoped follow-up) when a trigger is hit — the heavy build is **deferred, not rejected**.
