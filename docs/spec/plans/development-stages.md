# AgentKeys — Development Stages (v2, 2026-04-23)

**Date:** 2026-04-23
**Previous version:** [`../../archived/development-stages-v1-2026-04.md`](../../archived/development-stages-v1-2026-04.md) — full 1623-line history of stages 0-9.

This doc is the **current-state** roadmap. For everything that's already shipped, each stage gets one line in the Shipped section below. For future work, only the next 1–2 PRs (Active) and the higher-level roadmap (Planned) are called out.

If you're looking for setup / demo instructions, go to [`../../dev-setup.md`](../../dev-setup.md) instead — this file is the plan, not the runbook.

---

## Shipped

| Stage | Milestone | What landed | Done when |
|---|---|---|---|
| 0 | Foundation | `agentkeys-types` + `agentkeys-core` (`CredentialBackend` trait, 15 methods); canonical CBOR for `AuthRequestType`; HMAC OTP derivation | `cargo test` 8/8 |
| 1 | Mock backend | `agentkeys-mock-server` — Axum + SQLite, all 25 endpoints including identity-linking, rendezvous, auth-requests | 37/37 unit + curl smoke |
| 2 | CLI core | `agentkeys-cli` — 10 subcommands (`init`, `store`, `read`, `run`, `revoke`, `usage`, `approve`, `pair`, `recover`, `teardown`) | 14/14 unit + E2E |
| 3 | Daemon + MCP | `agentkeys-daemon` + `agentkeys-mcp` — Unix-socket JSON-RPC, `memfd_secret`, scope enforcement, 4 MCP tools | 13/13 unit |
| 4 | Pair / Approve / Recover | OTP-gated auth requests; 2-terminal pair flow; alias / email / ENS recovery via identity-link table | 15/11 unit + 2-terminal E2E |
| 5a | Provisioner (deterministic) | OpenRouter + OpenAI CDP scrapers; `signupEmailOtp` pattern library; HTML-strip + label-aware OTP extractor; mandatory post-provision verify; `agentkeys provision openrouter` | 59/59 unit + live provision |
| 6 (interim, 2026-04) | Hosted email infra | SES domain verification on `bots.litentry.org`; `agentkeys-daemon` IAM user → `agentkeys-agent` assume-role; S3 inbound bucket; `ses-s3` email backend; end-to-end demo from signup → SES receipt → S3 poll → key extraction | `scripts/stage6-demo-run.sh` prints a valid `sk-or-v1-...` key |

### Non-stage work shipped alongside

- **`~/.claude/skills/agentkeys-workflow-collection/`** — chrome-devtools-mcp-integrated recorder skill for diagnosing provider-side changes.
- **Email analyzer** (`provisioner-scripts/src/lib/email-analyzer.ts`) — shared `analyzeEmail` + `fetchAndAnalyzeSesEmail` helpers. Used by both OpenRouter and OpenAI scrapers.
- **Playwright patterns library** (`provisioner-scripts/src/lib/playwright-patterns.ts`) — `clickOuterCreate`, `probeAndDismissDialog`, captcha helpers.
- **Wiki** (`.omc/wiki/` + `wiki/` spec mirrors) — `email-system`, `oidc-federation`, `hosted-first`, `knowledge-storage`, `tag-based-access`, `overview`.

---

## Active — next 1–2 PRs

### A. Deterministic scraper drift monitor + LLM fallback (Stage 5b)

**Motivation.** Stage 5a scrapers are hard-coded to today's OpenRouter / OpenAI flows. When a provider adds, removes, or reorders a button, the deterministic path breaks silently and every subsequent `provision` request fails until a human updates the script. We need (a) detection before users hit the failure en masse, and (b) a fallback that keeps users unblocked while we patch the deterministic path.

**Scope.**

1. **Telemetry + demand-driven drift runner.** Every `provision` call emits a per-step success/failure telemetry record. The backend batches these; a drift-detection runner fires on an hourly schedule **only when new telemetry has arrived** (no fixed cron). If failure rate on any `(provider, step)` pair crosses threshold, the runner flags the scraper as drifted.
2. **MCP-capable caller fallback.** When a scraper is flagged drifted, callers that advertise MCP capability (Claude Code, Cursor, Zed, Continue.dev, etc., via chrome-devtools-mcp) get handed back a fallback plan instead of the deterministic failure: the daemon surfaces a structured recovery prompt the caller's own LLM drives via the user's chrome-devtools-mcp connection. **No second API key is consumed** — the caller's LLM is doing the agentic work, not ours.
3. **Fallback → PR loop.** Successful fallback runs dump a transcript; maintainers review and convert recurring patterns into deterministic-scraper patches. Nothing auto-submits.

**Explicitly out of scope.** Non-MCP callers (per decision 2026-04-22). We ship Stage 1 only. If a caller cannot speak MCP, they get the deterministic failure — clear error + link to docs.

**Plan doc (detail):** `~/.claude/plans/an-agentkey-user-could-streamed-meteor.md`

### B. Stage 6 finalization — roll into v0.1 hosted path

Today's Stage 6 still lists "interim" AWS-managed DKIM + static IAM user. To call it **finished** for v0.1:

- Replace AWS-managed DKIM with TEE-derived Ed25519 BYODKIM (blocked on `heima-gaps §3`).
- Replace static IAM user with `sts:AssumeRoleWithWebIdentity` against TEE-signed JWTs (Stage 7 overlap — do both at once).
- Move `agentkeys provision openrouter` off the headless-Playwright `openrouter.ts` path and onto the CDP-based `openrouter-cdp.ts` path (or make it selectable via `--cdp`).
- Make AssumeRole auto-refresh inside the daemon instead of requiring the 1-hour manual re-source.

---

## Planned — v0.1 and beyond

### Stage 7 — Generalized OIDC provider

Expose `oidc.agentkeys.dev` as a conforming OIDC Identity Provider. Any cloud that accepts external OIDC federation (AWS, GCP, Azure, Snowflake, K8s) trusts AgentKeys once and gets per-user-wallet-tagged temp creds via standard federation. Unlocks bring-your-own-domain + per-user cloud-enforced isolation via `PrincipalTag`. Scratch notes: [`../../stage7-wip.md`](../../stage7-wip.md). Blocked on: public TLS for `oidc.agentkeys.dev`, TEE-held ES256 signer at `oidc/issuer/v1` (`heima-gaps §3`).

### Stage 8 — Production hardening (Priority A only for v0.1)

- Daemon: `memfd_secret` via `SCM_RIGHTS` fd-passing for managed runtimes; credential zeroize on delivery; idle eviction.
- CLI: `agentkeys whoami`, idempotent `init`, `zeroize` wrapping, `PR_SET_DUMPABLE=0`.
- Optional: Touch-ID-gate master session on macOS; DEK + encrypted-file storage as cross-platform alternative.
- Priority B/C (core pages, ptrace checks, CI checksec) deferred to post-v0.1.

### Stage 9 — Heima migration holding pen

Design notes, not executable work. Pattern 4 (TEE-as-paymaster sponsored audit) chosen for v0.1 audit submission. Rate-limit gate (100 reads/min/session) is a Stage 8 prereq. Tracked in [issues #3, #4, #5](https://github.com/litentry/agentKeys/issues/3).

### npm package + DX polish

Postponed from the original Stage 6. v0 distribution is `cargo install` + prebuilt GH-release binaries. npm packaging, `install.sh`, polished README → v0.1+ when the v0 loop is proven in real use.

---

## How the harness still applies

The v1 plan (archived) spells out five artifacts: `harness/init.sh`, `progress.json`, `features.json`, `stage-N-done.sh`, and git commit discipline. All five remain live. Concrete session startup:

```
jj log --limit 10 && cat harness/progress.json && bash harness/init.sh $(jq -r .current_stage harness/progress.json)
```

New stages must extend `init.sh`, add a `stage-N-done.sh`, update `features.json` per deliverable, and update `progress.json` atomically at completion.

---

## Parallelization

| Track | Depends on | Can run alongside |
|---|---|---|
| Stage 5b (drift + fallback) | Telemetry from live Stage 5a usage | Stage 6 finalization, Stage 7 prep |
| Stage 6 finalization (BYODKIM, auto-AssumeRole) | `heima-gaps §3` | Stage 7 OIDC (shared TEE signing substrate) |
| Stage 7 (OIDC provider) | Public TLS + TEE ES256 | Stage 8 Priority A |
| Stage 8 Priority A | Stage 4 complete (already shipped) | Anything — independent from the above |

Critical path to v0.1 ship: Stage 5b telemetry → Stage 6 finalization → Stage 7 → Stage 8 Priority A. Two devs can split 5b from 6+7+8 cleanly.

---

## Change log

- **2026-04-23 (v2):** collapsed full stage-by-stage contracts into Shipped/Active/Planned; moved v1 to `docs/archived/`.
- **2026-04-19:** Stage 5-7 reorder (old Stage 6/7/8 postponed to v0.1; hosted email + OIDC promoted).
- **2026-04-16:** Stage 5 split into 5a (ships v0) and 5b (v0.1); Stage 6 (npm) postponed.
- Full prior history lives in the archived v1 file.
