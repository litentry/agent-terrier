# AgentKeys Dev Setup + Demo Guide

**Audience:** a developer picking up AgentKeys for the first time, or a collaborator running the Stage 5a / Stage 6 demo end-to-end.
**Scope:** everything you need to build, run the mock backend, and provision an OpenRouter or OpenAI key via the canonical CDP-based demo path. Operator-level one-time AWS setup lives in [`stage6-aws-setup.md`](./stage6-aws-setup.md) — do that first if it isn't already done for your account.

The CDP demo path is **the only supported path** — earlier Gmail-backed variants are archived under [`archived/`](./archived/) and should not be used for new work.

## 1. Prerequisites

| Tool | Why | Install |
|---|---|---|
| Rust (stable, edition 2021+) | Workspace crates | `rustup toolchain install stable && rustup default stable` |
| Node 20+ | `provisioner-scripts/` (TypeScript scrapers, tsx) | nvm / asdf / system install |
| Google Chrome | CDP scrapers connect to real Chrome to bypass Turnstile | Standard download |
| AWS CLI v2 | Demo uses SES + S3 inbound email and `sts:AssumeRole` | `brew install awscli` |
| `jj` | All VCS operations — never raw `git` | `brew install jj` (see [jj docs](https://github.com/martinvonz/jj)) |
| `jq` | Required by the helper scripts and by the runbook's JSON-generation pattern | `brew install jq` |

Optional but recommended:

- **1Password CLI** — for pulling the `agentkeys-daemon` / `agentkeys-admin` AWS creds without leaking them to shell history.
- **chrome-devtools-mcp** — auto-wired via `.mcp.json` when you open this repo in Claude Code / Cursor / Zed / Continue.dev. Gives the workflow-collection skill tool-level access to a live Chrome for diagnosing provider-side changes.

## 2. Build everything

```bash
cd ~/Projects/agentkeys   # or wherever your checkout lives
cargo build --workspace --release
npm install --prefix provisioner-scripts
npx --prefix provisioner-scripts playwright install chromium --with-deps
```

Smoke-test the build:

```bash
cargo test --workspace
npm test --prefix provisioner-scripts
```

Expect a clean pass on both. If Rust fails, stop and fix before moving on — the mock backend and CLI have to build before anything else is runnable.

## 3. One-time: Stage 6 AWS setup

Run through [`stage6-aws-setup.md`](./stage6-aws-setup.md) through §7 once per AWS account. Afterwards you should have:

- SES domain identity verified on `bots.litentry.org` (or your substitute via `AGENTKEYS_EMAIL_DOMAIN`)
- `agentkeys-daemon` IAM user with `sts:AssumeRole` only
- `agentkeys-agent` role with SES + S3 permissions
- S3 bucket `agentkeys-mail-<ACCOUNT_ID>` with receipt rule writing inbound to `inbound/`
- Route 53 records: three DKIM CNAMEs, MX, SPF, DMARC

Stash the daemon user's long-lived creds in 1Password (or your OS keychain) — never export them globally into your shell.

## 4. Demo: OpenRouter (CDP + SES inbox)

Canonical end-to-end demo. Three terminals.

### 4.1 Source the env helper (any terminal)

```bash
# Populate DAEMON_ACCESS_KEY_ID / DAEMON_SECRET_ACCESS_KEY from your secret store first.
source scripts/stage6-demo-env.sh
```

`stage6-demo-env.sh` calls `sts:AssumeRole` as the daemon, exports 1-hour temp creds into `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`, and sets `AGENTKEYS_EMAIL_BACKEND=ses-s3`. Re-source if creds expire (typical run is 1–3 min).

### 4.2 Terminal A — mock backend (leave running)

```bash
cargo run --release -p agentkeys-mock-server -- --port 8090
# → Mock server running on port 8090
```

### 4.3 Terminal B — real Chrome with CDP (leave running)

```bash
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --remote-debugging-port=9222 \
  --user-data-dir=/tmp/agentkeys-chrome-profile
```

Leave this Chrome window open. You may need to click a visible Turnstile checkbox once per fresh profile.

### 4.4 Terminal C — init + provision

```bash
BIN=$(pwd)/target/release/agentkeys
$BIN --backend http://127.0.0.1:8090 init --mock-token stage6-demo

KEY=$(./scripts/stage6-demo-run.sh | tail -1)
echo "extracted: ${KEY:0:12}****...${KEY: -4}"

$BIN --backend http://127.0.0.1:8090 store openrouter "$KEY"
$BIN --backend http://127.0.0.1:8090 read openrouter
# → full key

curl -sS -H "Authorization: Bearer $KEY" \
  https://openrouter.ai/api/v1/models | head -c 200
# → HTTP 200 with JSON body
```

`scripts/stage6-demo-run.sh` refreshes the per-run signup email, drives the CDP scraper (`provisioner-scripts/src/scrapers/openrouter-cdp.ts`), streams logs to `/tmp/cdp.log`, handles both the magic-link and legacy 6-digit-OTP Clerk flows, and prints the extracted key on stdout.

Success criteria (same as Stage 6 acceptance):

1. The scraper exits 0 with a key on stdout
2. Key matches `sk-or-v1-[a-zA-Z0-9]+`
3. `agentkeys read openrouter` returns that same key
4. `curl` against `/api/v1/models` returns HTTP 200

## 5. Demo: OpenAI (CDP + SES inbox)

Same shape as §4. The OpenAI scraper handles a post-verify profile step (first/last name + age + Tab blur) automatically, and uses label-aware OTP extraction so CSS hex colors in the email body never get mistaken for the code.

```bash
# After steps 4.1, 4.2, 4.3 are already running:
export AGENTKEYS_SIGNUP_EMAIL="bot-$(date +%s)@bots.litentry.org"
export AGENTKEYS_SIGNUP_PASSWORD="Demo-$(date +%s)-xZq9okFg"

npx --prefix provisioner-scripts tsx src/scrapers/openai-cdp.ts 2>&1 | tee /tmp/openai-cdp.log
KEY=$(tail -1 /tmp/openai-cdp.log)

$BIN --backend http://127.0.0.1:8090 store openai "$KEY"
curl -sS -H "Authorization: Bearer $KEY" https://api.openai.com/v1/models | head -c 200
```

## 6. Verifying your change

The harness tracks stage completion in `harness/progress.json`. Before opening a PR:

```bash
jj log --limit 10
cat harness/progress.json
bash harness/init.sh $(jq -r .current_stage harness/progress.json)
bash harness/stage-$(jq -r .current_stage harness/progress.json)-done.sh
cargo test --workspace
npm test --prefix provisioner-scripts
```

The stage-done script is the authoritative evaluator — never self-grade. If it exits 0, you're good.

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Cannot find package 'tsx'` | Running a scraper from repo root instead of `provisioner-scripts/` | Use `scripts/stage6-demo-run.sh`, or `cd provisioner-scripts` first |
| `ExpiredToken` in `/tmp/cdp.log` | STS temp creds are >1h old | `source scripts/stage6-demo-env.sh` again |
| Scraper hangs at `waiting for Turnstile` for >2 min | Turnstile showing a visible checkbox | Click it in the Chrome window from §4.3 |
| Turnstile repeatedly fails even after checkbox | Chromium profile fingerprint flagged | `rm -rf /tmp/agentkeys-chrome-profile` and restart Chrome |
| `env not loaded` in demo script | Missed `source scripts/stage6-demo-env.sh` | Source first, then run the demo script |
| `MalformedPolicyDocument: ... failed legacy parsing` during Stage 6 setup | Heredoc-generated JSON lost a `$VAR:r` / `$VAR:h` to a zsh modifier | Use the `jq -n --arg … '{…}'` pattern — never heredoc JSON into AWS calls |
| Mock server won't bind port 8090 | Stale process | `lsof -i :8090`, kill, restart |
| `agentkeys init` double-prompts on macOS | Known keyring-rs update path | Filed under Stage 8 "idempotent init" item |
| `bot-<ts>@bots.litentry.org` email never arrives | DNS / MX / SES receipt-rule misconfigured, or bucket missing write perm | `aws s3 ls s3://$BUCKET/inbound/ --recursive` — if empty >60s after signup, re-verify §2–§5 of `stage6-aws-setup.md` |

## 8. When a provider changes their flow

Providers add, remove, and reorder signup steps. When a deterministic scraper breaks, diagnose with the `/agentkeys-workflow-collection` skill — it drives a real Chrome session via `chrome-devtools-mcp` to produce a diff-ready transcript. That transcript is what feeds back into the scraper's pattern library.

The longer-term plan (Stage 5b) is to detect drift automatically from telemetry and hand MCP-capable callers a fallback that their own LLM can drive — details in [`spec/plans/development-stages.md`](./spec/plans/development-stages.md) § Active.

## 9. Further reading

- [`spec/plans/development-stages.md`](./spec/plans/development-stages.md) — Shipped / Active / Planned roadmap
- [`stage6-aws-setup.md`](./stage6-aws-setup.md) — one-time AWS infra for Stage 6
- [`stage7-wip.md`](./stage7-wip.md) — OIDC-federated variant for v0.1+
- [`spec/credential-backend-interface.md`](./spec/credential-backend-interface.md) — 15-method trait contract
- [`spec/ses-email-architecture.md`](./spec/ses-email-architecture.md) — Stage 6 email pipeline deep-dive
- `.omc/wiki/email-system.md`, `oidc-federation.md`, `hosted-first.md` — architecture wiki
- [PR #52](https://github.com/litentry/agentKeys/pull/52) — merged Stage 5 + 6 completion (foundation for this guide)
- [`archived/`](./archived/) — prior-snapshot docs; read-only reference, not a setup path
