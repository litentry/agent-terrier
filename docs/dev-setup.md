# AgentKeys Dev Setup + Demo Guide

**Audience:** anyone touching AgentKeys for the first time, regardless of role.
**Scope:** environment bootstrap, then role-keyed setup so each contributor sets up only what they need.

The CDP demo path is **the only supported path** — earlier Gmail-backed variants are archived under [`archived/`](./archived/) and should not be used for new work.

## 1. Prerequisites (everyone)

### Quick path: one-shot bootstrap (macOS + Linux)

Fresh machine? Run the bootstrap script — it installs every prerequisite below, builds the workspace, and runs the smoke tests:

```bash
bash scripts/setup-dev-env.sh
```

The script is idempotent (safe to re-run), detects macOS vs Linux (apt / dnf / pacman), and handles:

- Homebrew (macOS) or the system package manager (Linux)
- `rustup` + stable toolchain
- Node 20+ (Homebrew `node@20`, NodeSource on apt/dnf, distro package on Arch)
- `jj` (Homebrew / pacman, or `cargo install jj-cli` as fallback) — also seeds the required `Hanwen Cheng <heawen.cheng@gmail.com>` jj identity if unset
- `jq`
- AWS CLI v2 (Homebrew on macOS, official zip on Linux) — needed only by the **operator** role; harmless to have everywhere
- `cargo build --workspace --release`
- `npm install --prefix provisioner-scripts` + `playwright install chromium`
- `cargo test --workspace` and `npm test --prefix provisioner-scripts` as a smoke gate

Two things the script intentionally does **not** do:

1. **Install Google Chrome.** The CDP scrapers attach to real Chrome at `localhost:9222`; install it from <https://www.google.com/chrome/>.
2. **Touch AWS infra.** That's the one-time operator setup in §5.2.

### Other setup scripts at a glance

| Script | Audience | What it does |
|---|---|---|
| [`scripts/setup-dev-env.sh`](../scripts/setup-dev-env.sh) | Anyone — fresh dev machine | Installs every prerequisite above, builds workspace, runs smoke tests. (The one you just ran.) |
| [`scripts/setup-broker-host.sh`](../scripts/setup-broker-host.sh) | Operator — fresh broker host | Provisions a Linux host into a running broker: builds binaries, creates the `agentkeys` system user, drops systemd units, optional nginx + Let's Encrypt. Idempotent. See [`stage7-wip.md` "Remote deployment"](./stage7-wip.md) for the manual long-form walk-through. |

### Manual matrix (if you'd rather pick tools yourself)

| Tool | Why | Install |
|---|---|---|
| Rust (stable, edition 2021+) | Workspace crates | `rustup toolchain install stable && rustup default stable` |
| Node 20+ | `provisioner-scripts/` (TypeScript scrapers, tsx) | nvm / asdf / system install |
| Google Chrome | CDP scrapers connect to real Chrome to bypass Turnstile | Standard download |
| AWS CLI v2 | Operator-only — SES + S3 inbound email and `sts:AssumeRole` | `brew install awscli` |
| `jj` | All VCS operations — never raw `git` | `brew install jj` (see [jj docs](https://github.com/martinvonz/jj)) |
| `jq` | Required by the helper scripts and by the runbook's JSON-generation pattern | `brew install jq` |

Optional but recommended:

- **chrome-devtools-mcp** — auto-wired via `.mcp.json` when you open this repo in Claude Code / Cursor / Zed / Continue.dev. Gives the workflow-collection skill tool-level access to a live Chrome for diagnosing provider-side changes.

## 2. Build everything (everyone)

If you ran `scripts/setup-dev-env.sh` in §1, the workspace is already built and tested — skip ahead to §3. Otherwise:

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

Expect a clean pass on both. If Rust fails, stop and fix before moving on — every role needs the workspace to build.

## 3. Pick your role

AgentKeys has three roles. Each runs a different set of processes and holds a different set of secrets. The **broker server** ([Stage 7](./stage7-wip.md)) is the boundary that lets these stay separated — the operator's AWS keys never leave the operator's machine.

| Role | What you run | What you hold | Read |
|---|---|---|---|
| **App developer** — building an agent against AgentKeys | `agentkeys-daemon` + an agent process | A short-lived bearer token from the operator. **Zero AWS credentials.** | §4 |
| **App owner / operator** — running the broker for a team | `agentkeys-broker-server` (+ optionally the mock backend in dev) | Long-lived `agentkeys-daemon` AWS access key (persisted in `~/.zshenv` or supervisor-managed env). The broker's own master session. | §5 |
| **End user** — using a credential-brokered agent | `agentkeys` CLI | A 30-day master session token in OS keychain. | §6 |

**Solo dev?** You'll wear all three hats. Read §5 first to stand up your own broker, then §4 to point a daemon at it, then §6 for the user-facing CLI.

## 4. App developer

You're building an agent that needs OpenAI / OpenRouter / X / etc. credentials brokered through AgentKeys. You do **not** run AWS. You do **not** hold long-lived credentials. You run a daemon and point it at a broker your operator already provisioned.

### 4.1 What you need from the operator

- `AGENTKEYS_BROKER_URL` — e.g. `http://broker.local:8091` or `https://broker.litentry.org`.
- `AGENTKEYS_BEARER_TOKEN` — short-lived; the operator hands these out per-developer.

That's it. No AWS keys, no `aws sts assume-role`, no per-developer env scripting.

### 4.2 Run the daemon against the broker

```bash
export AGENTKEYS_BROKER_URL=http://broker.local:8091
export AGENTKEYS_BEARER_TOKEN=<token your operator gave you>

BIN=$(pwd)/target/release/agentkeys-daemon
$BIN --broker-url "$AGENTKEYS_BROKER_URL" --session "$AGENTKEYS_BEARER_TOKEN" --stdio
```

When the daemon needs to access the operator's S3 vault (to read or store a credential), it calls the broker's `POST /v1/mint-aws-creds` with the bearer token. The broker exchanges it for a 1-hour scoped AWS session and hands it back — you never touch the long-lived daemon AWS key.

### 4.3 Provision a new service

The provisioner scripts run unchanged from your machine. With `--broker-url` set, the daemon (or the `agentkeys` CLI directly) calls the broker's `/v1/mint-oidc-jwt` + `AssumeRoleWithWebIdentity` (issue #71 Option A) right before spawning the scraper subprocess, and injects 1-hour scoped `AWS_*` env vars into the child process. You don't need to set any AWS env vars yourself.

```bash
$BIN --broker-url "$AGENTKEYS_BROKER_URL" --session "$AGENTKEYS_BEARER_TOKEN" \
     provision openrouter --identity bot-$(date +%s)@bots.example.dev
```

Or via the CLI:

```bash
agentkeys --broker-url "$AGENTKEYS_BROKER_URL" provision openrouter
```

Success criteria:

1. The scraper exits 0 with a key on stdout.
2. `agentkeys read openrouter` returns that same key.

If the scraper fails, see §8 troubleshooting.

## 5. App owner / operator

You operate the AgentKeys infrastructure for a team. You hold the long-lived `agentkeys-daemon` AWS key. You run the broker server. Other developers point their daemons at your broker.

### 5.1 One-time: AWS setup

Run through [`cloud-setup.md`](./cloud-setup.md) §1–§3 once per AWS account. Afterwards you'll have:

- SES domain identity verified on `bots.litentry.org` (or your substitute via `AGENTKEYS_EMAIL_DOMAIN`)
- `agentkeys-daemon` IAM user with `sts:AssumeRole` only
- `agentkeys-data-role` role with SES + S3 permissions
- S3 bucket `agentkeys-mail-<ACCOUNT_ID>` with receipt rule writing inbound to `inbound/`
- Route 53 records: three DKIM CNAMEs, MX, SPF, DMARC

Manage the daemon user's long-lived AWS keys via a **named profile** in `~/.aws/credentials` (mode 0600). The broker uses the AWS SDK's default credential chain — `AWS_PROFILE` (set by `awsp` or your shell), the shared credentials file, or an EC2 instance profile via IMDS. **No long-lived AWS keys live in env vars.** See [`operator-runbook.md` §2](./operator-runbook.md#2-aws-credentials) for the full credential story.

### 5.2 Run the broker server

The broker holds your AWS daemon credentials (via the SDK default chain) and brokers scoped temp credentials to authenticated daemons. Same binary local + hosted; only the credential source differs.

**Local development shape:**

```bash
# Activate the daemon profile so the AWS SDK can resolve credentials.
awsp agentkeys-daemon                                # or: export AWS_PROFILE=agentkeys-daemon

# Non-secret config: BROKER_BACKEND_URL is required; the rest derive
# from ACCOUNT_ID + REGION already in your shell.
export BROKER_BACKEND_URL="http://127.0.0.1:8090"    # mock backend for v0.1 dev loop

cargo run --release -p agentkeys-broker-server -- --port 8091
# → "AWS credentials: SDK default chain (AWS_PROFILE / ~/.aws / IMDS)"
# → "broker listening on 0.0.0.0:8091"
```

The broker:

1. Validates incoming bearer tokens against `BROKER_BACKEND_URL` (the mock server in dev; the real chain backend in v0.2+).
2. Calls `sts:assume-role` on `BROKER_DATA_ROLE_ARN` using whatever credentials the SDK default chain returned.
3. Returns 1-hour temp creds to the caller.
4. Logs every mint to `BROKER_AUDIT_DB_PATH` (SQLite, one row per mint).

For runbook detail (start / supervise / rotate / monitor / migrate to hosted), see [`docs/operator-runbook.md`](./operator-runbook.md).
For the automated remote-host bootstrap, see [`scripts/setup-broker-host.sh`](../scripts/setup-broker-host.sh).

### 5.3 Hand off bearer tokens to your developers

For v0.1 each developer gets a session token by running `agentkeys init` against your mock backend (or the real chain backend). The token they receive is what they paste into `AGENTKEYS_BEARER_TOKEN` per §4.1. Token TTL is 30 days per [`wiki/session-token.md`](../wiki/session-token.md).

### 5.4 Solo-dev mock-backend loop

If you're running everything on one box (typical solo dev), you'll want three terminals up:

```bash
# Terminal A — mock backend
cargo run --release -p agentkeys-mock-server -- --port 8090

# Terminal B — broker. AWS credentials come from the active profile.
awsp agentkeys-daemon
export BROKER_BACKEND_URL=http://127.0.0.1:8090
cargo run --release -p agentkeys-broker-server -- --port 8091

# Terminal C — real Chrome with CDP (only if you're running scrapers)
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --remote-debugging-port=9222 \
  --user-data-dir=/tmp/agentkeys-chrome-profile
```

Then in a fourth terminal you wear the **app-developer** hat (§4): point a daemon at `http://127.0.0.1:8091`, with a bearer token minted via `agentkeys init` against `127.0.0.1:8090`.

## 6. End user

You're using an agent that's been provisioned via AgentKeys. Your only commitment is a 30-day session token that lives in your OS keychain. Your agent's daemon goes through someone else's broker — you don't run any AWS yourself.

```bash
BIN=$(pwd)/target/release/agentkeys
$BIN --backend "$AGENTKEYS_BACKEND_URL" init
# → mints a session, stores it in keychain
$BIN --backend "$AGENTKEYS_BACKEND_URL" read openrouter
# → returns the API key
```

The user-facing CLI surface is unchanged from prior stages; the broker is invisible from this side.

## 7. Verifying your change

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

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Cannot find package 'tsx'` | Running a scraper from repo root instead of `provisioner-scripts/` | `cd provisioner-scripts && npm install` first, or invoke via the daemon's `provision` subcommand which sets the cwd correctly |
| `ExpiredToken` from broker | Broker's daemon AWS key was rotated; broker process holds the old one | Restart the broker process — the SDK re-reads `~/.aws/credentials` (or IMDS / env vars) on start |
| `401 Unauthorized` from broker | Bearer token expired (30-day TTL), or token issued against a different backend | Re-run `agentkeys init` against the broker's `BROKER_BACKEND_URL` |
| Scraper hangs at `waiting for Turnstile` for >2 min | Turnstile showing a visible checkbox | Click it in the Chrome window from §5.4 |
| Turnstile repeatedly fails even after checkbox | Chromium profile fingerprint flagged | `rm -rf /tmp/agentkeys-chrome-profile` and restart Chrome |
| Mock server won't bind port 8090 | Stale process | `lsof -i :8090`, kill, restart |
| Broker won't bind port 8091 | Stale process | `lsof -i :8091`, kill, restart |
| `agentkeys init` double-prompts on macOS | Known keyring-rs update path | Filed under Stage 9 "idempotent init" item |
| `bot-<ts>@bots.litentry.org` email never arrives | DNS / MX / SES receipt-rule misconfigured, or bucket missing write perm | `aws s3 ls s3://$BUCKET/inbound/ --recursive` — if empty >60s after signup, re-verify [`cloud-setup.md` §1–§2](./cloud-setup.md#1-domain--dns) |
| `MalformedPolicyDocument: ... failed legacy parsing` during operator setup | Heredoc-generated JSON lost a `$VAR:r` / `$VAR:h` to a zsh modifier | Use the `jq -n --arg … '{…}'` pattern — never heredoc JSON into AWS calls |

## 9. When a provider changes their flow

Providers add, remove, and reorder signup steps. When a deterministic scraper breaks, diagnose with the `/agentkeys-workflow-collection` skill — it drives a real Chrome session via `chrome-devtools-mcp` to produce a diff-ready transcript. That transcript is what feeds back into the scraper's pattern library.

The longer-term plan (Stage 5b) is to detect drift automatically from telemetry and hand MCP-capable callers a fallback that their own LLM can drive — details in [`spec/plans/development-stages.md`](./spec/plans/development-stages.md) § Active.

## 10. Further reading

- [`spec/plans/development-stages.md`](./spec/plans/development-stages.md) — Shipped / Active / Planned roadmap
- [`cloud-setup.md`](./cloud-setup.md) — one-time AWS infra (DNS, SES, S3, IAM, OIDC federation)
- [`stage7-wip.md`](./stage7-wip.md) — broker server design + acceptance test
- [`operator-runbook.md`](./operator-runbook.md) — start, supervise, rotate, monitor the broker
- [`spec/credential-backend-interface.md`](./spec/credential-backend-interface.md) — 15-method trait contract
- [`spec/ses-email-architecture.md`](./spec/ses-email-architecture.md) — Stage 6 email pipeline deep-dive
- [`spec/threat-model-key-custody.md`](./spec/threat-model-key-custody.md) — what the broker is defending against
- `.omc/wiki/email-system.md`, `oidc-federation.md`, `hosted-first.md` — architecture wiki
- [PR #52](https://github.com/litentry/agentKeys/pull/52) — merged Stage 5 + 6 completion (foundation for this guide)
- [`archived/`](./archived/) — prior-snapshot docs; read-only reference, not a setup path
