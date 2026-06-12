# Broker + Local Operator Dev Guide

**Audience:** developers iterating on the broker, the workers, or the operator-side scripts (`harness/`, `scripts/heima-*.sh`).
**Scope:** the inner edit-build-test loop — running the broker stack on your laptop, exercising it with operator scripts, and knowing which knob to turn when something breaks.

This guide is **not** the environment bootstrap doc (see [`docs/dev-setup.md`](../dev-setup.md)) or the deploy-to-real-host runbook (see [`docs/operator-runbook-stage7.md`](../operator-runbook-stage7.md)). Read those first if you have a fresh machine or you're standing up a new broker EC2.

---

## 1. The local stack at a glance

The deployed broker runs five processes on one EC2. For local dev you run the same five processes on `localhost`, on the same ports, with the same env contract. Same code path — only the env values change.

| Process | Default port | Crate | Purpose | Local-dev role |
|---|---|---|---|---|
| `agentkeys-mock-server` | `:8090` | `agentkeys-mock-server` | v0 backend; mirrors the Heima parachain extrinsic surface | Stand-in for the chain RPC + the legacy session-validation backend |
| `agentkeys-broker-server` | `:8091` | `agentkeys-broker-server` | The credential broker — auth, cap-mint, OIDC issuer | The component you're most often editing |
| `agentkeys-signer` (dev_key_service) | `:8092` | `agentkeys-broker-server` (same binary, different listener) | EVM keypair derivation from `omni_account` via HKDF | Stub for the future TEE signer (see [`signer-protocol.md`](./signer-protocol.md)) |
| `agentkeys-worker-audit` | `:9092` | `agentkeys-worker-audit` | Merkle-root batching for credential audit | Only matters if you're touching audit code |
| `agentkeys-worker-email` | `:9093` | `agentkeys-worker-email` | Inbound email handler (SES → cap-mint trigger) | Only matters for email-link auth |
| `agentkeys-worker-creds` | `:9094` | `agentkeys-worker-creds` | Credential store — STS + S3 PrincipalTag-scoped | The data plane the cap-mint flow leads to |
| `agentkeys-worker-memory` | `:9095` | `agentkeys-worker-memory` | Memory store — STS + S3 (per-actor isolation) | Symmetric with creds |

In the deployed stack `nginx` fronts the broker + signer + 4 workers on `:443` with public hostnames. Locally you talk to the ports directly — no nginx, no TLS.

---

## 2. First-time local-stack bring-up

After [`docs/dev-setup.md`](../dev-setup.md) §1–§2 (rust, jj, node, `cargo build --workspace --release`), generate the broker's two ES256 keypairs once:

```bash
mkdir -p ~/.agentkeys/broker
cargo run -q --release -p agentkeys-broker-server -- keygen --purpose oidc    --out ~/.agentkeys/broker/oidc-keypair.json
cargo run -q --release -p agentkeys-broker-server -- keygen --purpose session --out ~/.agentkeys/broker/session-keypair.json
chmod 600 ~/.agentkeys/broker/{oidc,session}-keypair.json
```

These are the only persistent local state the broker needs. Treat them like any other dev secret — kept under `~/.agentkeys/`, gitignored at the home-directory level, never copied off your laptop. Regenerating them invalidates every previously-derived wallet that depended on the matching session pubkey, so don't `rm` them mid-session.

---

## 3. Inner loop A — edit broker code

The broker reads its config from env vars and the two keypair files. Source a dev env file once per shell, then iterate with `cargo run`.

### 3.1 The dev env

Create `scripts/broker.dev.env` (gitignored — copy + edit from `scripts/broker.env`):

```bash
# Local-dev broker env — everything points at localhost.
ACCOUNT_ID=000000000000                                    # placeholder; AWS calls go to mock backend
BROKER_DATA_ROLE_ARN=arn:aws:iam::000000000000:role/dev    # never assumed in local dev
BROKER_AWS_REGION=us-east-1                                # any region; not actually hit
BROKER_OIDC_ISSUER=http://127.0.0.1:8091                   # matches --bind/--port below
BROKER_OIDC_KEYPAIR_PATH=$HOME/.agentkeys/broker/oidc-keypair.json
BROKER_SESSION_KEYPAIR_PATH=$HOME/.agentkeys/broker/session-keypair.json
BROKER_AUTH_METHODS=wallet_sig,email_link
BROKER_AUDIT_ANCHORS=sqlite                                # sqlite store; never writes to chain
BROKER_EMAIL_SENDER=stub                                   # in-memory; no SES, no AWS creds needed
BROKER_EMAIL_FROM_ADDRESS=dev@localhost
BROKER_BACKEND_URL=http://127.0.0.1:8090                   # points at the local mock-server below

# dev_key_service signer (issue #74 step 1b)
DEV_KEY_SERVICE_MASTER_SECRET=local-dev-secret-32-bytes-min-length-please
```

Three lines matter most for local dev:

- `BROKER_EMAIL_SENDER=stub` — skips SES; magic-link tokens land in an in-process `Vec` that you read back via the test harness or a `curl`-driven `/v1/auth/email/list-pending` endpoint (broker test feature).
- `BROKER_AUDIT_ANCHORS=sqlite` — every audit row lands in a local SQLite file; nothing hits the chain. Set to `evm_testnet` ONLY when you've built with `--features audit-evm` AND you actually want to test the on-chain anchor path (Phase C, not shipped as of PR #102).
- `BROKER_BACKEND_URL` — the broker calls a "backend" for legacy session validation (the v0 mock-server, or a real chain backend in v0.2+). In local dev this points at `agentkeys-mock-server :8090` started in §3.3 below.

### 3.2 Build the broker with the right features

`cargo run` defaults to debug + workspace default features. The broker MUST be built with `--features auth-email-link` if `BROKER_AUTH_METHODS` includes `email_link` (which the dev env above does) — otherwise the broker boot-fails with `BROKER_AUTH_METHODS="email_link": unknown or feature-gated-out auth method`.

```bash
# Iteration build (~10s warm, ~3min cold):
cargo build -p agentkeys-broker-server --features auth-email-link

# Or release for cycle-accurate testing (~30s warm, ~5min cold):
cargo build --release -p agentkeys-broker-server --features auth-email-link
```

Cargo footgun (per [`scripts/setup-broker-host.sh:547`](../../scripts/setup-broker-host.sh)): never combine `-p agentkeys-broker-server -p agentkeys-mock-server --features auth-email-link` — cargo silently drops the feature flag. Always build the two binaries in separate `cargo build` invocations.

### 3.3 Run the three foreground processes

Three terminals. Source the dev env in each; pass `--bind 127.0.0.1 --port <p>`:

```bash
# Terminal 1 — mock-server (v0 backend the broker talks to)
set -a; source scripts/broker.dev.env; set +a
cargo run --release -p agentkeys-mock-server -- --bind 127.0.0.1 --port 8090

# Terminal 2 — broker (your usual edit target)
set -a; source scripts/broker.dev.env; set +a
RUST_LOG=info,agentkeys_broker_server=debug \
  cargo run --release -p agentkeys-broker-server --features auth-email-link -- \
    --bind 127.0.0.1 --port 8091

# Terminal 3 — signer (dev_key_service; serves /dev/derive-address + /dev/sign-*)
set -a; source scripts/broker.dev.env; set +a
cargo run --release -p agentkeys-broker-server -- \
  --bind 127.0.0.1 --port 8092 --signer-only
```

The signer is the SAME binary as the broker (`agentkeys-broker-server`) with `--signer-only` — it serves only `/dev/*` + `/healthz` and shares the keypair files with the broker process on `:8091`.

Skip workers (`agentkeys-worker-{audit,email,creds,memory}` on `:9092-:9095`) until you're editing them — the broker's hot path doesn't require them for most flows.

### 3.4 Sanity check

```bash
curl -s http://127.0.0.1:8091/healthz                                # → "ok"
curl -s http://127.0.0.1:8091/.well-known/openid-configuration | jq . # OIDC discovery doc
curl -s http://127.0.0.1:8091/.well-known/jwks.json | jq .            # broker's JWKS
```

If healthz returns `ok` but the JWKS is empty, the keypair files aren't being read — check the paths in your dev env. If the broker boot-fails with `BROKER_AUTH_METHODS=email_link: unknown`, you forgot `--features auth-email-link` on the cargo build.

### 3.5 Hot-reload loop

There's no `cargo watch` in the workspace, but the dev loop is fast enough without it:

1. Edit Rust in `crates/agentkeys-broker-server/src/...`.
2. `Ctrl-C` Terminal 2's broker.
3. Re-run the `cargo run -p agentkeys-broker-server ...` command from §3.3 (shell history is your friend).
4. The first re-run rebuilds the broker (~10s incremental); subsequent runs reuse the artifact.

For a tighter loop while editing a single module, write a unit test next to the module and use `cargo test -p agentkeys-broker-server <test_name>` — typically <2s per iteration.

---

## 4. Inner loop B — edit operator scripts

The operator-side scripts (`harness/v2-stage{1,2,3}-demo.sh`, `scripts/heima-*.sh`, `scripts/agentkeys-*-demo.sh`) are the dev loop for the *operator workflow*: cap-mint, identity bootstrap, scope grants, S3 isolation tests. They run on your laptop and call the broker (local or remote) via plain HTTP + `cast` + `aws`.

### 4.1 Point the operator env at the local broker

Create `scripts/operator-workstation.dev.env` (gitignored — copy + edit from `scripts/operator-workstation.env`):

```bash
# Local-dev operator env — points the harness scripts at localhost
ACCOUNT_ID=000000000000
REGION=us-east-1
BROKER_HOST=127.0.0.1:8091
OIDC_ISSUER=http://127.0.0.1:8091
AGENTKEYS_SIGNER_URL=http://127.0.0.1:8092
BACKEND_URL=http://127.0.0.1:8090

# Local-stack workers (skip these until you wire them up — broker hot path doesn't need them)
AGENTKEYS_WORKER_AUDIT_URL=http://127.0.0.1:9092
AGENTKEYS_WORKER_EMAIL_URL=http://127.0.0.1:9093
AGENTKEYS_WORKER_CRED_URL=http://127.0.0.1:9094
AGENTKEYS_WORKER_MEMORY_URL=http://127.0.0.1:9095

# Local chain backbone — pick ONE based on what you're testing:
#   anvil          — fully local (forge anvil running on 127.0.0.1:8545); fastest
#   heima-paseo    — Heima testnet; real chain, no real money
#   heima          — Heima mainnet (production); use with care
AGENTKEYS_CHAIN=anvil
```

### 4.2 Run the canonical inner-loop demo

[`harness/v2-stage1-demo.sh`](../../harness/v2-stage1-demo.sh) is the end-to-end exerciser most operator edits land against. It's a 13-step script: install CLI → email-link init → identity bootstrap → S3 envelope smoke test → chain bring-up → device register → agent create → scope grant → K11 enroll → cap-mint roundtrip.

```bash
set -a; source scripts/operator-workstation.dev.env; set +a

# Full demo against local stack:
bash harness/v2-stage1-demo.sh --chain anvil

# Re-run just one step you're iterating on:
bash harness/v2-stage1-demo.sh --only-step 7

# Skip the slow bits (CLI build, chain deploy, S3 provisioning):
bash harness/v2-stage1-demo.sh --skip-build --skip-deploy --skip-provision

# Stop after a specific step (useful when bisecting a regression):
bash harness/v2-stage1-demo.sh --to-step 5
```

The `--from-step N` / `--to-step N` / `--only-step N` triad is the inner-loop primitive — every step prints `[step N/M]` to stderr, every step is idempotent. If step 7 fails after a script edit, fix the script, re-run with `--from-step 7`, you keep the work from steps 1–6.

### 4.3 Anvil for fully-local chain dev

When you don't want to talk to Heima at all, run [foundry](https://book.getfoundry.sh/anvil/) anvil locally:

```bash
# Terminal 4 — local EVM (anvil) on :8545
anvil --chain-id 31337 --port 8545
```

Then `AGENTKEYS_CHAIN=anvil` in your operator env makes every `cast send` hit anvil instead of Heima. The deployer wallet is whichever anvil-prefunded key you point at via `HEIMA_DEPLOYER_KEY` / `HEIMA_DEPLOYER_KEY_FILE`. Anvil's mempool is single-tenant — none of the [PR #102 nonce-contention issues](../ci-setup.md) bite locally.

### 4.4 Editing `setup-broker-host.sh`

`scripts/setup-broker-host.sh` is the canonical "single entry point" for the broker EC2 (per AGENTS.md "Remote broker host (single entry point)" policy). When you change it, the unit-test is to dry-run it on a throwaway VM, but the practical inner loop is:

1. Edit the script.
2. `bash -n scripts/setup-broker-host.sh` — syntax check.
3. SSH into the test broker EC2 (`bash scripts/ssh-broker.sh`), `cd ~/agentKeys`, `git pull`, `bash scripts/setup-broker-host.sh --test --yes` — exercise the full path.
4. **Or** push to your PR branch and let the [CI auto-deploy](#5-inner-loop-c--ci-auto-deploy-issue-101) (PR #102) drive it on the test EC2.

Step 4 is usually faster — no SSH, you get fresh logs in the GHA run, and the harness validates the deploy end-to-end.

---

## 5. Inner loop C — CI auto-deploy (issue #101)

Per [PR #102](https://github.com/litentry/agentKeys/pull/102), pushing broker-affecting changes to a PR branch auto-deploys to the test EC2 via SSM and runs the full harness against the freshly-deployed broker. You see broker bugs in your own PR, not the next operator's.

What counts as "broker-affecting" — the path-filter list in [`.github/workflows/harness-ci.yml`](../../.github/workflows/harness-ci.yml):

```
crates/agentkeys-broker-server/**
crates/agentkeys-worker-*/**
crates/agentkeys-signer-protocol/**
crates/agentkeys-types/**
crates/agentkeys-core/**
scripts/setup-broker-host.sh
scripts/setup-broker-host.sh.d/**
scripts/broker.env
scripts/broker.test.env
Cargo.toml
Cargo.lock
```

Untouched + auto-deploy is opt-in (gated on `OIDC_AWS_ROLE_ARN_DEPLOY` + `TEST_BROKER_INSTANCE_ID` repo secrets — see [`docs/ci-setup.md`](../ci-setup.md) §7).

To dry-run the deploy without a broker code change, dispatch manually with the override:

```bash
gh workflow run harness-ci.yml --repo litentry/agentKeys \
  --ref <your-branch> \
  --field stage=1 \
  --field force_deploy_broker=true
```

---

## 6. Config-file map — which file controls what

Three files, three audiences. The "is the broker reading the right thing" debug usually comes down to which one you sourced.

| File | Where it lives | Who reads it | Local-dev override |
|---|---|---|---|
| [`scripts/broker.env`](../../scripts/broker.env) | **Broker host** (EC2 or your laptop's broker process) | `agentkeys-broker-server` (every entry has a matching constant in `crates/agentkeys-broker-server/src/env.rs`) | `scripts/broker.dev.env` (gitignored, copied from `broker.env`, swap hosts to `127.0.0.1`) |
| [`scripts/operator-workstation.env`](../../scripts/operator-workstation.env) | **Operator laptop** | Every `harness/` + `scripts/heima-*.sh` script | `scripts/operator-workstation.dev.env` (gitignored, swap hosts to `127.0.0.1:809x`) |
| [`scripts/broker.test.env`](../../scripts/broker.test.env) | **Test broker host** (CI auto-deploy target) | `agentkeys-broker-server` running on the test EC2 | Same shape as `broker.env`; CI workflow materializes per-run values into this on the runner |

Mixing them on the wrong host is the most common config bug. The broker host should NEVER source `operator-workstation.env` — that file has AWS admin tooling vars (BUCKET, OIDC_PROVIDER_ARN) that don't exist as broker-server env vars and would silently shadow what the broker actually reads.

---

## 7. Debugging cheatsheet

### 7.1 Logs

The broker uses `tracing_subscriber` with `EnvFilter` ([`crates/agentkeys-broker-server/src/main.rs:73`](../../crates/agentkeys-broker-server/src/main.rs)). Control via `RUST_LOG`:

```bash
# Default — only INFO and above
cargo run -p agentkeys-broker-server -- ...

# Verbose for the broker, quiet for everything else
RUST_LOG=info,agentkeys_broker_server=debug cargo run -p agentkeys-broker-server -- ...

# Trace-level for one specific module
RUST_LOG=info,agentkeys_broker_server::handlers::cap=trace cargo run -p agentkeys-broker-server -- ...
```

On the deployed broker, logs go to systemd journal:

```bash
ssh broker journalctl -u agentkeys-broker --since '5 min ago' -f
ssh broker journalctl -u agentkeys-signer --since '5 min ago' -f
```

### 7.2 Port collisions

If `cargo run` errors with `Address already in use`, find the stuck process:

```bash
lsof -nP -iTCP:8091 -sTCP:LISTEN     # broker
lsof -nP -iTCP:8090 -sTCP:LISTEN     # mock-server
lsof -nP -iTCP:8092 -sTCP:LISTEN     # signer
```

Kill by PID (the only `kill -9` you should reach for during dev) or by name: `pkill -f agentkeys-broker-server`.

### 7.3 The broker boots, then immediately exits

Common shapes:

| Symptom | Cause | Fix |
|---|---|---|
| `BROKER_AUTH_METHODS="email_link": unknown or feature-gated-out auth method` | Built without `--features auth-email-link` | Re-build with the feature; see §3.2 |
| `failed to read OIDC keypair: No such file` | `BROKER_OIDC_KEYPAIR_PATH` doesn't exist | Re-run the `keygen` from §2 |
| `BROKER_BACKEND_URL=http://127.0.0.1:8090: connection refused` | Mock-server isn't running on `:8090` | Start it (Terminal 1 in §3.3) |
| Broker logs are silent | `RUST_LOG` unset and the default filter is too quiet for what you want | Add `RUST_LOG=debug` to your `cargo run` command |
| `SES GetEmailIdentity: AccessDenied` | `BROKER_EMAIL_SENDER=ses` but no AWS creds in the shell | Set `BROKER_EMAIL_SENDER=stub` for local dev |

### 7.4 The harness fails at a specific step

Re-run with `--from-step N` to keep prior progress, OR `--only-step N` to test one step in isolation. Every step is idempotent — re-running a passed step is a no-op. If `--only-step 7` fails the same way as the full run, the bug is in that step's script; if it passes, the bug is cross-step state that the previous steps mutated.

---

## 8. Chain profile selection

`AGENTKEYS_CHAIN` controls which RPC + which contract addresses every harness script talks to. Default in `v2-stage1-demo.sh` is `heima-paseo`; common alternates:

| Profile | RPC | When to use | Cost |
|---|---|---|---|
| `anvil` | `http://127.0.0.1:8545` | Fully local; fastest iteration; no real-world side effects | Free |
| `heima-paseo` | Heima testnet | Real-chain semantics without real-money cost; default for `v2-stage1-demo.sh` | Testnet HEI (free from faucet) |
| `heima` | Heima mainnet | The canonical chain; matches what CI's harness-e2e runs against | Real HEI — small per-run cost |

Switch with `--chain` on any harness script. Contract addresses for `heima` and `heima-paseo` live in [`scripts/operator-workstation.env`](../../scripts/operator-workstation.env); add `anvil` ones by running `bash scripts/setup-heima.sh --chain anvil --from-step 4 --to-step 8` after starting your local anvil.

---

## 9. Related docs

- [`docs/arch.md`](../arch.md) — single source of truth for component inventory + trust boundaries.
- [`docs/dev-setup.md`](../dev-setup.md) — first-time machine bootstrap (rust, jj, node, AWS CLI, browser).
- [`docs/operator-runbook-stage7.md`](../operator-runbook-stage7.md) — deploy-to-real-EC2 walkthrough (manual; not for local dev).
- [`docs/ci-setup.md`](../ci-setup.md) — no-LLM CI + auto-deploy of test broker (issue #101 / PR #102).
- [`docs/spec/signer-protocol.md`](./signer-protocol.md) — wire contract for the signer (TEE swap-in target).
- [`docs/spec/credential-backend-interface.md`](./credential-backend-interface.md) — the `CredentialBackend` trait; what the broker's storage plug-ins must implement.
- [`docs/archived/development-stages-v2-2026-04.md`](../archived/development-stages-v2-2026-04.md) — the staged build plan + harness gates.
