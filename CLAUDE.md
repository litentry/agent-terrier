# AgentKeys

## Architecture
Rust monorepo with Cargo workspace. See `docs/spec/architecture.md` for component inventory.
See `docs/spec/credential-backend-interface.md` for the CredentialBackend trait contract (15 methods).
See `docs/spec/plans/development-stages.md` for the 8-stage build plan.
See `docs/spec/plans/execution-plan.md` for the orchestration runbook (ralph, team, ultraqa).
Do not read folder `docs/archived`

## Architecture-as-source-of-truth policy
[`docs/spec/architecture.md`](docs/spec/architecture.md) is the **single source of truth** for component inventory, key inventory (K1–K11), trust boundaries, identity model (HDKD actor tree), and per-actor binding ceremonies. **After editing any architectural doc** (broker plans, signer-protocol, demo doc, runbooks, plan files in `docs/spec/plans/`, heima-gaps), re-open `architecture.md` and verify it still matches; if it diverges, update arch.md in the same change. If the per-doc detail outgrows arch.md, link from arch.md outward — never duplicate. The wiki page at [`wiki/agent-role-and-usage-hdkd-per-agent-omni.md`](wiki/agent-role-and-usage-hdkd-per-agent-omni.md) is a focused operator reference for the agent role; it defers to arch.md.

## `/create-pr` policy
When the `/create-pr` skill is invoked from a Claude Code worktree at `.claude/worktrees/<name>`, the worktree is a *git worktree* under the main repo — `jj` cannot colocate there (`jj git init --colocate` fails with "Cannot create a colocated jj repo inside a Git worktree"). Use this hybrid workflow so the jj-only rule is preserved everywhere it can be:

1. **Commit (worktree, git — unavoidable).** From the worktree, `git add <explicit files> && git commit -m "<message>"`. Git is necessary at this step because jj cannot read a git-worktree's filesystem; the commit lands in the shared git object store and advances the branch ref. **Do NOT include `Co-Authored-By:` lines** — the commit author is the agent identity that ran the commit (`wildmeta-agent`); appended co-author tags are wrong attribution.
2. **Push (main repo, jj).** `cd` to the main repo (`~/Projects/agentKeys`), then `jj git fetch && jj git push -b <branch-name>` to push to `origin`. This is the jj-required step — jj fully controls remote interaction once the commit exists locally.
3. **PR (anywhere, gh).** `gh pr create --title "..." --body "$(cat <<'EOF' ... EOF)"`. The gh CLI is not git/jj-specific.

Outside Claude Code worktrees (i.e. directly in the main repo), the whole flow is jj per the standard "use `jj`, never raw `git`" rule from this file.

## Wiki-location policy
**All project wiki pages live under [`./wiki/`](wiki/) — never under `.omc/wiki/` or anywhere else.** `./wiki/` is the canonical, version-controlled wiki source (auto-published to the GitHub wiki on every push to `main`); `.omc/` is git-ignored per-session scratch and must not hold durable knowledge. When you create a new wiki page, write it directly to `./wiki/<page-name>.md` with the Write tool — do NOT use `wiki_add` / `wiki_ingest` (those tools default to `.omc/wiki/` and will hide the page from operators + lose it to gitignore). When you find an existing page under `.omc/wiki/`, move it to `./wiki/` in the same change and update all references; leave `.omc/wiki/` empty going forward. New `./wiki/` pages should follow the existing-page style: no YAML frontmatter, plain markdown, relative links to other wiki pages with `./other-page.md` and to repo files with `../path/to/file`.

### Terminology-source-of-truth rule
**Never invent a new name for a concept that arch.md already names.** When a doc, runbook, CLI output, or commit message needs to refer to a wallet / omni / key / endpoint that exists in arch.md, use the arch.md spelling verbatim. If a component currently emits a different label (e.g. `agentkeys whoami` prints `session_wallet:` while arch.md / the OIDC JWT call the same field `agentkeys_user_wallet` / `JWT.agentkeys.wallet_address`), either (a) align the component to the arch.md name OR (b) document the alias in arch.md's "Canonical names" section as an explicit synonym — never let the divergence silently persist. Drift is auditable only if it's explicit.

When you discover a name divergence while making any change, fix it in the same commit (or open a follow-up issue if the rename ripples beyond the current scope — but call out the divergence in the commit message either way). The cure for terminology drift is "one name, one concept, written down in arch.md's canonical-names section"; the disease is operators having to read three docs to figure out whether `master_wallet` / `session_wallet` / `agentkeys_user_wallet` are the same thing.

## Version Control
Use `jj` (Jujutsu) for all version control. Never use raw `git` commands.

## Branch push policy (this branch: `evm`)
On the `evm` branch, after **every** code/doc update that lands a `jj describe` (or amends the working change), push immediately with `jj git push`. The remote broker host pulls from `origin/evm` via `scripts/setup-broker-host.sh --upgrade`, so an unpushed local commit means the deploy script silently picks up the previous revision. No "I'll push at the end" — push per change.

## Diagnosis-before-edit policy
Before changing any file in response to a reported failure, **reproduce the failure locally** and isolate the layer (shell quoting, client tooling, doc command, broker code, network). If the cause is local (shell, copy-paste, env var), respond with the one-line fix and let the user run it — do NOT edit code or docs. Only edit when the cause is in the repo. Keep the response concise: failing command, root cause, fix command — nothing else.

## Land-the-fix policy
Once a local repro proves a fix is correct, **land it the same turn**: edit every affected file (search repo-wide — never assume one file), commit, push to `origin/evm`. Do not stop at "verified locally" or "fixed in one place" — the next operator running the docs will hit the same bug if the fix isn't on `origin/evm`. Pair this with the diagnosis-before-edit policy: diagnose once, fix everywhere, push immediately.

## Runbook-fix-fold-back policy
When the user is walking through a runbook (`docs/cloud-setup.md`, `docs/stage7-demo-and-verification.md`, `docs/operator-runbook-stage7.md`, etc.) and hits a step that fails, **two things must land in the same turn**:

1. The targeted fix to whatever broke (script default, env var, doc command, code).
2. **A revision to the runbook itself** so the next operator running it top-to-bottom will not hit the same failure. The fix lives wherever the bug was; the runbook revision lives wherever the operator first encounters the broken step.

Examples of revisions to land alongside the underlying fix:
- A failing prerequisite check → upgrade the prereq sanity-check step to catch the same case (not just fix the missing prereq once).
- A wrong env var on the wrong machine → call out the laptop-vs-broker-host scope explicitly in the runbook step that uses it.
- A silent skipped action that downstream commands rely on → add a verify-and-fail-loud sanity check in the runbook between the action and its dependent.
- A confusing diagnostic that took two rounds to resolve → fold the diagnosis steps inline into the runbook (one-shot lookup table, not 3 round-trips with the operator).

The goal: every operator-encountered failure makes the runbook strictly more robust before we move on. Never leave the runbook in a state where the same operator (or the next one) will hit the same trap.

## No-hardcoded-values policy
**Do not bake hardcoded values (paths, hostnames, addresses, account IDs, ports, magic numbers) into scripts, code, or runbooks.** Use one of:

- env var with default + override (preferred for operator-facing config)
- CLI flag with default
- config file (env file, TOML, etc.) sourced at startup
- constant in a single source-of-truth file with a clear name

If a hardcoded value is genuinely temporary — e.g. you're sketching a fix and don't yet know how to parameterize it — **log it in [`hardcoded.md`](hardcoded.md)** with: file path + line number, what's hardcoded, why it's hardcoded today, and the concrete change that would unblock making it dynamic. The doc is the audit trail; if a value is hardcoded but not in `hardcoded.md`, the next operator (or future-you) can't tell it was deliberate vs an oversight.

Hardcoded values that go unrecorded compound: each new operator adds defaults baked into a different layer, the runbook drifts from reality, and the project becomes un-deployable to anyone but the original author. The audit log is the cure — it forces an explicit decision instead of an accumulating series of "I'll fix it later"s.

## Plan-completion policy
When the user references a plan (e.g. `docs/spec/plans/issue-XX-*.md`), **complete every numbered step in the plan's implementation-order table — not a self-selected subset**. If you cannot complete a step (interactive flow needs human, scope explosion, prerequisites missing), say so up front before starting work and get explicit approval to defer. Never silently drop steps and ship a partial plan as "done."

The end-of-PR summary is mandatory and has two sections in this exact order:

1. **What landed** — bulleted list of every plan step you finished, with file paths.
2. **What did NOT land** — every plan step you skipped, with the reason and what unblocks it. If the section is empty, say so explicitly ("All plan steps shipped.").

Do not bury skipped work in a footnote, in a note partway through prose, or in a doc that the user has to dig for. The summary is the authoritative answer to "is this PR plan-complete?" — make it answerable from a glance.

Also: never gloss over a partial implementation in a demo doc or runbook. If the demo walks through a flow that is only half-shipped, the doc must state which half is shipped and which still requires manual setup or a follow-up PR. Operators reading the doc cannot tell which is which from prose alone.

## Remote broker host (single entry point)
All remote-host changes (binary upgrades, systemd edits, nginx/certbot, env tweaks, mock-server redeploys) MUST go through `bash scripts/setup-broker-host.sh` — it's idempotent and auto-detects bootstrap vs upgrade. No ad-hoc `systemctl` edits or hand-built `scp`.

## Heima chain (single entry point)
All chain bring-up + per-actor binding ceremonies (contract deploy, deployer funding, master device registration, agent creation, scope grants, K11 enrollment, audit-row append, worker smoke) MUST go through `bash scripts/setup-heima.sh` — it's idempotent and orchestrates the existing per-action `heima-*.sh` helpers in order. Same posture as `setup-broker-host.sh`: one command, every step pre-checks state + short-circuits when already done. The per-action helpers stay callable directly for surgical re-runs (`bash scripts/heima-scope-set.sh ...`); `setup-heima.sh` is the end-to-end orchestrator.

## Idempotent remote-setup rule (CLOUD / BLOCKCHAIN / CI / VM)
**Every script that mutates remote state — AWS / Heima / CI runners / EC2 VMs / Cloudflare / Tencent / IAM / DNS — MUST be idempotent.** A second run with the same inputs MUST exit 0 without re-applying the mutation. This is non-negotiable because:

1. **Operators re-run scripts.** Cloud setup is slow + flaky; a retry-from-the-start posture catches transient failures gracefully only when re-runs are safe.
2. **CI / CD pipelines re-run scripts.** Every CI redeploy or VM provision invokes the same script; non-idempotent scripts double-create resources, double-fund accounts, double-bill operators.
3. **The harness re-runs scripts.** `harness/v2-stage{1,2,3}-demo.sh` invokes every chain helper on every run. A non-idempotent helper means the harness can't be used as a regression gate.

Concrete shape for idempotent scripts (per the existing `setup-broker-host.sh` / `heima-*.sh` patterns):

| Mutation type | Pre-check before mutating | Short-circuit shape |
|---|---|---|
| Contract deploy | `cast code <addr>` — non-empty means deployed | `skip already-deployed` (log + exit 0) |
| Chain tx (register / scope / audit append) | `cast call <view-fn>` returning canonical state | `skip already-registered` / `skip config-matches` |
| Fund EVM account | `cast balance` ≥ requested amount | `skip already-funded` |
| AWS resource (bucket / role / policy) | `aws s3api head-bucket` / `aws iam get-role` | `skip already-exists` + best-effort `update-*` for drift |
| Systemd unit | Diff existing `/etc/systemd/system/<unit>` vs target | Write only if drift; `systemctl daemon-reload` only when written |
| Env-var file | Diff existing file vs target content | Write only if drift |
| nginx vhost | Diff existing `/etc/nginx/sites-available/<site>` vs target | Write + reload only if drift |
| DNS A record (Route 53) | `aws route53 list-resource-record-sets` for the name | UPSERT change-batch (no-op when value matches) |
| Key generation (keypair file) | `[ -f <path> ]` | `skip already-exists` (NEVER overwrite — would invalidate downstream encrypted blobs) |

Output convention: every script logs one of three outcomes per step — `ok proceeding` (mutation applied), `skip <reason>` (no-op), or `fail <reason>` (hard error, exit non-zero). The harness reads these to compute green/red per step.

If a remote-setup script you're writing CAN'T be made idempotent (e.g., one-shot CAS-burn cap-token mint, append-only audit event), explicitly call it out in the script header AND in the runbook ("step N is intentionally append-only; re-runs add a fresh row + advance entryCount"). Otherwise: idempotent or it doesn't ship.

## AWS local-profile ↔ remote-IAM mapping
Operator workstations use lowercase AWS profile names; the access key/secret inside each profile authenticates as the corresponding remote IAM user (case differences like `agentKeys-admin` on AWS vs `agentkeys-admin` locally are cosmetic — the key is the binding, not the name). Source-of-truth (`awsp` output):

| Local profile (laptop) | Remote IAM principal (AWS) | Use for |
|------------------------|---------------------------|---------|
| `agentkeys-admin`      | `user/agentKeys-admin`    | Account-owner ops: SES verify, S3 bucket admin, IAM put-role-policy, EC2 describe-instances, OIDC provider mgmt |
| `agentkeys-broker`     | `user/agentkey-broker`    | Broker-runtime-equivalent perms (rarely used from laptop; the broker EC2 has its own instance profile) |
| `agentkeys-daemon`     | `user/agentkey-daemon`    | Daemon-side AssumeRoleWithWebIdentity-equivalent (rarely used from laptop) |

Switch with `awsp <profile>`; verify with `aws sts get-caller-identity`.

### Per-profile default region is NOT uniform — always pass `--region "$REGION"` explicitly
**Critical trap (real 2026-05-12 incident):** `agentkeys-admin` defaults to `us-west-2` while `agentkeys-broker` / `agentkeys-daemon` default to `us-east-1` (where the broker EC2 + SES + S3 actually live). A bare `aws ec2 describe-instances --filters "Name=ip-address,Values=$EIP"` under `agentkeys-admin` searches `us-west-2`, the EC2 isn't there, the JMESPath returns empty, and the CLI exits 0 with no stderr — silently corrupting the downstream `--role-name ""` or `--instance-profile-name ""` call.

**Rule for all operator-facing docs, scripts, and copy-paste blocks:** every regional AWS API call (`aws ec2`, `aws ses`, `aws s3api`, `aws sts assume-role-*`, `aws logs`, etc.) MUST pass `--region "$REGION"` explicitly. `$REGION` comes from `scripts/operator-workstation.env` (us-east-1). Never rely on the profile's default region — they're not consistent across the three profiles. Global IAM calls (`aws iam`) are region-less and don't need the flag.

### Caller-ARN matching in scripts must be case-insensitive
Lowercase the caller_arn before matching, since the remote IAM user is `agentKeys-admin` (capital K) but operator scripts canonicalize on `agentkeys-admin`. Use `tr '[:upper:]' '[:lower:]'` (portable to /bin/bash 3.2) — not `${var,,}` (bash 4+).

## Per-actor + per-data-class isolation invariants (issue #90)

The OIDC + cap-token + IAM stack enforces a defense-in-depth chain across **four layers**. Every PR that touches storage, OIDC, the broker cap-mint flow, or the worker handlers MUST verify these invariants explicitly in a demo step. A change that doesn't add a corresponding test for the layer it touches is incomplete.

| Layer | Invariant | Enforced by | Canonical test |
|---|---|---|---|
| **1. Broker cap-mint** | The session JWT's `agentkeys.omni_account` claim MUST match the request's `operator_omni`. Also: `device.operator_omni == session_omni`, `device.actor_omni == req.actor_omni`, `device.roles & ROLE_CAP_MINT`, `isServiceInScope(operator, actor, service) == true`. Returns `OperatorMismatch` / `DeviceBindingMismatch` / `DeviceRoleMissing` / `ServiceNotInScope` otherwise. | [`handlers/cap.rs`](crates/agentkeys-broker-server/src/handlers/cap.rs) — `mint_cap()` | [`harness/v2-stage3-demo.sh`](harness/v2-stage3-demo.sh) step 13 (NEGATIVE cap-mint with cross-actor `operator_omni` → HTTP 4xx) |
| **2. Worker chain-verify** | Independent re-check of layer-1 invariants from the worker's perspective — defense-in-depth against broker compromise. `verify_signature` (broker cap-sig), `check_chain_device`, `check_chain_scope`, `check_chain_k3_epoch`. | [`crates/agentkeys-worker-creds/src/verify.rs`](crates/agentkeys-worker-creds/src/verify.rs) + 26 unit tests | [`harness/v2-stage3-demo.sh`](harness/v2-stage3-demo.sh) steps 11+12 (full HTTP roundtrip exercises every verify hook) |
| **3. AWS IAM PrincipalTag scoping** | STS creds minted via `AssumeRoleWithWebIdentity` carry `PrincipalTag/agentkeys_actor_omni`. S3 resources scoped via `${aws:PrincipalTag/agentkeys_actor_omni}` resource-ARN interpolation. `s3:ListBucket` MUST carry an `s3:prefix=bots/${PrincipalTag}/<class>/*` condition (codex P2 — split-statement v3 bucket policy). | [`scripts/provision-vault-role.sh`](scripts/provision-vault-role.sh) + [`scripts/provision-memory-role.sh`](scripts/provision-memory-role.sh) + [`scripts/apply-vault-bucket-policy.sh`](scripts/apply-vault-bucket-policy.sh) + [`scripts/apply-memory-bucket-policy.sh`](scripts/apply-memory-bucket-policy.sh) | [`harness/v2-stage3-demo.sh`](harness/v2-stage3-demo.sh) steps 4-9: POSITIVE write to own prefix, NEGATIVE write + LIST to cross-actor prefix → AccessDenied |
| **4. Per-data-class bucket separation** | Vault-role's IAM permissions MUST be scoped to the vault bucket only; memory-role to the memory bucket only. Vault creds in the wrong bucket → AccessDenied; memory creds in the vault bucket → AccessDenied. Per arch.md §17.2 ("sharing one role across data classes collapses blast radius"). | Per-data-class IAM roles (`agentkeys-vault-role`, `agentkeys-memory-role`) | [`harness/v2-stage3-demo.sh`](harness/v2-stage3-demo.sh) step 10 (vault creds → memory bucket, memory creds → vault bucket, both AccessDenied) |

**Test-discipline rule**: any PR that adds a NEW worker, a NEW data class (e.g. a payments worker), or a NEW broker auth method MUST extend the stage-3 demo with negative cross-isolation tests for ALL four layers. Don't ship the feature with only POSITIVE-path tests.

### Cap-tokens are data-class-explicit (issue #90 followup)

The broker mints FOUR cap endpoints — two per data class — and the `data_class` is a SIGNED FIELD in the cap payload. Workers reject caps whose `data_class` doesn't match their bucket. This is the cap-layer isolation gate, symmetric with the AWS IAM cross-bucket gate (layer 4) but at the broker-signed capability layer.

```
POST /v1/cap/cred-store    → mints CapPayload { op: Store,    data_class: Credentials, ... }
POST /v1/cap/cred-fetch    → mints CapPayload { op: Fetch,    data_class: Credentials, ... }
POST /v1/cap/memory-put    → mints CapPayload { op: Store,    data_class: Memory,      ... }
POST /v1/cap/memory-get    → mints CapPayload { op: Fetch,    data_class: Memory,      ... }
```

What this prevents:

```bash
# Operator A mints a credentials Store cap:
cred_cap=$(curl -X POST $BROKER/v1/cap/cred-store -d ...)
# → CapPayload { ..., op: store, data_class: credentials }

# Tries to abuse it against the memory worker:
curl -X POST https://memory.litentry.org/v1/memory/put -d '{"cap": '"$cred_cap"', "plaintext_b64": "..."}'
# → HTTP 403 cap_data_class_mismatch
#   The memory worker's verify_cap() calls check_data_class(cap, DataClass::Memory),
#   sees cap.payload.data_class == Credentials, rejects.
```

The reverse (memory cap submitted to cred worker) is symmetrically blocked.

**Why two endpoints per data class, not just one + a `data_class` query param**: by making the route the source of truth, the broker can't ever mint a `Memory` cap from a request that hit `/v1/cap/cred-*` — the variant is statically derived in `handlers/cap.rs`, not from user input. Mistakes-on-the-broker-side are impossible to construct.

**Why this matters beyond the IAM layer**: AWS IAM (layer 3+4) enforces cross-actor + cross-bucket isolation at the AWS-API call site. The `data_class` cap binding enforces it at the cap-authz site — earlier in the trust chain, before the worker even calls AWS. If the AWS IAM grants were ever accidentally too broad, the cap-layer check still rejects. Defense in depth.

Verified live:

- `harness/v2-stage3-demo.sh` step 14 — cred-class cap → memory worker → `cap_data_class_mismatch`
- `harness/v2-stage3-demo.sh` step 15 — memory-class cap → cred worker → `cap_data_class_mismatch`
- Unit tests: `crates/agentkeys-worker-creds/src/verify.rs::check_data_class_rejects_cross_class` + serialization test for `DataClass`

**When a third data class lands** (e.g. payments-audit per arch.md §15.6): mint two more endpoints (`/v1/cap/payaudit-store` + `/v1/cap/payaudit-fetch`), add `DataClass::PaymentsAudit` variant, plumb to the new worker. The pattern is closed-extension: existing data classes don't need to know about the new one.

## Development Workflow (Anthropic Harness Pattern)

On every session start:
1. `jj log --limit 10 && cat harness/progress.json && bash harness/init.sh $(jq -r .current_stage harness/progress.json)`
2. Read the stage contract for your current stage in `docs/spec/plans/development-stages.md`
3. Pick the HIGHEST-PRIORITY incomplete deliverable from `harness/features.json`
4. Implement ONE deliverable
5. Run tests: `cargo test -p <crate>` for the affected crate
6. Describe: `jj describe -m "agentkeys: stage N -- <deliverable name>"`
7. Update `harness/features.json` (set `implemented: true`) and `harness/progress.json`
8. New change: `jj new -m "harness: update progress"`

## Stage Completion Protocol
1. Run `bash harness/stage-N-done.sh` -- must exit 0
2. `jj bookmark create stage-N-done` (bookmark marks the completion point)
3. Update `harness/progress.json`: set stage status to "complete"
4. `jj describe -m "harness: stage N complete"`
5. `jj new` (start fresh change for next stage)

## Heima EVM compatibility level — pin to `london` in foundry.toml

Heima's Frontier EVM (the parachain's `pallet_evm` + `pallet_ethereum` stack) is at **London** EVM level. Pre-Merge. Verified live 2026-05-19 against `https://rpc.heima-parachain.heima.network` block header:

| Field | Present? | Implication |
|---|---|---|
| `baseFeePerGas: 0x5d21dba00` | ✅ | EIP-1559 active → ≥ London |
| `difficulty: 0x0`, `mixHash: null`, `prevRandao: absent` | ❌ | Pre-Paris (Merge introduced these) → < Paris |
| `withdrawalsRoot: null` | ❌ | Pre-Shanghai |
| `blobGasUsed`, `excessBlobGas: null` | ❌ | Pre-Cancun |

**Practical consequence**: any Foundry project that deploys to Heima MUST set `evm_version = "london"` in `foundry.toml`. With `paris` or higher, `forge script ... --broadcast` errors with:

```
EVM error; header validation error: `prevrandao` not set
```

…because forge's simulator validates the chain's block header against its target EVM version before broadcasting, and a Paris-or-higher simulator requires `prevrandao` in the header.

`london` also avoids the Shanghai-era PUSH0 opcode (which Heima would reject during EVM execution).

Verify the live EVM version of Heima any time with:

```bash
curl -sS -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",false],"id":1}' \
  https://rpc.heima-parachain.heima.network | jq '{baseFeePerGas: .result.baseFeePerGas, mixHash: .result.mixHash, withdrawalsRoot: .result.withdrawalsRoot, blobGasUsed: .result.blobGasUsed}'
```

If any of `mixHash`/`withdrawalsRoot`/`blobGasUsed` becomes non-null in the future (Heima upgrade), bump `evm_version` accordingly in `crates/agentkeys-chain/foundry.toml` AND re-read the verification check above.

## Deployed contract registry

Live v2 stage-1 contract addresses on each chain are kept in [`docs/spec/deployed-contracts.md`](docs/spec/deployed-contracts.md). The same addresses are also written to `scripts/operator-workstation.env` (via `env_set` in `scripts/heima-bring-up.sh` step 6) for shell-script consumption — those env-file entries are the operational source of truth and `deployed-contracts.md` is the human-readable canonical record (deployer, deploy date, block, explorer links, ABI summary).

Verify all contracts are live + functional any time:

```bash
AGENTKEYS_CHAIN=heima       bash scripts/verify-heima-contracts.sh
AGENTKEYS_CHAIN=heima-paseo bash scripts/verify-heima-contracts.sh   # when Paseo collators come back up
```

The verify script is read-only RPC (zero gas), exits 0 on all-pass / 1 on any failure. Run after every chain bring-up (`v2-stage1-demo.sh` step 9) to confirm the deploy was clean.

## Code Conventions
- Rust: `thiserror` for library errors, `anyhow` for binary errors
- All async: `tokio` runtime, `#[tokio::test]` for async tests
- Crate names: agentkeys-types, agentkeys-core, agentkeys-cli, agentkeys-daemon, agentkeys-mock-server, agentkeys-mcp, agentkeys-provisioner
- Git commits: `agentkeys: stage N -- <deliverable>`
- Never self-grade: run `bash harness/stage-N-done.sh` to verify

## Mock Server Design Principles
The mock server mirrors Heima blockchain extrinsics. Follow these rules:
- **Typed parameters**: Every endpoint must accept explicit typed inputs (e.g., `identity_type` + `identity_value`), never parse opaque JSON blobs to guess types at runtime. Blockchain extrinsics require typed parameters -- the mock must enforce the same contract.
- **Shared identity resolution**: Use a single `resolve_identity(db, identity_type, identity_value) -> Result<String>` utility in `handlers/identity.rs` for all identity-to-wallet lookups. Never inline if/else chains per identity variant.
- **Modular handlers**: Split request-type-specific logic into separate functions (e.g., `mint_pair_session()`, `mint_recover_session()`). The `approve_auth_request` handler dispatches to these, not inline everything.

## Test Commands
```
cargo test -p agentkeys-types
cargo test -p agentkeys-core
cargo test -p agentkeys-mock-server
cargo test -p agentkeys-cli
cargo test -p agentkeys-daemon -p agentkeys-mcp
cargo test -p agentkeys-provisioner
npm test --prefix provisioner-scripts
```

