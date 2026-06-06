# AgentKeys

## Architecture
Rust monorepo with Cargo workspace. See `docs/arch.md` for component inventory.
See `docs/spec/credential-backend-interface.md` for the CredentialBackend trait contract (15 methods).
See `docs/plan/milestones-roadmap.md` for the M1–M7 milestone roadmap (replaces the archived v1/v2 staged plan).
See `docs/plan/execution-plan.md` for the orchestration runbook (ralph, team, ultraqa).
Do not read folder `docs/archived`

## Docs layout (lean)
`docs/arch.md` is the single source of truth — brief, indexes every detail via outward links. Five sub-folders, each one audience:
- `docs/spec/` — developers + coordinating colleagues (cloud, CI, blockchain, signer-protocol, threats).
- `docs/plan/` — agent-authored plans BEFORE code lands; promote to `spec/` when shipped, else archive.
- `docs/research/` — third-party context (Heima, EIP-191/712, aiosandbox, agent memory).
- `docs/wiki/` — end users + hardware integrators; mirrored to GitHub Wiki by [`publish-wiki.yml`](.github/workflows/publish-wiki.yml).
- `docs/archived/` — superseded files; never linked from arch.md, never read in normal dev. Move stale files here, don't delete. Run the `agentkeys-docs` skill to audit + compact.

**User-facing instructions** — every behavior/caveat a user would notice (e.g. `agentkeys wire` taking over the runtime's `hooks:` block) goes in [`docs/user-manual.md`](docs/user-manual.md), the single home for user-aware instructions.

## Architecture-as-source-of-truth policy
[`docs/arch.md`](docs/arch.md) is the **single source of truth** for component inventory, key inventory (K1–K11), trust boundaries, identity model (HDKD actor tree), and per-actor binding ceremonies. **After editing any architectural doc** (broker plans, signer-protocol, demo doc, runbooks, plan files in `docs/plan/`, heima-gaps), re-open `arch.md` and verify it still matches; if it diverges, update arch.md in the same change. If the per-doc detail outgrows arch.md, link from arch.md outward — never duplicate. The wiki page at [`docs/wiki/agent-role-and-usage-hdkd-per-agent-omni.md`](docs/wiki/agent-role-and-usage-hdkd-per-agent-omni.md) is a focused operator reference for the agent role; it defers to arch.md.

## `/create-pr` policy
When the `/create-pr` skill is invoked from a Claude Code worktree at `.claude/worktrees/<name>`, the worktree is a *git worktree* under the main repo — `jj` cannot colocate there (`jj git init --colocate` fails with "Cannot create a colocated jj repo inside a Git worktree"). Use this hybrid workflow so the jj-only rule is preserved everywhere it can be:

1. **Commit (worktree, git — unavoidable).** From the worktree, `git add <explicit files> && git commit -m "<message>"`. Git is necessary at this step because jj cannot read a git-worktree's filesystem; the commit lands in the shared git object store and advances the branch ref. **Do NOT include `Co-Authored-By:` lines** — the commit author is the agent identity that ran the commit (`wildmeta-agent`); appended co-author tags are wrong attribution.
2. **Push (main repo, jj).** `cd` to the main repo (`~/Projects/agentKeys`), then `jj git fetch && jj git push -b <branch-name>` to push to `origin`. This is the jj-required step — jj fully controls remote interaction once the commit exists locally.
3. **PR (anywhere, gh).** `gh pr create --title "..." --body "$(cat <<'EOF' ... EOF)"`. The gh CLI is not git/jj-specific.

Outside Claude Code worktrees (i.e. directly in the main repo), the whole flow is jj per the standard "use `jj`, never raw `git`" rule from this file.

## Wiki-location policy
**All project wiki pages live under [`./docs/wiki/`](docs/wiki/) — never under `.omc/wiki/`, the root-level `./wiki/`, or anywhere else.** `./docs/wiki/` is the canonical, version-controlled wiki source (auto-published to the GitHub wiki on every push to `main` by [`.github/workflows/publish-wiki.yml`](.github/workflows/publish-wiki.yml)); `.omc/` is git-ignored per-session scratch and must not hold durable knowledge. When you create a new wiki page, write it directly to `./docs/wiki/<page-name>.md` with the Write tool — do NOT use `wiki_add` / `wiki_ingest` (those tools default to `.omc/wiki/` and will hide the page from operators + lose it to gitignore). When you find an existing page under `.omc/wiki/` or root-level `./wiki/`, move it to `./docs/wiki/` in the same change and update all references; leave the old locations empty going forward. New `./docs/wiki/` pages should follow the existing-page style: **no YAML frontmatter and no redundant leading `# H1`**, plain markdown, relative links to other wiki pages with `./other-page.md` and to repo files with `../../path/to/file`.

**Why no frontmatter and no leading H1 (the GitHub-Wiki rendering rules):** [`publish-wiki.yml`](.github/workflows/publish-wiki.yml) is a *raw* mirror — GitHub Wiki renders each page's title from its **filename** and copies the body verbatim, with no transform. So (a) a `---…---` frontmatter block is NOT stripped — it renders as a literal heading + sidebar-preview text; and (b) a body `# H1` duplicates the filename-derived page title AND pushes every section one level deeper in the right-sidebar table of contents. Open each page body on real content instead — a lead paragraph, a `**Status:**`/`**Scope:**` block, a `>` note, or an `## H2`. **CI enforces both rules** via [`scripts/lint-wiki.sh`](scripts/lint-wiki.sh) (workflow [`.github/workflows/wiki-lint.yml`](.github/workflows/wiki-lint.yml), runs on every PR touching `docs/wiki/**`); run `bash scripts/lint-wiki.sh` locally before pushing. (Documentation alone was insufficient — the "no frontmatter" rule predated the lint and 22 pages still shipped with frontmatter + redundant H1s because the OMC `wiki_*` tooling injects them; the lint is the actual gate.)

### Terminology-source-of-truth rule
**Never invent a new name for a concept that arch.md already names.** When a doc, runbook, CLI output, or commit message needs to refer to a wallet / omni / key / endpoint that exists in arch.md, use the arch.md spelling verbatim. If a component currently emits a different label (e.g. `agentkeys whoami` prints `session_wallet:` while arch.md / the OIDC JWT call the same field `agentkeys_user_wallet` / `JWT.agentkeys.wallet_address`), either (a) align the component to the arch.md name OR (b) document the alias in arch.md's "Canonical names" section as an explicit synonym — never let the divergence silently persist. Drift is auditable only if it's explicit.

When you discover a name divergence while making any change, fix it in the same commit (or open a follow-up issue if the rename ripples beyond the current scope — but call out the divergence in the commit message either way). The cure for terminology drift is "one name, one concept, written down in arch.md's canonical-names section"; the disease is operators having to read three docs to figure out whether `master_wallet` / `session_wallet` / `agentkeys_user_wallet` are the same thing.

## Version Control
Use `jj` (Jujutsu) for all version control. Never use raw `git` commands.

## Branch / deploy policy (`origin/main` is the default + deploy branch)
**`origin/evm` is DEPRECATED.** All new work lands on the default branch **`origin/main`** (feature branch → PR → `main`). The remote broker host now deploys from `origin/main`: `bash scripts/setup-broker-host.sh --ref main` (fetch + checkout + pull `main`, rebuild, redeploy). `--upgrade` is a back-compat no-op — the script is idempotent and `--ref` drives any pull. Push per change so the branch the host deploys from is never behind your local commits; an unpushed commit means the deploy silently picks up the previous revision. (Historical note: the broker used to deploy from `origin/evm`; that branch is frozen — do not push to it.)

## Diagnosis-before-edit policy
Before changing any file in response to a reported failure, **reproduce the failure locally** and isolate the layer (shell quoting, client tooling, doc command, broker code, network). If the cause is local (shell, copy-paste, env var), respond with the one-line fix and let the user run it — do NOT edit code or docs. Only edit when the cause is in the repo. Keep the response concise: failing command, root cause, fix command — nothing else.

## Land-the-fix policy
Once a local repro proves a fix is correct, **land it the same turn**: edit every affected file (search repo-wide — never assume one file), commit, push to your working branch (PR'd to `origin/main`). Do not stop at "verified locally" or "fixed in one place" — the next operator running the docs will hit the same bug if the fix isn't on `origin/main`. Pair this with the diagnosis-before-edit policy: diagnose once, fix everywhere, push immediately.

## Runbook-fix-fold-back policy
When the user is walking through a runbook (`docs/cloud-setup.md`, `docs/v2-stage1-migration-and-demo.md`, `scripts/setup-broker-host.sh`, etc.) and hits a step that fails, **two things must land in the same turn**:

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
When the user references a plan (e.g. `docs/plan/issue-XX-*.md`), **complete every numbered step in the plan's implementation-order table — not a self-selected subset**. If you cannot complete a step (interactive flow needs human, scope explosion, prerequisites missing), say so up front before starting work and get explicit approval to defer. Never silently drop steps and ship a partial plan as "done."

The end-of-PR summary is mandatory and has two sections in this exact order:

1. **What landed** — bulleted list of every plan step you finished, with file paths.
2. **What did NOT land** — every plan step you skipped, with the reason and what unblocks it. If the section is empty, say so explicitly ("All plan steps shipped.").

Do not bury skipped work in a footnote, in a note partway through prose, or in a doc that the user has to dig for. The summary is the authoritative answer to "is this PR plan-complete?" — make it answerable from a glance.

Also: never gloss over a partial implementation in a demo doc or runbook. If the demo walks through a flow that is only half-shipped, the doc must state which half is shipped and which still requires manual setup or a follow-up PR. Operators reading the doc cannot tell which is which from prose alone.

## Three idempotent deployment entry points — the ONLY scripts an operator/CI runs directly

Deployment has exactly **three** idempotent orchestrators. An operator (or CI) runs ONLY these three; every other setup/provision/DNS/cert/chain mutation is **wired into** one of them as a delegated step — never run standalone in a runbook.

| Entry point | Runs on | Owns |
|---|---|---|
| [`scripts/setup-cloud.sh`](scripts/setup-cloud.sh) | operator laptop (`agentkeys-admin`) | AWS account: IAM users/roles/policies, SES, S3 buckets (vault/memory/config), OIDC provider, **all DNS** (broker/signer/mcp inline + the 5 workers delegated to `dns-upsert-workers.sh`), EIP allocate-by-tag |
| [`scripts/setup-broker-host.sh`](scripts/setup-broker-host.sh) | broker EC2 host | build+install binaries, systemd units, nginx vhosts, certbot prep, env files, hosted-MCP re-converge (`setup-mcp-host.sh`) |
| [`scripts/setup-heima.sh`](scripts/setup-heima.sh) | operator laptop | chain bring-up + per-actor binding ceremonies (orchestrates the `heima-*.sh` helpers) |

**Flag convention (all three):** run **PLAIN for local/prod**; add **`--ci`** (alias `--test`) for the CI/test environment. `--ci` selects the CI broker EIP (tag `agentkeys-broker-eip-test`), `-test`-suffixed IAM identifiers + buckets, and the `*.test.env` files. Never hand operators a pile of env flags — **plain = prod, `--ci` = CI**. (Per-step targeting — `--only-step N`, `--ref main`, `--reclaim-toolchain` — is fine; *environment* selection is `--ci` or nothing.)

**Wire-in rule (HARD):** a NEW script that mutates cloud / broker / chain state MUST be called from the matching entry point in its normal flow (e.g. `provision-config-*.sh` + `apply-config-bucket-policy.sh` ← `setup-cloud.sh` step 13; `dns-upsert-workers.sh` ← `setup-cloud.sh` step 6; `setup-mcp-host.sh` ← `setup-broker-host.sh`). A per-action helper MAY stay directly callable for surgical re-runs, but the orchestrator MUST invoke it so a clean `setup-*.sh` run is complete. **A new mutating script that isn't wired into one of the three does not ship.**

**Exempt (NOT deploy entry points):** `setup-dev-env.sh` (developer-workstation bootstrap — rustup/node/jj, not a deploy), `*-demo.sh` demos, read-only `verify-*.sh` checks, `install-agentkeys-cli.sh`, `lint-wiki.sh`, and surgical `heima-*-revoke`/`-rotate` helpers — tools, run on their own. (The `mcp-demo-mode-*.sh` demos were removed in #207 — the MCP protocol-conformance proof is now the Rust `crates/agentkeys-mcp-server/tests/transport_conformance.rs`, run by `cargo test`.)

## Remote broker host (single entry point)
All remote-host changes (binary upgrades, systemd edits, nginx/certbot, env tweaks, mock-server redeploys) MUST go through `bash scripts/setup-broker-host.sh` — it's idempotent and auto-detects bootstrap vs upgrade. No ad-hoc `systemctl` edits or hand-built `scp`.

**NEVER pass `--upgrade` (or `--skip-pull`) to any idempotent setup script** (`setup-broker-host.sh`, `setup-cloud.sh`, the `heima-*` / `setup-heima.sh` helpers, etc.). They are back-compat **no-ops** — these scripts are idempotent and auto-detect bootstrap vs upgrade; there is no "upgrade mode" to opt into. Invoke them **plain** for prod/local (optionally with `--ci` for CI / `--yes` / `--only-step N` / `--reclaim-toolchain`), or pass **`--ref main`** to `setup-broker-host.sh` when you also want it to fetch + checkout + redeploy `main`. Do not add an `--upgrade` flag to any new script, runbook, doc, or CLI guidance; if you find an existing `--upgrade` reference in an active (non-archived) operator path, replace it with the idempotent invocation (`--ref main` for deploy, plain for ensure) in the same change.

### SSH access to the remote broker host
On the operator machine, **SSH into the prod broker with the zsh alias `ssh-agentkeys`** (= `bash $AGENTKEYS_REPO/scripts/ssh-broker.sh prod`, which uses EC2 Instance Connect under AWS profile `agentkeys-broker`). Use it for read-only diagnostics (worker logs, env, status) — it is the sanctioned remote-shell entry point; do not hand-roll `aws ec2-instance-connect ssh` or raw `ssh`. Pass a trailing command to run non-interactively: `ssh-agentkeys 'systemctl status agentkeys-worker-memory'`. The login user is `agentkey` (uid 1001); it is in the `sudo` group but sudo **requires a password and a TTY**, so `journalctl`/reading `/etc/agentkeys/*.env` (owned `agentkeys:agentkeys 0600`) need an interactive session — non-interactive `ssh-agentkeys '<cmd>'` can only run unprivileged commands. For privileged log reads, open an interactive `ssh-agentkeys` shell and run `sudo` there. (`ssh-broker.sh test` / `--fallback` reach the test stack / use the `.pem` when EC2-IC is down.)

## Heima chain (single entry point)
All chain bring-up + per-actor binding ceremonies (contract deploy, deployer funding, master device registration, agent creation, scope grants, K11 enrollment, audit-row append, worker smoke) MUST go through `bash scripts/setup-heima.sh` — it's idempotent and orchestrates the existing per-action `heima-*.sh` helpers in order. Same posture as `setup-broker-host.sh`: one command, every step pre-checks state + short-circuits when already done. The per-action helpers stay callable directly for surgical re-runs (`bash scripts/heima-scope-set.sh ...`); `setup-heima.sh` is the end-to-end orchestrator.

**Harness / demo testing runs on Heima mainnet (`AGENTKEYS_CHAIN=heima`), not a testnet** — the operator deploy wallet has enough HEI to fund test agents, so use real mainnet (no gas-free shortcuts); the per-actor binding txs are funded from the deploy wallet automatically.

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

### Prod vs CI/test broker = SEPARATE machines + SEPARATE EIPs — ALWAYS verify the IP before a cloud deploy/bootstrap/DNS step
**Critical trap (real #201 incident, 2026-06-06):** two broker EC2 instances exist, each with its own Elastic IP, distinguished by the **EIP's `Name` tag** (NOT the instance name):

| Env | EIP `Name` tag (stable selector) | EIP today (re-verify, don't hardcode) |
|---|---|---|
| **prod** | `agentkeys-broker-eip` | 54.164.117.252 |
| **CI/test** | `agentkeys-broker-eip-test` | 3.214.219.209 |

**Never pick "the broker EIP" with a `describe-addresses` first-match** (`Addresses[0].PublicIp`, or `Addresses[?AssociationId!=\`null\`] | first`). With both EIPs allocated it returns whichever the API lists first — which once pointed all 5 worker A records (`audit/email/cred/memory/config`) at the **test** broker while `broker`/`signer` stayed on **prod**, causing multi-round Let's Encrypt 404s (the CA validated against the wrong machine).

**Rule — any cloud deploy/bootstrap/DNS step that needs the broker IP must resolve it env-aware FIRST:**
- **By tag, keyed on prod-vs-test** (canonical — `setup-cloud.sh` step 4 + `dns-upsert-workers.sh`): `aws ec2 describe-addresses --region "$REGION" --filters Name=tag:Name,Values=agentkeys-broker-eip[-test] --query 'Addresses[0].PublicIp'`. Both scripts pick the `-test` suffix from `TEST_MODE` (`--test`, or a `*test*` ENV_FILE).
- **On the broker host:** `curl -s ifconfig.me` is ground truth for which box you're actually on.
- **For DNS:** every worker A record MUST equal `broker.${ZONE}`'s — cross-check via DoH, never laptop DNS (a VPN rewrites `${ZONE}`): `for h in broker audit email cred memory config; do echo "$h $(curl -s "https://dns.google/resolve?name=$h.${ZONE}&type=A" | jq -r '.Answer[0].data')"; done`.

Any new script that needs the broker IP MUST accept `--eip`, derive by the env-aware tag, OR read `broker.${ZONE}`'s A record — and SHOULD warn if the chosen IP ≠ the broker's current A record (co-location guard). Never "first associated EIP".

## Per-actor + per-data-class isolation invariants (issue #90)

The OIDC + cap-token + IAM stack enforces a defense-in-depth chain across **four layers**. Every PR that touches storage, OIDC, the broker cap-mint flow, or the worker handlers MUST verify these invariants explicitly in a demo step. A change that doesn't add a corresponding test for the layer it touches is incomplete.

| Layer | Invariant | Enforced by | Canonical test |
|---|---|---|---|
| **1. Broker cap-mint** | The session JWT's `agentkeys.omni_account` claim MUST match the request's `operator_omni`. Also: `device.operator_omni == session_omni`, `device.actor_omni == req.actor_omni`, `device.roles & ROLE_CAP_MINT`, `isServiceInScope(operator, actor, service) == true`. Returns `OperatorMismatch` / `DeviceBindingMismatch` / `DeviceRoleMissing` / `ServiceNotInScope` otherwise. | [`handlers/cap.rs`](crates/agentkeys-broker-server/src/handlers/cap.rs) — `mint_cap()` | [`harness/v2-stage3-demo.sh`](harness/v2-stage3-demo.sh) step 13 (NEGATIVE cap-mint with cross-actor `operator_omni` → HTTP 4xx) |
| **2. Worker chain-verify** | Independent re-check of layer-1 invariants from the worker's perspective — defense-in-depth against broker compromise. `verify_signature` (broker cap-sig), `check_chain_device`, `check_chain_scope`, `check_chain_k3_epoch`. | [`crates/agentkeys-worker-creds/src/verify.rs`](crates/agentkeys-worker-creds/src/verify.rs) + 26 unit tests | [`harness/v2-stage3-demo.sh`](harness/v2-stage3-demo.sh) steps 11+12 (full HTTP roundtrip exercises every verify hook) |
| **3. AWS IAM PrincipalTag scoping** | STS creds minted via `AssumeRoleWithWebIdentity` carry `PrincipalTag/agentkeys_actor_omni`. S3 resources scoped via `${aws:PrincipalTag/agentkeys_actor_omni}` resource-ARN interpolation. `s3:ListBucket` MUST carry an `s3:prefix=bots/${PrincipalTag}/<class>/*` condition (codex P2 — split-statement v3 bucket policy). | [`scripts/provision-vault-role.sh`](scripts/provision-vault-role.sh) + [`scripts/provision-memory-role.sh`](scripts/provision-memory-role.sh) + [`scripts/provision-config-role.sh`](scripts/provision-config-role.sh) + [`scripts/apply-vault-bucket-policy.sh`](scripts/apply-vault-bucket-policy.sh) + [`scripts/apply-memory-bucket-policy.sh`](scripts/apply-memory-bucket-policy.sh) + [`scripts/apply-config-bucket-policy.sh`](scripts/apply-config-bucket-policy.sh) | [`harness/v2-stage3-demo.sh`](harness/v2-stage3-demo.sh) steps 4-9 (cred + memory): POSITIVE write to own prefix, NEGATIVE write + LIST to cross-actor prefix → AccessDenied; step 19 (config, master-self) |
| **4. Per-data-class bucket separation** | Vault-role's IAM permissions MUST be scoped to the vault bucket only; memory-role to the memory bucket only; config-role to the config bucket only (#201). Creds for one data class in another's bucket → AccessDenied. Per arch.md §17.2 ("sharing one role across data classes collapses blast radius"). | Per-data-class IAM roles (`agentkeys-vault-role`, `agentkeys-memory-role`, `agentkeys-config-role`) | [`harness/v2-stage3-demo.sh`](harness/v2-stage3-demo.sh) step 10 (vault ↔ memory, both AccessDenied) + step 19 (config creds → memory/vault bucket, memory creds → config bucket, all AccessDenied) |

**Test-discipline rule**: any PR that adds a NEW worker, a NEW data class (e.g. a payments worker), or a NEW broker auth method MUST extend the stage-3 demo with negative cross-isolation tests for ALL four layers. Don't ship the feature with only POSITIVE-path tests.

### Cap-tokens are data-class-explicit (issue #90 followup)

The broker mints SIX **storage** cap endpoints — two per data class (credentials, memory, config) — plus ONE **compute-gate** cap (`/v1/cap/classify`, #207), and the `data_class` is a SIGNED FIELD in the cap payload. Workers reject caps whose `data_class` doesn't match their bucket. This is the cap-layer isolation gate, symmetric with the AWS IAM cross-bucket gate (layer 4) but at the broker-signed capability layer.

```
POST /v1/cap/cred-store    → mints CapPayload { op: Store,    data_class: Credentials, ... }
POST /v1/cap/cred-fetch    → mints CapPayload { op: Fetch,    data_class: Credentials, ... }
POST /v1/cap/memory-put    → mints CapPayload { op: Store,    data_class: Memory,      ... }
POST /v1/cap/memory-get    → mints CapPayload { op: Fetch,    data_class: Memory,      ... }
POST /v1/cap/config-store  → mints CapPayload { op: Store,    data_class: Config,      ... }   # #201, master-only
POST /v1/cap/config-fetch  → mints CapPayload { op: Fetch,    data_class: Config,      ... }   # #201, master-only
POST /v1/cap/classify      → mints CapPayload { op: Classify, data_class: <from body>, ... }   # #207, compute gate (no S3)
```

The 7th (`/v1/cap/classify`, #207 items 2-3) is the **compute-gate** cap for the `agentkeys-worker-classify` worker (COMPILE + TAG, no S3 bucket). It is the ONLY endpoint where `data_class` comes from the request body, not the route — a classify cap spans data classes, so the worker binds on the signed `data_class` (a Memory-classify cap can't TAG a credential) AND on `op: Classify` (the storage workers reject `op: Classify`; the classify worker rejects any non-Classify op).

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
- `harness/v2-stage3-demo.sh` step 20 — config-class cap → memory + cred workers → `cap_data_class_mismatch` (#201, master-self)
- `harness/v2-stage3-demo.sh` step 21 — memory + cred-class cap → config worker → `cap_data_class_mismatch` (#201, master-self)
- Unit tests: `crates/agentkeys-worker-creds/src/verify.rs::check_data_class_rejects_cross_class` + `check_data_class_rejects_config_at_cred_and_memory` + serialization test for `DataClass` (incl. `Config` → `"config"`); `crates/agentkeys-worker-config/src/handlers.rs` (config-prefix S3-key tests)

**The third data class — `config` (#201) — has landed** (the policy / memory-types taxonomy, #178 §7; MASTER-ONLY). It followed the closed-extension pattern exactly: two endpoints (`/v1/cap/config-store` + `/v1/cap/config-fetch`), `DataClass::Config` (serializes `"config"`), the `agentkeys-worker-config` crate (mirror of `agentkeys-worker-memory`, `config/` S3 prefix, own `$CONFIG_BUCKET` + `agentkeys-config-role`), provisioned by `provision-config-{bucket,role}.sh` + `apply-config-bucket-policy.sh`, deployed by `setup-broker-host.sh` (port 9096). Because it is master-only (`operator == actor`), its cap-mint + worker scope checks ride the #195 master-self skip — no on-chain scope grant. **When a FOURTH data class lands** (e.g. payments-audit per arch.md §15.6): mint two more endpoints (`/v1/cap/payaudit-store` + `/v1/cap/payaudit-fetch`), add the `DataClass` variant, plumb to the new worker, mirror the provision/apply scripts + `setup-broker-host.sh` wiring, and extend the stage-3 demo with the four-layer + cap-mismatch negatives. Existing data classes don't need to know about the new one.

**Env-file + provisioner discipline for ANY new data class / worker / EIP-keyed resource (HARD — learned the hard way, #201):**
1. **Add the new keys to BOTH `scripts/operator-workstation.env` AND `scripts/operator-workstation.test.env`** — every role ARN, bucket, and `WORKER_*_HOST` (+ `*_URL`), with the `-test` variant in the test file. The test file is NOT auto-derived from prod; a key added only to prod makes `setup-cloud.sh --ci` / `setup-broker-host.sh --ci` die on the missing-var check (the config data class shipped to prod but was absent from `.test.env`, so the whole `--ci` path was broken until caught).
2. **When `setup-cloud.sh` delegates to a provision/apply helper, pass `ENV_FILE="$ENV_FILE"`** (step 13 does this in a loop; step 6 for `dns-upsert-workers.sh`). The helpers default `ENV_FILE` to `operator-workstation.env` (prod) and `set -a; . "$ENV_FILE"` OVERWRITES any inherited `$BUCKET`/`$ROLE` — so without the passthrough a `--ci` run silently provisions the **prod** bucket. Verify both: `setup-cloud.sh --ci --dry-run` must name the `-test` resources, never the prod ones.
3. **Add the new keys to the CI env-MATERIALIZER too — [`.github/workflows/harness-ci.yml`](.github/workflows/harness-ci.yml)'s "Materialize the production env file with TEST values" step.** CI does NOT source `operator-workstation.test.env`; it writes its own `scripts/operator-workstation.env` from GH secrets + derived values. A key missing there is unbound when a harness script that runs under `set -u` references it → the whole stage crashes with `<KEY>: unbound variable` (real #201 incident: stage-3 step 19 died on `CONFIG_ROLE_ARN: unbound variable` because the config keys were added to both env files in Phase 1 but never to the materializer). Derive `-test` values inline (`CONFIG_BUCKET=agentkeys-config-test-$ACCOUNT_ID`, `CONFIG_ROLE_ARN=arn:aws:iam::$ACCOUNT_ID:role/agentkeys-config-role-test`, `AGENTKEYS_WORKER_CONFIG_URL=https://config-test.$TEST_BROKER_ZONE`) — no new secret needed. **Belt-and-braces:** any harness script must also DEFAULT new optional keys (`: "${NEW_KEY:=}"`) right after sourcing the env file, so a stale env file degrades via `prereq_missing` instead of an unbound-variable abort. If the new resource is an operator one-shot not yet provisioned in the test env, allow its skip reason in the CI invocation (`--allow-skip=scope-not-set,config-role-missing`).

## Broker/worker request shapes have ONE owner (issue #203)

**The broker/worker client protocol — cap-mint (the six `/v1/cap/*` endpoints: cred/memory/config × store/fetch, #201), the STS relay, worker `/v1/memory/{put,get}` + `/v1/config/{put,get}` body types, audit append, the `memory:<ns>` service builder, and the `0x`-omni normalizer — is owned by ONE crate, [`agentkeys-backend-client`](crates/agentkeys-backend-client/) (request/response field types co-owned with [`agentkeys-types`](crates/agentkeys-types/)). Never re-type a cap/worker body in a second Rust path or in bash.**

This is the structural fix for the drift bug class #200 closed (`evm_address` vs `{address,chain_id}`, bare-vs-`0x` omni, per-namespace field shapes): the same JSON used to be hand-coded in the MCP `HttpBackend`, the daemon `ui_bridge`, and bash `jq -n` bodies. Now:

- **Rust callers share the crate.** The MCP server's [`HttpBackend`](crates/agentkeys-mcp-server/src/backend/http_backend.rs) is a thin delegate over `BackendClient`; the daemon's [`ui_bridge`](crates/agentkeys-daemon/src/ui_bridge.rs) mints every master-self cap (memory AND #201 config) via `BackendClient::cap_mint` (`mint_master_cap`) and builds its worker put/get bodies from the crate's `MemoryPutBody`/`MemoryGetBody`/`ConfigPutBody`/`ConfigGetBody` types. A drifted shape is a **compile error**. (The raw worker POST stays in the daemon to reuse the once-minted STS creds across namespaces; only the body shape is crate-owned.)
- **Bash is gated.** Any hand-rolled cap/worker body in `harness/**` that is meant to mirror the wire shape carries a `# @backend-fixture: <shape>` comment above it. [`scripts/check-backend-fixture-drift.sh`](scripts/check-backend-fixture-drift.sh) diffs each annotated body's key-set against the crate-emitted fixtures in [`harness/fixtures/backend-protocol/`](harness/fixtures/backend-protocol/) (regenerated by `cargo run -p agentkeys-backend-client --bin dump-protocol-fixtures`). A drifted bash body is a **CI failure** (the [`harness-ci.yml`](.github/workflows/harness-ci.yml) `rust-checks` job runs both the fixture `--check` and the bash gate on every PR touching `crates/**`, `harness/**`, or `scripts/**`).
- **The daemon's web-API plant contract is gated too** (the adjacent frontend↔daemon↔harness surface — the #206 parity ladder, rung 2). The route `/v1/master/memory/plant` + the `ApiMemoryEntry` body have ONE source of truth (the daemon's `MASTER_MEMORY_PLANT_ROUTE` const + struct in [`ui_bridge.rs`](crates/agentkeys-daemon/src/ui_bridge.rs)), pinned to [`harness/fixtures/web-api/master_memory_plant.json`](harness/fixtures/web-api/master_memory_plant.json) by a `ui_bridge` unit test, and BOTH non-Rust consumers — the React frontend [`daemon.ts`](apps/parent-control/lib/client/daemon.ts) and [`web-parity-demo.sh`](harness/web-parity-demo.sh) — carry a `@web-fixture: master_memory_plant` annotation and are diffed against it by [`scripts/check-web-api-drift.sh`](scripts/check-web-api-drift.sh) in CI. This closed phase 6's frontend false-green (a `daemon.ts` route/shape change is now CI-red, not a stale green).

**Rules when you touch this surface:**
- Adding/changing a wire field → change the serde type in `agentkeys-backend-client::protocol` (the single definition), then `cargo run -p agentkeys-backend-client --bin dump-protocol-fixtures` to regenerate the committed fixtures, and update the frozen key-set test in `fixtures.rs`. The four Rust callers recompile against the new shape automatically.
- Real-path harness steps should drive the `agentkeys` CLI (which routes through the shared client), NOT hand-roll curls. Keep raw curls only for negative / HTTP-status-assertion tests — and annotate any such body that mirrors a canonical shape with `# @backend-fixture: <shape>` so the gate keeps it honest. Deliberately-malformed negative-test payloads are NOT annotated (they're supposed to be wrong).
- Per the terminology-source-of-truth rule, the field names are the arch.md canonical spellings — don't invent a synonym in a new body.

## Harness rules → [`harness/CLAUDE.md`](harness/CLAUDE.md)

Harness-specific rules now live in [`harness/CLAUDE.md`](harness/CLAUDE.md) (loaded
when you work on `harness/`, so they don't bloat the global context) — extracted from
here: the **agent-side wire demo REAL-memory-only** rule, the **Development Workflow
(Anthropic harness pattern)**, and the **Stage Completion Protocol**, alongside the
harness authoring contract + the orchestrator inventory. How to RUN the demos is the
operator runbook [`docs/operator-runbook-harness.md`](docs/operator-runbook-harness.md).
**Every harness-script change must update that runbook + `harness/CLAUDE.md` in the
same change** (the keep-the-docs-in-sync rule).

## Heima EVM compatibility level — keep `evm_version = "london"` in foundry.toml (but NOT because Heima is "London")

**Two separate things — do not conflate them (the earlier revision of this section did):**

1. **EVM *execution* level (which opcodes the chain runs) = Cancun.** Heima's Frontier `stable2412` `pallet_evm` returns `&CANCUN_CONFIG` from `frame/evm/src/lib.rs::config()` (the `// London` doc-comment one line up is stale upstream). **Verified on-chain** (local `heima-node --dev`, 2026-06-01) by deploying + *executing* contracts that use post-London opcodes:
   - `PUSH0` (Shanghai, `0x5f`): a Shanghai-compiled `set(42)` ran; `x()` returned `42`.
   - `TSTORE`/`TLOAD` (EIP-1153, **Cancun-only**): `rt(99)` returned `99`.
   So **Heima does NOT reject PUSH0 or other ≤Cancun opcodes.** The previous claim ("london avoids PUSH0 which Heima would reject") was wrong.

2. **Foundry `forge script` simulator's block-header validation — this is the real reason for the pin, and it is unrelated to (1).** Heima is a Substrate/Aura parachain via Frontier, so its block header has **no `prevrandao`/`mixHash`/`withdrawalsRoot`/`blobGasUsed`** fields — those are Ethereum-PoS-consensus header fields, NOT opcode-capability signals. `forge script ... --broadcast` runs a local simulation that validates the fetched header against the target EVM revision *before broadcasting*; with `evm_version = paris` or higher it requires `prevrandao` and errors:

   ```
   EVM error; header validation error: `prevrandao` not set
   ```

   **Verified 2026-06-01**: running the real `DeployAgentKeysV1.s.sol` against the dev chain with `FOUNDRY_EVM_VERSION=cancun` reproduced this error; with `london` it deploys. (Note: `forge create --broadcast` with `cancun` does NOT hit this — it's specific to `forge script`'s simulator. Our deploy path uses `forge script`, so the pin stays.)

**Practical consequence (unchanged): keep `evm_version = "london"` in `crates/agentkeys-chain/foundry.toml`** so `forge script` broadcasts don't trip header validation. But understand it's a **simulator-header workaround, not an EVM-capability ceiling** — our contracts *may* use ≤Cancun features (PUSH0, transient storage) at runtime if ever needed; only the broadcast simulator cares about the header.

**Why the earlier "London" conclusion was wrong:** it introspected the block header (`baseFeePerGas` present, `mixHash`/`withdrawalsRoot`/`blobGasUsed` absent) and inferred the EVM level from header *format*. Header format reflects the consensus/block-structure layer; opcode support is set independently by Frontier's `config()`. The header check is the right way to predict the **forge-script-simulator** behavior, but the wrong way to determine the **opcode execution level**.

Determine the real opcode level any time by *executing* a probe on a dev chain (authoritative), not by reading the header:

```bash
# spin a dev chain, fund an EVM acct, then:
# deploy a TSTORE/TLOAD contract (Cancun-only) and call it — if it returns its input, EVM >= Cancun.
# (header introspection only tells you what forge-script's simulator will accept, not what the EVM runs.)
```

## Deployed contract registry

Live contract addresses on each chain (Heima mainnet v2 set, the ERC-4337 master infra #164, historical v1) plus the prod/test EVM deployer wallets are kept in [`docs/spec/deployed-contracts.md`](docs/spec/deployed-contracts.md) — the single canonical registry, indexed from `arch.md` §5. (`docs/contracts.md` is now a redirect to it.) The same addresses are also written to `scripts/operator-workstation.env` (via `env_set` in `scripts/heima-bring-up.sh` step 6) for shell-script consumption — those env-file entries are the operational source of truth and `docs/spec/deployed-contracts.md` is the human-readable canonical record (deployer, deploy date, block, explorer links, ABI summary).

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

