# AgentKeys

## Architecture
Rust monorepo with Cargo workspace. See `docs/arch.md` for component inventory.
See `docs/spec/credential-backend-interface.md` for the CredentialBackend trait contract (15 methods).
Do not read folder `docs/archived`

## Client (front-end only — skip for backend context)
The browser UI lives in four front-end dirs, **separate from the Rust backend and not needed as context for broker/daemon/chain/cli work** — don't read them unless the task is front-end:
- [`design-system/`](design-system/) — shared `@agentkeys/design-system`: design tokens (3 themes, bilingual EN/中文, two font sets) + React components, consumed by every app (`tokens.json` is the color source-of-truth → `scripts/generate-tokens.mjs`).
- TanStack Start apps [`apps/website`](apps/website) (`:3116`), [`apps/mobile-mock`](apps/mobile-mock) (`:3117`), [`apps/design-system`](apps/design-system) (`:3118` — component gallery + theme curator). Run via the fleet `d` menu or `npm --prefix <dir> run dev`.

node_modules / build output / generated route trees / lockfiles are gitignored — regenerable from `package.json` + source.

## Docs layout (lean)
`docs/arch.md` is the single source of truth — brief, indexes every detail via outward links. Sub-folders, each one audience:
- `docs/spec/` — developers + coordinating colleagues (cloud, CI, blockchain, signer-protocol, threats).
- `docs/research/` — third-party context (Heima, EIP-191/712, aiosandbox, agent memory).
- `docs/wiki/` — end users + hardware integrators; mirrored to GitHub Wiki by [`publish-wiki.yml`](.github/workflows/publish-wiki.yml).
- `docs/market/` — investor / BD / marketing collateral (pitch deck, website content, positioning); audience = investors / partners / marketing. Not indexed from arch.md (not architectural).
- `docs/archived/` — superseded files; never linked from arch.md, never read in normal dev. Move stale files here, don't delete. Run the `agentkeys-docs` skill to audit + compact.

**User-facing instructions** — every behavior/caveat a user would notice (e.g. `agentkeys wire` taking over the runtime's `hooks:` block) goes in [`docs/user-manual.md`](docs/user-manual.md), the single home for user-aware instructions.

## Architecture-as-source-of-truth policy
[`docs/arch.md`](docs/arch.md) is the **single source of truth** for component inventory, key inventory (K1–K11), trust boundaries, identity model (HDKD actor tree), and per-actor binding ceremonies. **After editing any architectural doc** (broker plans, signer-protocol, demo doc, runbooks, heima-gaps), re-open `arch.md` and verify it still matches; if it diverges, update arch.md in the same change. If the per-doc detail outgrows arch.md, link from arch.md outward — never duplicate. The wiki page at [`docs/wiki/agent-role-and-usage-hdkd-per-agent-omni.md`](docs/wiki/agent-role-and-usage-hdkd-per-agent-omni.md) is a focused operator reference for the agent role; it defers to arch.md.

## `/create-pr` policy
When the `/create-pr` skill is invoked from a Claude Code worktree at `.claude/worktrees/<name>`, the worktree is a *git worktree* under the main repo — `jj` cannot colocate there (`jj git init --colocate` fails with "Cannot create a colocated jj repo inside a Git worktree"). Use this hybrid workflow so the jj-only rule is preserved everywhere it can be:

1. **Commit (worktree, git — unavoidable).** From the worktree, `git add <explicit files> && git commit -m "<message>"`. Git is necessary at this step because jj cannot read a git-worktree's filesystem; the commit lands in the shared git object store and advances the branch ref. **Do NOT include `Co-Authored-By:` lines** — the commit author is the agent identity that ran the commit; appended co-author tags are wrong attribution.
2. **Push (main repo, jj).** `cd` to the main repo, then `jj git fetch && jj git push -b <branch-name>` to push to `origin`. This is the jj-required step — jj fully controls remote interaction once the commit exists locally.
3. **PR (anywhere, gh).** `gh pr create --title "..." --body "$(cat <<'EOF' ... EOF)"`. The gh CLI is not git/jj-specific.

Outside Claude Code worktrees (i.e. directly in the main repo), the whole flow is jj per the standard "use `jj`, never raw `git`" rule from this file.

## Wiki-location policy
**All project wiki pages live under [`./docs/wiki/`](docs/wiki/) — never under `.omc/wiki/`, the root-level `./wiki/`, or anywhere else.** `./docs/wiki/` is the canonical, version-controlled wiki source (auto-published to the GitHub wiki on every push to `main` by [`.github/workflows/publish-wiki.yml`](.github/workflows/publish-wiki.yml)); `.omc/` is git-ignored per-session scratch and must not hold durable knowledge. When you create a new wiki page, write it directly to `./docs/wiki/<page-name>.md` with the Write tool — do NOT use `wiki_add` / `wiki_ingest` (those tools default to `.omc/wiki/` and will hide the page from operators + lose it to gitignore). When you find an existing page under `.omc/wiki/` or root-level `./wiki/`, move it to `./docs/wiki/` in the same change and update all references; leave the old locations empty going forward. New `./docs/wiki/` pages should follow the existing-page style: **no YAML frontmatter and no redundant leading `# H1`**, plain markdown, relative links to other wiki pages with `./other-page.md` and to repo files with `../../path/to/file`.

**Why no frontmatter and no leading H1 (the GitHub-Wiki rendering rules):** [`publish-wiki.yml`](.github/workflows/publish-wiki.yml) is a *raw* mirror — GitHub Wiki renders each page's title from its **filename** and copies the body verbatim, with no transform. So (a) a `---…---` frontmatter block is NOT stripped — it renders as a literal heading + sidebar-preview text; and (b) a body `# H1` duplicates the filename-derived page title AND pushes every section one level deeper in the right-sidebar table of contents. Open each page body on real content instead — a lead paragraph, a `**Status:**`/`**Scope:**` block, a `>` note, or an `## H2`. **CI enforces both rules** via [`scripts/utils/lint-wiki.sh`](scripts/utils/lint-wiki.sh) (workflow [`.github/workflows/wiki-lint.yml`](.github/workflows/wiki-lint.yml), runs on every PR touching `docs/wiki/**`); run `bash scripts/utils/lint-wiki.sh` locally before pushing. (Documentation alone was insufficient — the "no frontmatter" rule predated the lint and 22 pages still shipped with frontmatter + redundant H1s because the OMC `wiki_*` tooling injects them; the lint is the actual gate.)

### Terminology-source-of-truth rule
**Never invent a new name for a concept that arch.md already names.** When a doc, runbook, CLI output, or commit message needs to refer to a wallet / omni / key / endpoint that exists in arch.md, use the arch.md spelling verbatim. If a component currently emits a different label (e.g. `agentkeys whoami` prints `session_wallet:` while arch.md / the OIDC JWT call the same field `agentkeys_user_wallet` / `JWT.agentkeys.wallet_address`), either (a) align the component to the arch.md name OR (b) document the alias in arch.md's "Canonical names" section as an explicit synonym — never let the divergence silently persist. Drift is auditable only if it's explicit.

When you discover a name divergence while making any change, fix it in the same commit (or open a follow-up issue if the rename ripples beyond the current scope — but call out the divergence in the commit message either way). The cure for terminology drift is "one name, one concept, written down in arch.md's canonical-names section"; the disease is operators having to read three docs to figure out whether `master_wallet` / `session_wallet` / `agentkeys_user_wallet` are the same thing.

## Version Control
Use `jj` (Jujutsu) for all version control. Never use raw `git` commands.

## Diagnosis-before-edit policy
Before changing any file in response to a reported failure, **reproduce the failure locally** and isolate the layer (shell quoting, client tooling, doc command, broker code, network). If the cause is local (shell, copy-paste, env var), respond with the one-line fix and let the user run it — do NOT edit code or docs. Only edit when the cause is in the repo. Keep the response concise: failing command, root cause, fix command — nothing else.

## No-silent-override policy
**Don't silently override. Whenever you reach for an override, stop and ask whether you've ignored the real reason.** An "override" — an env-var override, a fallback default, a shim, a post-resolve mutation, a "just set it here too" — that masks a root cause is a bug-in-waiting: it papers over a divergence (one component reading a different source, a value not propagating, a missing wiring) instead of fixing it where it lives.

- **Never add a *silent* override** — one that quietly diverges from how the rest of the system resolves the same value. If component A reads a value from source X and you find yourself "overriding" it in component B, first find **why B doesn't read X**. Usually B is the OUTLIER and the fix is to wire B onto X, not to bolt an override onto B.
- An override is correct ONLY when it IS the root fix: a genuine, documented operator knob with a clear, shared precedence — never a patch over a difference you didn't diagnose.
- Real incident: the web chain badge showed a stale RPC because the daemon was the ONE component reading the compiled chain profile while the broker, every worker, and the bundler all read `AGENTKEYS_CHAIN_RPC_HTTP`. The reflex ("add an RPC override to the daemon") would have shipped a SECOND silent source of truth; the real fix was to bring the daemon onto the SAME env var the rest of the system already used.

Pairs with the Diagnosis-before-edit policy: diagnose the root, fix it at the source; an override is a last resort, never a reflex.

## Land-the-fix policy
Once a local repro proves a fix is correct, **land it the same turn**: edit every affected file (search repo-wide — never assume one file), commit, push to your working branch (PR'd to `origin/main`). Do not stop at "verified locally" or "fixed in one place" — the next operator running the docs will hit the same bug if the fix isn't on `origin/main`. Pair this with the diagnosis-before-edit policy: diagnose once, fix everywhere, push immediately.

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

## Per-actor + per-data-class isolation invariants (issue #90)

Four-layer defense-in-depth. The **canonical table** (per-layer invariants, cap-endpoint inventory, stage-3 demo step numbers, rationale) is [arch.md §17.5](docs/arch.md); summary:

1. **Broker cap-mint** — [`handlers/cap.rs`](crates/agentkeys-broker-server/src/handlers/cap.rs) `mint_cap()` + `verify_cap_pop()`: session-JWT omni == request `operator_omni`, device binding + `ROLE_CAP_MINT`, service in scope, K10 cap proof-of-possession when supplied (#76).
2. **Worker chain-verify** — [`agentkeys-worker-creds/src/verify.rs`](crates/agentkeys-worker-creds/src/verify.rs) (shared by the cred/memory/config/classify workers): independent re-check of layer 1 against the chain (defense against broker compromise); K10 PoP *presence* enforced once `AGENTKEYS_WORKER_REQUIRE_CAP_POP=1` (staged rollout, arch.md §22b.4).
3. **AWS IAM PrincipalTag scoping** — `scripts/provision-{vault,memory,config}-role.sh` + `apply-*-bucket-policy.sh`: S3 ARNs interpolate `${aws:PrincipalTag/agentkeys_actor_omni}`; `s3:ListBucket` carries the `s3:prefix` condition.
4. **Per-data-class bucket separation** — one IAM role per bucket (vault / memory / config, #201); creds for one data class in another's bucket → AccessDenied (arch.md §17.2).

Cap-tokens are **data-class-explicit**: six storage endpoints (`/v1/cap/{cred,memory,config}-{store,fetch}` — the route statically fixes the SIGNED `data_class` field) plus the `/v1/cap/classify` compute gate (#207, the only endpoint whose `data_class` comes from the body). Workers reject mismatches with HTTP 403 `cap_data_class_mismatch` — the cap-layer twin of the IAM cross-bucket gate, enforced before the worker touches AWS.

**Hard rules:**
- Every PR touching storage / OIDC / cap-mint / worker handlers MUST add a stage-3 demo test for the layer it touches. A NEW worker / data class / broker auth method MUST extend the stage-3 demo with negative cross-isolation tests for ALL FOUR layers — never positive-path-only.
- A NEW data class follows the closed-extension recipe: two cap endpoints, a `DataClass` variant, a mirrored worker crate + provision/apply scripts + `setup-broker-host.sh` wiring, stage-3 negatives. `config` (#201, master-only → rides the #195 master-self skip) is the template; existing data classes need no changes. (The deploy-side env-file discipline for a new data class lives in `AGENTS.ops.md`.)

## Broker/worker request shapes have ONE owner (issue #203)

The broker/worker client protocol — the six `/v1/cap/*` mint endpoints, the STS relay, worker put/get body types, audit append, the `memory:<ns>` service builder, the `0x`-omni normalizer — has ONE definition, split across two crates by transport-safety: the wire **types** live in [`agentkeys-protocol`](crates/agentkeys-protocol/) — pure serde, transport-free, compiles to `wasm32` — and the native **client** (cap-mint → STS → worker) in [`agentkeys-backend-client`](crates/agentkeys-backend-client/), which re-exports the types as `agentkeys_backend_client::protocol` (field types co-owned with [`agentkeys-types`](crates/agentkeys-types/)). The browser host [`agentkeys-web-core`](crates/agentkeys-web-core/) (wasm) depends on the SAME `agentkeys-protocol`, so the cap-mint body cannot drift across native vs browser — it used to (`ttl_seconds` required-`u64` vs `Option<u64>`, and web-core's copy was missing the #76 K10 PoP fields). web-core must NOT depend on `agentkeys-backend-client` directly: that crate pulls `aws-sdk-sts` + `tokio` + native `reqwest` (via the provisioner) and breaks the wasm build — the `wasm32` CI gate in `e2e-ci.yml` enforces this. **Never re-type a cap/worker body in a second Rust path or in bash** (the #200 drift-bug class). All Rust callers (the MCP server's `BackendClient`, daemon `ui_bridge`, web-core) compile against the shared types, so a drifted shape is a compile error; bash and the web app are fixture-gated in CI.

**Rules when you touch this surface:**
- Wire-field change → edit the serde type in [`agentkeys-protocol`](crates/agentkeys-protocol/) (the single definition; re-exported as `agentkeys_backend_client::protocol`), regenerate the committed fixtures (`cargo run -p agentkeys-backend-client --bin dump-protocol-fixtures`), update the frozen key-set test in `fixtures.rs`. The native callers AND the browser host recompile against the new shape automatically; the `wasm32` gate proves the browser still builds.
- Harness steps drive the `agentkeys` CLI, not hand-rolled curls. Raw curls only for negative / HTTP-status tests; a body that mirrors a canonical shape carries `# @backend-fixture: <shape>` ([`scripts/utils/check-backend-fixture-drift.sh`](scripts/utils/check-backend-fixture-drift.sh) diffs it against [`e2e/fixtures/backend-protocol/`](e2e/fixtures/backend-protocol/) in CI); deliberately-malformed negative payloads are NOT annotated.
- **The frontend's wire types are GENERATED, never hand-mirrored (#215 re-land B2, rung 3).** `ts-rs` derives on the `ui_bridge.rs` `Api*` structs, the catalog `Sensitivity`, and the protocol UserOp build/submit responses emit [`apps/parent-control/lib/generated/*.ts`](apps/parent-control/lib/generated/); [`daemon.ts`](apps/parent-control/lib/client/daemon.ts) imports them instead of re-declaring interfaces, so a Rust-side rename is a frontend **compile error**. After changing one of those structs: `cargo test export_bindings` (any `cargo test` triggers it), commit the regenerated `.ts`. CI (`e2e-ci.yml` rust-checks) `git diff --exit-code`s the generated dir AND runs `npm run typecheck` against a fresh wasm-pack build, so both the bindings and their consumers are gated. `u64` fields carry `#[ts(type = "number")]`; skip-serialize `Option`s carry `#[ts(optional)]`. Never edit `lib/generated/` by hand, and never add a hand-declared wire interface next to a generated one.
- The daemon's web-API plant contract lives one rung lower still (#275 tier-3): route + `ApiMemoryEntry` + plant request/response bodies are owned by [`agentkeys-protocol::web_api`](crates/agentkeys-protocol/) (re-exported by `ui_bridge.rs`); the React frontend consumes them via the `agentkeys-web-core` **wasm builder** (`masterMemoryPlantRoute()` + `buildMasterMemoryPlantBody()` — one code path, drift is a compile error), and the one remaining hand-built consumer (`e2e/suite-6-web-parity.sh`) stays `@web-fixture`-annotated against [`e2e/fixtures/web-api/master_memory_plant.json`](e2e/fixtures/web-api/master_memory_plant.json), gated by [`scripts/utils/check-web-api-drift.sh`](scripts/utils/check-web-api-drift.sh) (the fixture itself is pinned to the shared types by a `ui_bridge` unit test).
- Field names are the arch.md canonical spellings — never invent a synonym in a new body.

## Harness rules (operator-internal)

The harness — the demo orchestrators that drive real deploys, plus the authoring
contract `e2e/AGENTS.md` — is operator-internal and **not in the OSS mirror**.
The only public harness surface is `e2e/fixtures/`, the wire-protocol fixtures
the CI drift gates (`check-backend-fixture-drift.sh`, `check-web-api-drift.sh`)
diff against; the fixture/codegen discipline that touches the public crates lives
in the "Broker/worker request shapes have ONE owner" section above.

## Heima EVM compatibility level — keep `evm_version = "london"` in foundry.toml (but NOT because Heima is "London")

> **Migration index:** every Heima-vs-Ethereum EVM divergence the repo works around (this `evm_version` pin, the `eth_estimateGas`-reverts-on-`handleOps` gas-limit pins, the mixHash-less-receipt on-chain re-verify posture, the `cast send --create` deploy path, the year-prefixed `chain_id`) is consolidated as a **gap → symptom → workaround → code site → what-changes-on-eth** inventory in [`docs/spec/heima-eth-gap.md`](docs/spec/heima-eth-gap.md), with a Heima→Ethereum migration checklist. This section stays the canonical home for the *capability proofs* below; the gap doc defers here for them.

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

Live contract addresses on each chain plus the prod/test EVM deployer wallets are documented in [`docs/spec/deployed-contracts.md`](docs/spec/deployed-contracts.md) — **human PROSE only** (deployer wallets, ABI summaries, cutover/historical notes, explorer links), indexed from `arch.md` §5. (`docs/contracts.md` redirects to it.) It **no longer carries an address table** — the addresses live in the chain profile (below).

**The machine-readable SOURCE OF TRUTH is the chain profile [`crates/agentkeys-core/chain-profiles/<chain>.json`](crates/agentkeys-core/chain-profiles/heima.json)** — a strict-typed `ChainProfile` (Rust struct + `include_str!` + the `chain_profile::tests::heima_carries_full_contract_registry_and_version` pinning test). Its `contracts[]` array holds each contract's address; `contract_set_version` holds the deployed SET version. The chain bring-up rewrites it programmatically on every fresh deploy (alongside `scripts/operator-workstation.env`, the shell mirror). The **expected** source version lives in [`crates/agentkeys-chain/VERSION`](crates/agentkeys-chain/VERSION). (The former `deployed-contracts.json` was folded INTO the chain profile — do not re-create it.)

**Two HARD rules when any contract changes:**

1. **Idempotency is by VERSION, not bytecode.** Solidity bytecode isn't reliably comparable (embedded metadata hash + immutables), so do NOT diff bytecode. A redeploy is warranted when `crates/agentkeys-chain/VERSION` ≠ the chain profile's `contract_set_version` (or there's no on-chain code). **Bump `VERSION` when you change a contract** → the next deploy redeploys + bumps the profile's `contract_set_version`. A `VERSION` mismatch while code is already live is a **hard stop** (the script prints the mismatch + asks for an explicit opt-in — orphaning state costs mainnet gas), not an auto-redeploy.
2. **A new deploy auto-updates the two machine mirrors (chain profile + `operator-workstation.env`); YOU update only the prose + rebuild.** You ALSO touch `docs/spec/deployed-contracts.md` **only if the design/version changed** (the version line + any ABI/cutover note — no address table to edit), and since the profile is `include_str!`-compiled, rebuild the broker/daemon/UI so they serve the new addresses. `arch.md` §5 links to the registry (no literal addresses to edit). The deploy + **commit-before-redeploy ordering is operator-only — see `AGENTS.ops.md`.** **Confirm locally AND in CI:** `bash scripts/utils/check-deployed-contracts-sync.sh` — verifies the chain profile ⟷ `operator-workstation.env` mirror AND (#251) that no tracked `.md` re-introduces a literal contract address a chain profile owns (docs must **anchor** to the profile — link + jq/grep resolve command — never copy; historical/orphaned addresses pass since they're no longer in the profile). CI runs it via the cheap [`.github/workflows/contracts-sync.yml`](.github/workflows/contracts-sync.yml) on PRs touching markdown / chain profiles / the env mirror.

Verify all contracts are live + functional any time:

```bash
AGENTKEYS_CHAIN=heima       bash scripts/utils/verify-heima-contracts.sh
AGENTKEYS_CHAIN=heima-paseo bash scripts/utils/verify-heima-contracts.sh   # when Paseo collators come back up
```

The verify script is read-only RPC (zero gas), exits 0 on all-pass / 1 on any failure. Run after every chain bring-up to confirm the deploy was clean.

## Rust toolchain pin (single source of truth)
[`rust-toolchain.toml`](rust-toolchain.toml) pins the EXACT Rust version + components (clippy, rustfmt) for every surface — local dev, all CI jobs, the broker-host build. **Never a floating `stable`**: CI lints with `-D warnings`, so a floating channel turns new-stable lints into CI-red-while-local-green skew (the PR #270 incident). Workflows install via plain `rustup toolchain install`, which reads the pin; **never reintroduce `dtolnay/rust-toolchain@stable`** — it sets `RUSTUP_TOOLCHAIN`, bypassing the file (even a version-pinned `@1.x.y` is a second pin site that drifts). CI-gated by [`scripts/utils/check-toolchain-pin.sh`](scripts/utils/check-toolchain-pin.sh). Bump = ONE change: edit `channel`, fix any new fmt/clippy lints, commit pin + fixes together — full ritual in [`docs/dev-setup.md`](docs/dev-setup.md) "Toolchain pin + bump ritual".

## Code Conventions
- Rust: `thiserror` for library errors, `anyhow` for binary errors
- All async: `tokio` runtime, `#[tokio::test]` for async tests
- **Bash: never expand a possibly-empty array unguarded under `set -u`** — the operator laptop runs **bash 3.2**, where `"${arr[@]}"` on an EMPTY array is an `unbound variable` error; bash ≥4.4 (CI + every Linux host) expands it to nothing, so the bug is invisible everywhere except the machine that runs the deploy scripts. Use the expand-if-set idiom: `cmd ${args[@]+"${args[@]}"}` (no outer quotes — the inner ones preserve per-element quoting). The classic shape is an args array seeded empty and appended to only conditionally (`[ "$DRY_RUN" = 1 ] && args+=(--dry-run)`), which breaks the **normal** path while the dry-run path works — exactly how `setup-cloud.sh` step 18 (#440/#447) and `setup-heima.sh` step 14 shipped broken. CI-gated by [`scripts/utils/check-bash-empty-array-expansion.sh`](scripts/utils/check-bash-empty-array-expansion.sh) (e2e-ci `rust-checks`), which flags only the provably-possibly-empty shape.
- **Never mutate process env in tests** — no `std::env::set_var`/`remove_var` anywhere under `crates/`; process env is global and `cargo test` runs tests on parallel threads, so one test's mutation leaks into concurrently running siblings (the #258/#259 flake class). Inject instead: read env once in a `from_env()`-style constructor and have tests build the config struct / pass the value explicitly (`BrokerConfig`, `BundlerBootValues` pattern). CI-gated by [`scripts/utils/check-no-env-mutation-in-tests.sh`](scripts/utils/check-no-env-mutation-in-tests.sh) (e2e-ci `rust-checks`); exceptions need an allowlist entry there with the removal condition.
- Crate names: agentkeys-types, agentkeys-core, agentkeys-cli, agentkeys-daemon, agentkeys-mock-server, agentkeys-mcp, agentkeys-provisioner
- Git commits: `agentkeys: stage N -- <deliverable>`
- Never self-grade: run the e2e suite (`bash e2e/suite.sh`; one phase: `--stage N`) to verify
- **Always `cargo fmt --all` before committing** — CI's `cargo fmt --all -- --check` is a verifier, not a fixer, so unformatted code is a guaranteed red (the common trap: a standalone `//` comment placed right after a line with a trailing `// comment`, which rustfmt right-aligns). The committed [`.githooks/`](.githooks) pre-commit hook (installed by `setup-dev-env.sh` via `core.hooksPath`) enforces this for BOTH workspaces (root + `viz/server`). It fires on the `git commit` step — note `jj git push` bypasses git hooks, so the pre-commit hook, not pre-push, is the real gate. See [`docs/dev-setup.md`](docs/dev-setup.md) "Git hooks".

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
