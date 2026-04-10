# Plan: AgentKeys v0 — Harness-Driven Staged Execution

## Context

AgentKeys has 15+ specification documents but zero code. The implementation is broken into 8 stages (Stage 0–7) in `v2/plans/development-stages.md` with 105 tests + 6 E2E flows, estimated at 25–34 human-days. The user wants to execute this using the Anthropic harness pattern (initializer → coding loop → evaluator) combined with OMC orchestration tools (ralph for persistence loops, team for parallel stages, ultraqa for E2E cycling).

**Key Anthropic principles applied:**
- `progress.json` + `features.json` + `init.sh` + `stage-N-done.sh` as machine-readable handoff artifacts
- Git commits per deliverable + stage-completion tags for resumability
- Generator-evaluator separation (agent writes code, `stage-N-done.sh` evaluates — no self-grading)
- One feature group per ralph story, committed atomically

**Tool mapping:** `/ralph` = the coding loop (persist until PRD passes). `/team` = parallel agents for independent stages. `/ultraqa` = QA cycling for final E2E.

## Step 1: Create the code repo + harness (human, ~15 min)

```bash
mkdir -p ~/Projects/agentkeys
cd ~/Projects/agentkeys
git init

# Copy spec docs so agents have them without leaving the repo
mkdir -p docs/spec/plans docs/spec/aiosandbox
cp ~/Projects/project-life/projects/idea/agentkeys/v2/*.md docs/spec/
cp ~/Projects/project-life/projects/idea/agentkeys/v2/plans/*.md docs/spec/plans/
cp ~/Projects/project-life/projects/idea/agentkeys/v2/aiosandbox/*.md docs/spec/aiosandbox/

git add -A && git commit -m "docs: seed spec documents from project-life"
```

Then create `CLAUDE.md` in the repo root encoding the harness workflow (read progress.json → run init.sh → pick feature → implement → test → commit → update progress). The plan agent produced the full content for this file.

## Step 2: Stage 0 — Types + Core Trait (ralph, ~2-4 hours)

**Invoke:**
```
/oh-my-claudecode:ralph "Implement Stage 0 per docs/spec/plans/development-stages.md: create Cargo workspace skeleton (7 crates), harness artifacts (init.sh, progress.json, features.json, stage-0-done.sh), agentkeys-types crate (all types from docs/spec/credential-backend-interface.md), agentkeys-core crate (CredentialBackend trait with 15 methods, PaymentRail trait, canonical CBOR serialization, OTP derivation, test vectors). 8 tests must pass. Tag stage-0-done when done."
```

**Deliverables:** Cargo workspace compiles, 8 tests pass, harness artifacts exist, `bash harness/stage-0-done.sh` exits 0.

**Advance:** `bash harness/advance-stage.sh 0 1`

## Step 3: Stage 1 — Mock Backend (ralph, ~1-2 days)

The largest stage: 37 tests, 10 stories. Ralph loops through them.

**Invoke:**
```
/oh-my-claudecode:ralph "Implement Stage 1 per docs/spec/plans/development-stages.md: agentkeys-mock-server (axum + rusqlite) with 7 SQLite tables, 15 REST endpoints implementing every CredentialBackend method, identity linking, master key custody, TTL/single-use enforcement, MockHttpClient connection. 37 tests must pass. See docs/spec/plans/eng-review-test-plan.md for the full test matrix including property tests (pair-code collision, nonce uniqueness) and integrity tests (tamper detection, OTP replay). Tag stage-1-done when done."
```

**Deliverables:** Mock server starts on port 8090, all 37 tests pass, curl smoke test works, `bash harness/stage-1-done.sh` exits 0.

**Advance:** `bash harness/advance-stage.sh 1 2`

## Step 4: Stages 2+3 in parallel (team, ~4-5 hours)

The one parallelization opportunity. Stages 2 (CLI, 14 tests) and 3 (Daemon+MCP, 13 tests) touch entirely different crates — zero merge conflicts.

**Invoke:**
```
/oh-my-claudecode:team 2:executor "Two parallel stages for AgentKeys. AGENT 1: Implement Stage 2 (CLI Core) per docs/spec/plans/development-stages.md — 10 CLI commands in agentkeys-cli, 14 tests, keyring session storage, error messaging spec, --help with examples. AGENT 2: Implement Stage 3 (Daemon + MCP) per docs/spec/plans/development-stages.md — agentkeys-daemon binary with MCP tools (get_credential, list_credentials), kernel hardening (memfd_secret, seccomp, caps), 13 tests. Use AGENTKEYS_SESSION env var as test seam (NOT the production bootstrap). Both agents: read harness/progress.json first, commit per deliverable, tag stage-N-done when complete."
```

**Deliverables:** Both `stage-2-done.sh` and `stage-3-done.sh` exit 0. `cargo test --workspace` passes all 72 tests (8+37+14+13).

**Advance:** `bash harness/advance-stage.sh 3 4`

## Step 5: Stage 4 — Pair/Approve Flow (ralph, ~4-8 hours)

The cross-component integration stage. Modifies both daemon (pair-on-startup) and CLI (`agentkeys approve`).

**Invoke:**
```
/oh-my-claudecode:ralph "Implement Stage 4 per docs/spec/plans/development-stages.md: child-initiates rendezvous pairing (daemon generates keypair → open_auth_request → register_rendezvous → display pair code → long-poll), CLI approve command (fetch_auth_request → display OTP → user confirms → approve_auth_request), recovery flow (--recover with AgentIdentity resolution via identity graph). 11 tests must pass. Two-terminal pair E2E must work. Tag stage-4-done."
```

**Deliverables:** Pair flow works across two terminals, recovery preserves credentials, 11 tests pass.

**Advance:** `bash harness/advance-stage.sh 4 5`

## Step 6: Stage 5 — Provisioner (ralph, ~4-8 hours)

Mixed Rust+TypeScript stage. Playwright browser automation for OpenRouter signup.

**Invoke:**
```
/oh-my-claudecode:ralph "Implement Stage 5 per docs/spec/plans/development-stages.md: agentkeys-provisioner Rust orchestrator (spawn TS subprocess, IPC via stdin/stdout JSON, encrypt API key to shielding key, store_credential), provisioner-scripts/lib/email.ts (Gmail IMAP plus-addressing for verification codes), provisioner-scripts/scrapers/openrouter.ts (Playwright signup flow using email.ts). MCP tool: agentkeys.provision(service). 9 tests must pass. Tag stage-5-done."
```

**Deliverables:** Orchestrator IPC tests pass, email client tests pass, live OpenRouter provision works (manual verification by human).

**Advance:** `bash harness/advance-stage.sh 5 6`

## Step 7: Stage 6 — npm Package + DX (ralph, ~2-4 hours)

Packaging and documentation polish.

**Invoke:**
```
/oh-my-claudecode:ralph "Implement Stage 6 per docs/spec/plans/development-stages.md: @agentkeys/daemon npm package with postinstall binary selection (linux-x64, linux-arm64, darwin-x64, darwin-arm64), install.sh curl script, README with quickstart, docs/how-it-works.md, docs/security-model.md, CHANGELOG, LICENSE (MIT OR Apache-2.0), per-subcommand --help with examples. 7 tests must pass. Tag stage-6-done."
```

**Advance:** `bash harness/advance-stage.sh 6 7`

## Step 8: Stage 7 — Full E2E Integration (ultraqa, ~2-6 hours)

Pure integration testing. No new code, just cross-cutting E2E verification and bug fixes.

**Invoke:**
```
/oh-my-claudecode:ultraqa --custom "bash harness/stage-7-done.sh"
```

UltraQA runs the 6 E2E flows (full lifecycle, multi-agent isolation, pair+MCP+revoke, recovery, MCP auth demo, revocation latency), diagnoses failures, fixes, and repeats up to 5 cycles.

**Done when:** All 6 E2E flows pass. `git tag stage-7-done`. **AgentKeys v0 is demo-ready.**

## Between-stage verification protocol (every transition)

```bash
# Human runs after each stage completes:
bash harness/stage-N-done.sh          # must exit 0
git tag stage-N-done                   # tag the completion
cat harness/progress.json             # verify stage marked complete
bash harness/advance-stage.sh N N+1   # advance to next stage
```

## Error recovery

| Failure | Recovery |
|---|---|
| Ralph session dies mid-story | Re-invoke `/ralph` with same PRD. Ralph reads progress.json + git log and resumes from last completed story. |
| One team agent fails, other succeeds | Invoke `/ralph` individually for the failed stage. The successful stage's work is already committed. |
| Test seems like a spec bug | `credential-backend-interface.md` > `development-stages.md` > `eng-review-test-plan.md` (priority order). Fix spec if genuinely wrong, then re-run. |
| Playwright breaks on live site | Update selectors in `openrouter.ts`. Rust IPC tests still pass (mock subprocess). |
| Stage 7 E2E keeps failing after 5 ultraqa cycles | Human diagnoses root cause. Likely a cross-component integration issue that needs manual architectural judgment. |

## Timeline estimate

```
Day 0    : Repo setup + Stage 0 (ralph)           → stage-0-done
Day 1-2  : Stage 1 (ralph, largest stage)          → stage-1-done
Day 2-3  : Stages 2+3 in parallel (team)           → stage-2-done + stage-3-done
Day 3-4  : Stage 4 (ralph)                         → stage-4-done
Day 4-5  : Stage 5 (ralph)                         → stage-5-done
Day 5-6  : Stage 6 (ralph)                         → stage-6-done
Day 6-7  : Stage 7 (ultraqa)                       → stage-7-done
Day 7    : DEMO READY ✓
```

**~7-10 days with agent execution** (vs. 25-34 days human-solo per the spec). Parallelization of Stages 2+3 saves ~4 days. Agent speed compresses each stage by ~60%.

## Critical files

- `v2/plans/development-stages.md` — the 8-stage implementation contract (759 lines)
- `v2/credential-backend-interface.md` — the CredentialBackend trait (454 lines)
- `v2/architecture.md` — Cargo workspace layout and component inventory (355 lines)
- `v2/plans/eng-review-test-plan.md` — the full test matrix (122 lines)
- `v2/plans/ceo-plan.md` — product scope decisions constraining v0 (490 lines)

## Verification

After Stage 7 completes:
```bash
cd ~/Projects/agentkeys
cargo test --workspace                    # 105 tests pass
bash harness/stage-7-done.sh              # 6 E2E flows pass
git tag -l | grep stage                   # 8 tags: stage-0-done through stage-7-done
cat harness/progress.json | jq .stages   # all 8 stages: "complete"
wc -l harness/features.json              # all features implemented: true
```

The system is demo-ready for the 4-demo meetup talk (multi-agent isolation, recovery, provisioning-in-action, cost transparency).
