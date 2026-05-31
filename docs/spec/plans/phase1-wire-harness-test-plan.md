# Phase 1 wire harness — test plan + action table

**Status:** DRAFT 2026-05-28 — review the automation decisions below before the harness script is built.
**Tests:** PR #141 (`agentkeys wire` + `agentkeys hook`) end-to-end against the real backend.
**Reuses:** the account `setup-heima.sh` already creates (master + agent), the live broker + workers, and the Heima contracts. This harness does NOT re-create chain state — it verifies + layers the wire/hook flow on top.

## 1. Topology

```
┌─ MacBook (MASTER) ───────────────┐        ┌─ aiosandbox (AGENT) ──────────────┐
│ operator_omni  (session "alice") │        │ actor_omni  (demo-agent)          │
│ agentkeys CLI (master session)   │        │ Hermes (Task Host)                │
│   - provision creds (LLM key)    │        │ agentkeys CLI (hook helpers)      │
│   - grant / revoke memory scope  │        │ agentkeys-mcp-server (--backend   │
│   - seed agent memory (S3)       │        │   http → broker) on :8088         │
└──────────────┬───────────────────┘        │ wired hooks → MCP → broker        │
               │                             └──────────────┬────────────────────┘
               │ both point at the same live broker + workers
               └──────────────► broker / cred+memory+audit workers / Heima chain
                                (URLs + contract addrs from operator-workstation.env)
```

- **Master = MacBook** holds the operator identity + authority actions (provision, grant, revoke).
- **Agent = sandbox** holds the actor identity; Hermes runs here, wired so its hooks call AgentKeys as the actor.
- **Backend = real** (`--backend http`). The in-memory backend (Mode L below) is the fast pre-check; the account-reuse test is Mode R.

## 2. Two run modes

| Mode | Backend | Account | Use |
|---|---|---|---|
| **L — light** (inner loop) | `--backend in-memory` (seeds demo actor + `travel`/`family`/`profile`) | none; demo constants | Fast plumbing check of wire + hooks. Already passing (PR #141 smoke test). Fully automated, no manual gates except none. |
| **R — real** (this plan) | `--backend http` → live broker + workers + Heima | **reuse** `setup-heima.sh` master (`alice`) + agent (`demo-agent`) | The account-reuse end-to-end. The table below is Mode R. |

The harness defaults to **Mode R**; pass `--light` to run Mode L as a pre-flight.

## 3. Automation-decision principles

1. **Automate anything deterministic, non-interactive, and idempotent.** Chain reads, healthz, file writes (incl. the binary into the sandbox via the sandbox's own MCP), hook smoke-calls, wire.
2. **Real account, real K11 — no stubs.** This harness reuses the existing real account: the master's **email login is automated** (real email, the harness fetches + follows the verification link, same path `setup-heima.sh` already uses) and **K11 is a real Touch ID ceremony** (`--webauthn`, real Secure Enclave passkey). We are NOT in stub mode — the point is to test the real biometric authority path.
3. **Keep three things manual — they are the "test through" essence:**
   - **LLM key provisioning** (a real secret, pasted once) — never bake a key into a script.
   - **Real K11 Touch ID** at the master authority step (scope grant, if not already granted from the reused account) — a genuine biometric gate.
   - **The final Hermes "surprise"** (open Hermes in the sandbox, send a query, judge the memory-aware response) — human judgment + a real LLM call.
   - (+ the `[y/N]` confirmation of the surprise.)
4. **Reuse, never re-create.** The account, chain bindings, broker, workers are prerequisites verified (not rebuilt) here. Re-creating them is `setup-heima.sh`'s job.
5. **Idempotent end-to-end.** Every step pre-checks + short-circuits (`ok proceeding / skip <reason> / fail <reason>`). This harness has **no state-mutating demo step** — Act 3 (revocation) is out of scope (tested elsewhere) — so re-runs are pure no-ops once the account + wiring are in place.

## 4. The action table (Mode R)

Legend — **Host**: M = MacBook (master), S = sandbox (agent), H = human. **A/M**: AUTO / MANUAL. (No stub mode — email login is automated against the real account; K11 is a real Touch ID gate.)

### Phase 0 — Prerequisites (verify reuse; don't rebuild)

| # | Action | Host | A/M | Idempotency pre-check (skip-if) | Expected |
|---|---|---|---|---|---|
| 0.1 | Heima contracts live | M | AUTO | `verify-heima-contracts.sh` exits 0 | all 6 contracts respond |
| 0.2 | Broker + cred/memory/audit workers healthy | M | AUTO | each `/healthz` returns 200 | ok |
| 0.3 | Operator master registered + K11 enrolled (real account; email login automated) | M | AUTO | `cast call SidecarRegistry isMaster(operator_omni)` == true | registered |
| 0.4 | Agent `demo-agent` created + funded (mainnet HEI; operator has funds) | M | AUTO | agent wallet file exists (0600) + on-chain device row present | exists |
| 0.5 | Scope operator→actor→`memory` granted | M | AUTO if already granted; else **MANUAL (real Touch ID)** | `cast call AgentKeysScope isServiceInScope(...)` == true | granted — skips silently if the reused account already has it; otherwise `heima-scope-set.sh --webauthn` prompts a real Touch ID |
| 0.6 | LLM API key for the Phase 4 surprise | M | **AUTO** if `OPENROUTER_API_KEY` exported (e.g. `~/.zshenv`); else MANUAL paste | env `OPENROUTER_API_KEY` / `LLM_API_KEY` set | resolved from env (no prompt); if absent, paste once or skip Phase 4 |
| 0.7 | Agent memory seeded — `travel` from `tests/fixtures/demo-profile.md` | M | AUTO | `agentkeys ... memory get travel` returns content | seeded |

### Phase 1 — Sandbox bring-up (agent host)

| # | Action | Host | A/M | Skip-if | Expected |
|---|---|---|---|---|---|
| 1.1 | aiosandbox container running | S | AUTO | `docker ps` shows the sandbox (detached `-d`, `--security-opt seccomp=unconfined`) | up; `:8080/healthz` ok |
| 1.2 | Hermes installed in sandbox | S | AUTO | `hermes --version` succeeds (guarded `curl\|bash`) | installed |
| 1.3 | `agentkeys` binary present in sandbox — pushed via the **sandbox's own MCP file ops** (`sandbox_file_operations` / `POST :8080/v1/file/write`), not scp | S | AUTO | `agentkeys --version` in sandbox | present (uploaded through the sandbox MCP, then chmod +x) |
| 1.4 | MCP server up in sandbox (`--backend http` → broker) | S | AUTO | `curl localhost:8088/healthz` 200 | ok; tools/list = 10 |

### Phase 2 — Wire (the #141 core)

| # | Action | Host | A/M | Skip-if | Expected |
|---|---|---|---|---|---|
| 2.1 | `agentkeys wire hermes --check-only` | S | AUTO | (read-only) | step 0 detect ok; would-write plan |
| 2.2 | `agentkeys wire hermes` (`--actor-omni <demo-agent>` `--operator-omni <alice>` `--mcp-url localhost:8088`) | S | AUTO | scripts + managed block already match → all `skip` | scripts + config + consent written; `hermes hooks doctor` ok |
| 2.3 | Verify managed block in `~/.hermes/config.yaml` | S | AUTO | grep sentinel markers | present |
| 2.4 | Re-run wire (idempotency proof) | S | AUTO | — | every step `skip … matches` |

### Phase 3 — Acts 1 + 2 + audit (IAM guarantees, real backend)

> **Act 3 (revocation) is OUT OF SCOPE for this harness** — it's tested elsewhere. Dropping it keeps this harness a pure no-op on re-run (no scope churn, no extra mainnet gas).

| # | Action | Host | A/M | Notes | Expected |
|---|---|---|---|---|---|
| 3.1 | **Act 1** memory-inject `travel` (agent hook) | S | AUTO | real cred-mint → memory worker | `{"context":"## Memory: travel\n…Chengdu…"}` |
| 3.2 | Act 1 isolation — agent reads only ITS actor's memory | S | AUTO | per-actor S3 isolation (PrincipalTag) enforced; **namespace is wire-level only in M1** (see #108 note) | cross-actor read → AccessDenied |
| 3.3 | **Act 2** check over-cap (600 > 500) | S | AUTO | PolicyEngine in MCP server (deterministic, no backend) | `{"decision":"block","reason":"daily_spend_cap_exceeded: …"}` |
| 3.4 | Act 2 under-cap (200) | S | AUTO | — | `{}` |
| 3.5 | Auto-audit — `hook audit` appends a row | S | AUTO | real audit worker | `{}` returned; row written |
| 3.6 | Verify audit row in the off-chain feed | M | AUTO | query audit worker for the actor | row present (op_kind, params hash) |

### Phase 4 — The "surprise" (human-judged)

| # | Action | Host | A/M | Notes | Expected |
|---|---|---|---|---|---|
| 4.1 | Open **Hermes in the sandbox** (v0.14.0 — has the hook system); send "where am I going this weekend?" | S | **MANUAL** | real Hermes session + the LLM key; the wired `pre_llm_call` hook injects the `travel` memory | response references Chengdu |
| 4.2 | Confirm the memory-aware surprise | H | **MANUAL** | `[y/N]` prompt in the harness | operator confirms |

### Phase 5 — Teardown (account kept; pure no-op re-runs)

| # | Action | Host | A/M | Notes | Expected |
|---|---|---|---|---|---|
| 5.1 | Stop the sandbox MCP server | S | AUTO | leave the container + Hermes + wiring up for re-runs | stopped |
| 5.2 | Keep account + chain + agent + creds + scope grant | — | no-op | nothing mutated (no Act 3) → next run is a clean no-op | — |
| 5.3 | (optional) `agentkeys wire hermes` unwire — remove managed block | S | AUTO | only with `--unwire` | block removed |

## 5. Manual gates — the "test through" essence

| Gate | Step | Why it stays manual |
|---|---|---|
| LLM key | 0.6 | **Auto when `OPENROUTER_API_KEY` is exported** (the harness inherits it from your shell, e.g. `~/.zshenv`). Only prompts when the env var is absent — never scripted into the repo. |
| Real Touch ID K11 | 0.5 (scope grant) — only when the reused account doesn't already have the `memory` scope | Real biometric authority ceremony (`--webauthn`, Secure Enclave). The email login that establishes the master session is automated; the K11 signature is the genuine human gate. Skipped entirely when the account is already scoped. |
| The Hermes surprise | 4.1 | Needs a real LLM call + the whole chain live. The payoff moment. |
| Surprise confirmation | 4.2 | Human judgment that the response is genuinely memory-aware. |
| Surprise confirmation | 4.3 | Human judgment that the response is genuinely memory-aware. |

Everything else is automated (email login included). The only human stops are 0.5 (real Touch ID — and only if the reused account isn't already scoped), 0.6 (LLM key, once), and 4.1–4.2 (the payoff).

## 6. Idempotency contract

- Re-running the harness is safe: every step has a skip-if pre-check; the account/chain/broker are verified, not rebuilt.
- **No mutating demo step** — Act 3 (revocation) is out of scope, so the harness never changes scope/chain state. Once the account is scoped + wired, a re-run is a pure sequence of `skip`s through to the manual surprise.
- Output convention per step: `ok proceeding` / `skip <reason>` / `fail <reason>` (CLAUDE.md idempotent-remote-setup rule).
- Cross-machine state (M↔S) is reconciled by reading the live broker/chain, never by caching local assumptions.

## 7. Proposed harness shape (for the build step — pending approval of this table)

- `harness/phase1-wire-demo.sh` — the orchestrator (`--webauthn` for the real K11 ceremony at scope grant, `--unwire`, per-phase `--skip-N`, `--yes` to auto-advance non-secret prompts).
- Reuses `verify-heima-contracts.sh`, `heima-scope-set.sh`, `heima-agent-create.sh` (NOT `heima-scope-revoke.sh` — no Act 3). Agent-side steps run via the sandbox MCP: `sandbox_execute_bash` for commands, `sandbox_file_operations` to push the `agentkeys` binary.
- Manual gates are `read -p` prompts (LLM key, surprise confirm) + the OS Touch ID dialog (scope grant, if needed).

## 8. Open questions — all resolved (2026-05-28)

1. **MCP server location** — ✅ **in the sandbox** (localhost:8088 → real broker); simplest for the agent hooks.
2. **agentkeys binary into the sandbox** — ✅ **via the sandbox's own MCP file ops** (`sandbox_file_operations` / `POST :8080/v1/file/write`), then `chmod +x`. No scp.
3. **Namespace enforcement** — ✅ **accepted for the demo narrative**; the real gap (M1 enforces per-actor isolation, not per-namespace) is logged on **issue #108** for the durable fix. Act 1 demonstrates per-actor isolation; namespace is wire-level.
4. **Chain** — ✅ **heima mainnet** (operator has funds). No gas-free alternative; Act 3 revocation is out of scope, so the only mainnet writes are the one-time scope grant (0.5, reused account usually already has it) + agent funding (0.4). One-line operator guide added to the project `CLAUDE.md`.
