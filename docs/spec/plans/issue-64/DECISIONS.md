# Stage 7 — Issue #64 — Decisions Log

## Process decisions (locked)
- **D1 — Plan home:** `docs/spec/plans/issue-64/PLAN.md` (mirror of `~/.claude/plans/now-i-just-merged-idempotent-plum.md`). Updates in this file overlay the master plan.
- **D2 — Branch independence:** Work on `claude/dazzling-mirzakhani-2a06bc` only. No `jj rebase` / no `git merge` from sibling branch `claude/quizzical-ellis-d6f1e9`. Verbatim artifact harvesting allowed only after rewrite per user rules in plan §1.
- **D3 — Reviewer:** codex (per `--critic=codex`). Each phase ends with at least one codex round; stop rule = 2 consecutive rounds of same-severity P2 → ship.
- **D4 — Per-story commit:** `git commit` inside the worktree, one commit per US-* story. Format: `agentkeys: stage 7 issue#64 phase <N> -- US-NNN <deliverable>`.
- **D5 — VCS tool exception:** This worktree is a git worktree at `.claude/worktrees/dazzling-mirzakhani-2a06bc/`, not a jj workspace. Global CLAUDE.md says "use jj for all version control," but jj's working copy is the main repo at `/Users/agent-jojo/Projects/agentKeys/` — it cannot see edits inside this worktree. Pragmatic exception: use `git` for commits inside the worktree. After PR merges to `main`, jj on the main repo will see them via `jj git fetch`.

## Architectural decisions (locked from plan defaults)
- **A1 — Wallet-sig wire format:** SIWE (EIP-4361) wrapping EIP-191. Closes codex P0 #2.
- **A2 — Per-call daemon signature on mint:** Required. Closes codex P0 #5.
- **A3 — EmailLink first form:** magic-link with fragment-token + POST verify + CLI polling.
- **A4 — Backwards compat:** `POST /v1/auth/exchange` shim (legacy bearer → session JWT once at startup). No dual-accept on `/v1/mint-aws-creds`.
- **A5 — OAuth2 v0 provider:** Google only.
- **A6 — OAuth2 multi-tenant:** Single-tenant for v0 (broker holds Google client credentials).
- **B1 — Recovery threat model:** Master-gated via new capability grant. Email-only rebinding rejected (codex P0 #4).
- **B2 — Capability grants:** First-class endpoints + audit_proof signature.
- **C1 — Audit policy:** `dual_strict` default.
- **C2 — Gas-drain mitigations:** All four (per-identity rate, daily budget, min-balance, pre-tx check).
- **C3 — Speculative STS:** Allow, gate response on audit-write success.
- **C4 — Testnet target:** Base Sepolia.
- **D1 — Refuse-to-boot tiering:** Tier-1 config-only sync + Tier-2 boot-to-Unready async.
- **D2 — SES cache:** persisted 24h TTL.
- **D3 — /readyz JSON:** per-check status + reason + docs URL.
- **E1 — Phase ordering:** 0 → A.1 → A.2 → C.0 → B → C → D-rest → E.
- **E2 — Codex stop rule:** 2 consecutive same-severity P2 rounds, with independent prompts and explicit user sign-off on residual P2s.
- **E3 — Production-ready definition:** single-operator EC2 + runbook + 30-min restore drill from SQLite snapshot.

## Open meta-questions (carried into next iteration)
- **M1 — Primary v0 testnet consumer:** Both agents and human devs (current default).
- **M2 — Recovery hard gate:** Yes (Phase B.2 ships in v0).
- **M3 — End-to-end measure:** Operator deploy success (current default).

Per-phase decisions appended below as work proceeds.

---

## Session 1 — 2026-05-05 — Phase 0 commit log

| Story | Commit | Files | Tests | Status |
|---|---|---|---|---|
| US-001 env.rs | `32d3dd3` | env.rs (new) + lib.rs + config.rs refactor + plan home | 5/5 | PASS |
| US-002 plugin traits | `d6e5bba` | plugins/{mod,auth,wallet,audit}.rs + Cargo.toml features | 8/8 | PASS |
| US-004 + US-008 OmniAccount + SqliteAnchor | `80c01f6` | identity/, plugins/audit/{mod,sqlite}.rs + 4 cross-crate match-arm fixes | 9 + 8 | PASS |
| US-005 dual keypair purpose | `130f684` | jwt/{mod,session,issue,verify}.rs + oidc.rs purpose field | 10/10 | PASS |
| US-007 ClientSideKeystore | `61a737b` | storage/wallets.rs + plugins/wallet/{mod,keystore}.rs | 9/9 | PASS |
| US-006 SiweWalletAuth | `51a5191` | storage/auth_nonces.rs + plugins/auth/{mod ⟵ ex auth.rs, wallet_sig}.rs + Cargo k256+sha3 | 11+7 | PASS |
| US-003 tiered refuse-to-boot | `171d141` | boot.rs (new) + state.rs (extended AppState) + main.rs (rewritten) + lib.rs + tests fixtures updated | 4 + 9+6 | PASS |
| US-012 broker_status /readyz | `7bbe20d` | handlers/broker_status.rs (new) + handlers/mod.rs + lib.rs route + tests/mint_flow.rs readyz updated | 9 readyz | PASS |

Total: 9 of 16 Phase 0 stories complete. ~94 tests passing across lib + integration. Workspace build green. /readyz aggregator now lives — every plug-in's `ready()` + 4 Tier-2 atomics surface in a single structured JSON response with per-check runbook anchor URLs.

## Session 2 commit log (Phase 0 close-out, 2026-05-05)

| Story | Commit | Tests | Status |
|---|---|---|---|
| US-011 mint upgrade (session JWT + per-call sig + AuditAnchor gate) | `1edb4f6` | 10 unit + 5 v2 + 9 legacy | PASS |
| US-013 tests/invariant_load_bearing.rs (6 cases a-f) | `8657d74` | 7/7 | PASS |
| US-016 Phase 0 codex review round 1 + round 2 | (this commit) | 0 P0, 0 P1, 14 P2, 6 P3 across both rounds | PASS — stop rule fired |

Phase 0 totals after Session 2: **16 of 16 stories complete**. Round 1 + round 2 found only P2/P3; plan rule 9 stop rule fires; Phase 0 ships with P2/P3 rolled to V0.1-FOLLOWUPS.md.

## Phase 0 ship verdict

**SHIP.** Round 1 (`codex-round1.md`) + round 2 (`codex-round2.md`) both find zero P0/P1; the 20 total findings are P2/P3 and rolled to `V0.1-FOLLOWUPS.md` for Phases A.1, A.2, B, C, D-rest, E to consume in priority order.
