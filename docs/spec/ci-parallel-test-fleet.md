# Parallel CI test fleet — multi-broker architecture (issue #265)

**Status:** phase 2 shipped (slot parameterization + slot 2 live, PR #277); phases 1, 3–6 designed below, not yet landed.
**Scope:** the design for running N concurrent, fully isolated CI test environments ("multi-thread CI") — one EC2 broker stack per slot — so harness pipelines stop serializing globally. Covers what is shared vs replicated, why the chain layer is shared, slot identity + lifecycle, and the per-phase delivery plan.
**Audience:** developers + CI maintainers. The operator-facing bring-up (naming matrix, add-a-slot checklist, live inventory) is [`cloud-bootstrap.md` §0.3](../cloud-bootstrap.md#03-test-broker-fleet--multiple-test-brokers-issue-265); current single-slot CI activation is [`ci-setup.md`](../ci-setup.md).

## 1. Problem

All harness CI runs share one test environment. Two consequences, both hit live:

1. **Correctness (fixed by #262):** concurrent runs share ONE test EC2 — any run's deploy step re-converges systemd and restarts every worker under another run's in-flight harness → nginx 502 "worker unreachable" mid-run. On 2026-06-10 this produced five false-red runs in one hour.
2. **Throughput (the cost of that fix):** #262 serialized deploy+harness in one global concurrency group (`heima-test-deployer-nonce`), so every harness run now queues globally (~6–12 min each).

The fleet restores throughput: **N parallel slots, each a complete test stack on its own EC2**, with per-slot identities everywhere contention or blast radius exists.

## 2. Topology — shared vs per-slot

| Layer | Shared (one per account/fleet) | Per-slot (replicated ×N) |
|---|---|---|
| Compute | — | EC2 instance + EIP (tag `agentkeys-broker-eip-test[-N]`), full stack: broker, signer, 6 workers, bundler, nginx + certs |
| DNS | parent zone | 9 A records (`broker-test-N.${ZONE}`, `signer/audit/email/cred/memory/config/classify/mcp-test-N.${ZONE}`) |
| OIDC | — | issuer URL + IAM OIDC provider (byte-distinct per slot) |
| IAM | GH-Actions deploy role `github-actions-agentkeys-deploy` (SendCommand scope covers the whole fleet) | daemon + SSH users, data role, per-data-class roles, SSM instance profile (`agentkeys-test-broker-ssm[-N]` — never shared across machines) |
| S3 | — | all four buckets per slot (mail/vault/memory/config — decision (a): per-slot buckets, zero cross-slot blast radius) |
| SES | rule set name `agentkeys` (rules are per-slot) | domain identity `bots-test-N.${ZONE}`, sender, receipt rule |
| Chain | **contract set** (Registry/Scope/K3/Audit + the test EntryPoint/factory) — §3 | deployer wallet (`TEST_DEPLOYER_KEY_N`) → distinct operator/actor omnis, master P256Account, EntryPoint deposits + nonces |
| CI | workflow definition | concurrency group `heima-test-slot-N` (phase 4), env materialization, deploy target |

Slot naming: slot 1 keeps the grandfathered plain `-test` names (its OIDC issuer `test-broker.${ZONE}` is byte-frozen against the registered IAM provider); slots ≥ 2 use a uniform `-test-N` suffix. Full identifier matrix: [`cloud-bootstrap.md` §0.3](../cloud-bootstrap.md#03-test-broker-fleet--multiple-test-brokers-issue-265).

## 3. Why the chain contract set is SHARED across slots

On this contract set, **the unit of isolation is the key, not the contract address** — and the failures the fleet exists to fix were never contract-state collisions.

**Every mutable cell in the set is already namespaced by omni/account.** SidecarRegistry bindings are keyed by (operator_omni, actor_omni, key_hash); AgentKeysScope by (operator, actor); K3EpochCounter per omni; CredentialAudit rows per omni; EntryPoint deposits and nonces per account address. Two slots with different deployer keys derive completely disjoint omni/account keyspaces, so slot 1 and slot 2 cannot read or write each other's rows — the same mechanism that keeps two *prod tenants* apart. A second contract set would add address-level separation on top of key-level separation that is already total: zero marginal isolation.

**What actually broke CI was contention, not state.** The 2026-06-10 false-red storm was concurrent runs restarting systemd units on one shared EC2; the other recurring flake was deployer-EOA nonce races. Both live *off* the contracts — and both are exactly what the fleet replicates per slot (own machine, own deployer key). The contract set never appeared in any incident.

**Sharing also buys real things:**

- **Fidelity to prod.** Prod is one contract set with many tenants. The four-layer isolation invariants (cross-actor negatives, CLAUDE.md issue #90 table) are *more* meaningful when another slot's state coexists in the same registry — a scope check that accidentally matched another operator's row would actually fire in CI. Per-slot sets would test a topology prod doesn't have and hide that bug class.
- **One registry to govern.** Harness CI runs on Heima *mainnet* (real gas). N sets would mean N× deploy gas on every `crates/agentkeys-chain/VERSION` bump, N cutover ceremonies per contract change (the #225 account-auth cutover would have been prod + N instead of prod + 1), and N× the surface for the #225 split-registry incident class (a broker compiled against one registry while a client onboards into another).

**The deliberate asymmetry:** the test fleet *does* have its own EntryPoint + factory, separate from prod's (#250). That isolation protects *prod* — a mis-pointed test bundler or a test-tier compromise must never be able to touch prod's EntryPoint deposits. Between two same-tier, equally disposable test slots, that blast-radius argument has no force.

**No per-slot paymaster either.** The whole test fleet intentionally runs unsponsored (#230): `PAYMASTER_ADDRESS_HEIMA=` is empty on every slot, broker + bundler boot degraded, `/v1/accept/*` answers 5xx actionably. Harness master-gated txs are gas-paid by the slot's deployer EOA (the #250 master-model-aware path). A per-slot paymaster becomes relevant only if a slot ever needs to exercise the *sponsored web-accept* flow — out of scope on every slot today.

**Revisit conditions:** (a) a contract grows *global* (non-omni-keyed) mutable state that concurrent runs could contend on; (b) per-PR testing of *contract changes themselves* is wanted — which already has a better home than mainnet: the CI tier-1 ephemeral anvil stage spins a fully isolated chain per run. The shared mainnet test set's job is integration realism, not contract-change isolation.

## 4. Slot identity + lifecycle

- **Declared once, at first bootstrap.** A virgin machine has no state, so the operator declares its identity exactly once: `setup-broker-host.sh --ci --slot N --yes`. That run writes the identity into the broker unit (`BROKER_OIDC_ISSUER=https://broker-test-N.${ZONE}`).
- **Self-identified ever after.** Every re-run (flagless `--yes`, CI's `--test --yes` SSM deploy, `--ref main`) reads the deployed unit's issuer and adopts TEST mode + the slot from it. CI never needs to pass a slot to a deploy; a flag mistake cannot re-render a slot-2 box with slot-1 hostnames.
- **Cross-wiring is a hard error.** An explicit `--slot` that contradicts the deployed identity aborts ("refusing to cross-wire two slots on one machine"); re-purposing a box is a deliberate teardown (remove the unit + `/etc/agentkeys`) followed by a fresh bootstrap.
- Laptop-side selection everywhere else (`setup-cloud.sh`, `dns-upsert-workers.sh`, `setup-heima.sh` via `--env-file`, `ssh-broker.sh test-N`): `--ci --slot N` / `AGENTKEYS_TEST_SLOT=N` / auto-detect from a `*test-N*` env-file path.

## 5. Delivery phases

| Phase | Content | Status |
|---|---|---|
| 1 | **CI-built artifacts** — stop cargo-building on the broker host; `rust-checks` uploads binaries, the SSM deploy downloads into `/opt/agentkeys/releases/<sha>/` + flips a symlink. Deploys ~6 min → <1 min, near-atomic. Standalone win even pre-fleet. | not started |
| 2 | **Slot parameterization + slot 2** — `--ci --slot N` across the entry points, slot env files, fleet-aware `provision-ci-deploy-role.sh`, per-slot SSM profiles, host self-identification, slot 2 fully stood up + verified (broker/worker healthz, OIDC provider, per-class roles/buckets, idempotent re-runs). | **landed — PR #277** |
| 3 | **Per-slot chain identity** — mint the slot deployer key (local file + `TEST_DEPLOYER_KEY_N` GH secret), fund from the operator deploy wallet, then `AGENTKEYS_ALLOW_STAGE1_STUBS=1 AGENTKEYS_CHAIN=heima HEIMA_DEPLOYER_KEY_FILE=~/.agentkeys/heima-deployer-test-N.key bash scripts/setup-heima.sh --ci --env-file scripts/operator-workstation.test-N.env` (skips all contract deploys — shared set §3; runs the per-identity ceremonies: fund, #164 software master register via the #252 deterministic passkey, **stub K11 enroll — the `ALLOW_STAGE1_STUBS` opt-in is REQUIRED on mainnet per arch.md §22b.1 / chain-setup.md's chain-policy table**, scopes, smoke), pin `HEIMA_DEPLOYER_ADDR_HEIMA` in the slot env, extend `check-wallet-balances.sh` to N wallets. The slot-2 bring-up shook out the [`ci-setup.md` troubleshooting table](../ci-setup.md#troubleshooting--traps-the-slot-2-phase-3-bring-up-hit) (stale CLI, session-omni drift, mainnet stub opt-in, software-register-vs-hardware-exec signer consistency). | **landed — slot 2** (master+agent+audit+smoke green, `TEST_DEPLOYER_KEY_2` set; `check-wallet-balances.sh` extension + per-slot scope grant deferred) |
| 4 | **CI orchestration** — slot assignment `slot = PR# % N` (stateless); per-slot concurrency `heima-test-slot-${N}` on deploy+harness (the #262 semantics, sharded: same-slot runs serialize, different slots run fully parallel); per-slot secrets selection (`TEST_DEPLOYER_KEY_N`, per-slot instance id — the deploy role already covers the fleet, no IAM change); slot-aware env materializer (derives `-test-N` hostnames/buckets/roles from the slot). Upgrade path if static packing queues: first-free-slot lease via S3 conditional PUT (run-id + TTL = job timeout, released in `if: always()`). | deferred |
| 5 | **Cross-slot isolation tests + docs** — harness negatives: slot-1 STS creds → slot-2 bucket/prefix = AccessDenied; slot-1 instance role cannot assume slot-2 roles; both directions. Mirrors the four-layer per-actor invariants at the machine layer. | deferred |
| 6 | **Cost controls** — scheduled stop/start for idle slot EC2s (slots 2..N stopped outside working hours; deploy step starts-if-stopped, idempotent). | deferred |

## 6. Acceptance (from #265)

- Three PRs' harness pipelines run concurrently end-to-end green with zero worker-unreachable flaps.
- Deliberate same-slot overlap: the second run queues on the slot group, never trampled.
- Cross-slot negative tests pass (S3 + IAM assume, both directions).
- Each test EC2 has its own instance profile/role set; no role attached to more than one machine. *(holds today: `agentkeys-test-broker-ssm` / `-2`)*
- Docs + the three idempotent entry points own all new mutations; `--ci --slot N` re-runs converge cleanly. *(verified for slot 2: full `setup-cloud.sh --ci --slot 2 --yes` re-run is all ok/skip)*

## 7. References

- Issue [#265](https://github.com/litentry/agentKeys/issues/265) (this design), [#262](https://github.com/litentry/agentKeys/issues/262) (global serialization — the correctness fix this shards)
- PR [#277](https://github.com/litentry/agentKeys/pull/277) (phase 2 + slot-2 bring-up)
- [`cloud-bootstrap.md` §0.3](../cloud-bootstrap.md#03-test-broker-fleet--multiple-test-brokers-issue-265) — operator bring-up: naming matrix, add-a-slot checklist, live fleet inventory
- [`ci-setup.md`](../ci-setup.md) — current (single-slot) CI activation; phase 4 updates it
- CLAUDE.md — flag convention (`--ci [--slot N]`), EIP-by-tag rule, idempotent remote-setup rule, per-actor isolation invariants (#90)
