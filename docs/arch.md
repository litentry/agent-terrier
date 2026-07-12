# AgentKeys — Architecture v3

**Audience:** anyone who needs to reason about AgentKeys end-to-end — new contributors, security reviewers, ops, design partners.

**Status:** canonical v3 (compacted 2026-07-08). v3 is a **compaction + re-index** of v2, not a redesign: every section keeps its v2 number, states the load-bearing facts, and links outward for depth. The **frozen full-detail v2 text** is [`archived/arch_V2.md`](archived/arch_V2.md) — cited per-section below as "*full detail: v2 §N*". The **forward design direction** — decoupling agents from devices via **channels** — is [`spec/agent-channel-decoupling.md`](spec/agent-channel-decoupling.md), summarized in [§22e](#22e-channels--agent--device-decoupling-design). v2's own supersession note (it replaced the pre-v2 mock-server architecture) still holds.

**Companion docs** (canonical for their narrow surface — link, never duplicate):
[`spec/signer-protocol.md`](spec/signer-protocol.md) · [`spec/threat-model-key-custody.md`](spec/threat-model-key-custody.md) · [`spec/credential-backend-interface.md`](spec/credential-backend-interface.md) · [`spec/agent-background-job-harness.md`](spec/agent-background-job-harness.md) · `plan/v2-issues/` (stage deliverable inventories, operator-internal).

---

## 1. System overview

Five independent trust boundaries, five independent products (diagram: [`assets/component-architecture.svg`](assets/component-architecture.svg); mermaid original: v2 §1):

| Service | Holds | Role |
|---|---|---|
| **Broker** (`broker.<zone>`) | K1 (cap co-sign + session JWTs), K2 (OIDC JWTs) | Mints cap-tokens after on-chain scope/registry/epoch verification; mints OIDC JWTs for STS; relays master UserOps; **stateless** — never holds K3, no AWS principals, never writes chain |
| **Signer** (TEE) | K3_v[1..current] sealed in enclave | KEK derivation, STS minting, K10/K11 verification helpers; attested mTLS |
| **Workers** (per data class) | Nothing at rest; per-invocation STS | Per-data-class ops; independently re-verify every cap against the chain before touching S3/SES/rails |
| **Daemon** (sidecar, localhost) | K10 (+ K11 on master); TTL-bounded plaintext cache | Caller auth, cap-mint on the caller's behalf, credential injection, host-local policy |
| **Chain** | ScopeContract, SidecarRegistry, K3EpochCounter, CredentialAudit | Single source of truth for bindings, scopes, epoch, audit anchors |

**Headline guarantee:** every cap-bearing request is independently re-verified against the chain by the worker before any S3/KEK/STS/payment operation. Caps carry a **K10 proof-of-possession** the worker verifies independently of the broker (#76; enforcement staged via `AGENTKEYS_WORKER_REQUIRE_CAP_POP=1`, §22b.4) — once flipped, broker-only compromise cannot mint a usable cap. Compromise of any single boundary yields bounded damage (§3), never a system-wide takeover.

**Deployed stacks:** the same five-boundary unit set replicates per environment — Heima prod (consumer free tier, default), Base prod (`-base`, partner tier, own EC2), CI/test fleet (`-test`, `-test-N`, #265), and the Volcano Engine mirror (Heima-VE, #373). A stack is a **(chain, cloud/broker) pair** (§17). Naming matrix: the internal cloud-bootstrap runbook §0.2–0.4.

## 2. Component inventory

Visual map: [`assets/component-architecture.svg`](assets/component-architecture.svg) — trust zones + the four edge classes (network / mTLS / shared wire types via `agentkeys-protocol` (#203) / in-process). Keep it in sync with this table.

| Component | Runs | Job |
|---|---|---|
| `agentkeys` CLI | master workstation | init, agent mgmt, scope, recovery, whoami, signer debug |
| `agentkeys-daemon` (master / agent) | workstation / sandbox | K10 (+K11 master); localhost sidecar proxy; cap-mint |
| Broker | broker EC2 | cap-mint authority; chain reads; SSE drop events; UserOp relay |
| Bundler | broker host loopback | thin in-house ERC-4337 v0.7 `handleOps` submitter (#230) |
| Signer | TEE | K3 vault; KEK/STS/verification (§14) |
| Workers: creds / memory / config / audit / email / payment / classify | Lambda or axum microservice | per-data-class ops (§15); classify = compute-only gate (#207) |
| `agentkeys-gate` | operator host | metered key-custody LLM-egress relay (#384) — custody + metering, never control |
| Chain | Heima (default) / Base / any EVM | the four contracts (§16) |
| Provisioner + TS scrapers | sandbox subprocess | per-service API-key signup/mint (Class B) |
| `agentkeys-mcp-server` | next to any LLM host | MCP tools over stdio/HTTP/WS; backend = `agentkeys-backend-client` |
| `agentkeys-protocol` / `agentkeys-backend-client` | shared crates | ONE owner of wire types (wasm-safe) / native client (#203/#215) |
| Front-ends: `apps/parent-control`, web-core (wasm) | browser | master surfaces; generated types via ts-rs |
| Firmware `esp32s3-touch-lcd-4b` | device | keyed machine: on-device K10 keygen + signing (#348/#367) |

*Full detail: v2 §2.*

## 3. Trust boundaries (where keys live, who can see them)

Compromise-blast-radius (the design's core security statement; diagram + long form: v2 §3):

| Boundary breached | Gains | CANNOT |
|---|---|---|
| Master workstation (no biometric) | stolen J1 (TTL replay) + K10 (cap-mint as that actor until rotation) | complete WebAuthn — K11 is hardware-sealed; no scope/device mutations (hardware-registered masters; software-passkey caveat §22b.1) |
| Master workstation (with biometric) | + scope/device mutations, bounded to this human's actor tree, chain-visible | reach other operators; recovery (§11) revokes in ~60 s |
| Agent machine (sandbox root) | that agent's K10 + J1 (TTL) | impersonate siblings (per-actor binding); mutate scope; reach master or sibling prefixes (PrincipalTag) |
| Broker process | mint J1s; co-sign caps | forge the K10 PoP (§22b.4); derive K4/KEK (no K3); reach AWS; write chain |
| Signer TEE (attestation defeated) | derive any K4/KEK — catastrophic for credentials | mint caps/JWTs (no K1); bypass on-chain binding; reach S3 |
| One worker | that one data class, for callers with valid caps | forge caps; reach other classes (separate workers/roles/buckets §17) |
| AWS account | this deployment's data plane | chain-anchored boundaries; audit anchoring is independent |
| One chain validator | standard ≤-honest-majority properties | bypass worker re-verification |

## 4. Key inventory

| # | Key | Lives in | Role |
|---|---|---|---|
| K1 | broker session+cap ES256 keypair | broker file (0600); pubkey at `/.well-known/jwks.json` | signs session JWTs; co-signs caps |
| K2 | broker OIDC ES256 keypair | broker file (0600); jwks | signs OIDC JWTs for `AssumeRoleWithWebIdentity` |
| K3 | signer master secret (32 B / epoch) | sealed in TEE; historical epochs retained | HKDF input for K4 + KEK; rotates via `K3EpochCounter` (§21) |
| K4 | per-actor derived wallet (secp256k1) | signer memory, derived on demand, never persisted | the managed EVM wallet per HDKD node |
| K5 | operator-held EVM wallet | operator's MetaMask/HW | `identity_type = evm` SIWE; bypasses K3/K4 |
| K6 | session JWT (J1) | OS keychain / daemon memory | bearer for `/v1/cap/*` etc.; TTL default 5 h |
| K7 | OIDC JWT | transient | web-identity token for STS; TTL default 300 s |
| K8 | STS temp credentials | transient | direct cloud access scoped by PrincipalTag `agentkeys_actor_omni` |
| K9 | DKIM keypair | email worker (TEE/KMS pattern) | outbound-mail signing per domain |
| K10 | device key (secp256k1) | per **machine**: master OS keychain; agent/sandbox keychain-or-file; **device flash/NVS** (firmware) | per-request signature on cap-mints; registered on chain. **Machine→actor binding — never an agent↔device bond** (§10.2, §22e) |
| K11 | WebAuthn platform credential (P-256) | **master only**, Secure Enclave/TPM/StrongBox | hardware user-presence on master mutations; not per-request |

Key relationship map (derivations + rationale): [`assets/key-map.svg`](assets/key-map.svg); worked example + mermaid: v2 §4.1. Identity flows into the anchors exactly once: the identity omni seeds the initial wallet derivation and is discarded; everything else keys off `actor_omni`.

## 5. Canonical names (one concept, one canonical spelling)

Pinned to disambiguate the same value showing up under different labels across components. **Use the canonical column** in every new doc, runbook, CLI output, and commit message; per `AGENTS.md` → "Terminology-source-of-truth rule", if you introduce a name not in this table, either add the alias row here or rename the call site in the same change.

> **Deployed addresses** for every contract named here live in the chain profile [`crates/agentkeys-core/chain-profiles/heima.json`](../crates/agentkeys-core/chain-profiles/heima.json) (`.contracts[]` + `contract_set_version`) — the machine source of truth (#251), mirrored to `scripts/operator-workstation.env`. The human registry is [`spec/deployed-contracts.md`](spec/deployed-contracts.md). Docs **anchor** to those sources, never copy (CI: `check-deployed-contracts-sync.sh`). Operator wallet/contract/funding map: the internal chain-setup runbook (`operator-docs/chain-setup.md`, not in the OSS mirror).

| Canonical name | Identity | Aliases seen in the codebase / docs |
|---|---|---|
| `actor_omni` | **The durable per-actor cryptographic anchor.** `SHA256("agentkeys" \|\| "evm" \|\| initial_master_wallet_K3_v1)`. Frozen at the first managed-wallet attestation; never rotates. The Layer 1 identifier (§6). | `omni_account` (JWT + whoami), `agentkeys_actor_omni` (PrincipalTag), `OMNI_A/B` (demo vars) |
| `managed-wallet attestation` | **The proof the operator controls the derived managed wallet (K4)** — signer-performed EIP-191/SIWE over the broker's challenge → long-lived J1; `actor_omni` freezes here. Distinct from the K5 `evm`-identity path (operator signs SIWE directly). | "activate your managed wallet"; `SIWE → J1`, "wallet attestation" |
| `current_master_wallet` | **The current chain identity** = `HKDF(K3_v[epoch], O_master)`; rotates per K3 epoch; `msg.sender` in sovereign mode. Layer 2 (§6). | `master_wallet`, `wallet_address`, `MASTER_WALLET`; qualify `master_wallet_K3_v[N]` for历史 epochs |
| `identity_omni` | **Transient identity omni** — `SHA256("agentkeys" \|\| id_type \|\| id_value)`; broker-internal between init and attestation; never in a post-attestation JWT. | `identity_omni_email`, "identity omni" |
| `agent_omni` | **A child actor omni** = `SHA256("agentkeys-hdkd-v1" \|\| O_master \|\| "//<label>")` (#144). **Public + recomputable**; unforgeability = the master-gated claim + master-submitted binding. | `O_master//agent-A`, `O_agent_A` |
| `operator` / `master` | **The owner control identity** (#295/#339): owns canonical creds+memory+inbox, authorizes every grant (K11), **global visibility over all data, channels, contacts, and audit — surfaced only in parent-control**; never proxies, never hosts an app. | `master`, `operator_omni`, `O_master`, `operatorMasterWallet` |
| `delegate` | **A scoped app-serving identity** = `(actor_omni + K10) ⊗ exactly one application`; **sandbox-resident** (the sandbox's own K10 is its identity root — [`spec/agent-channel-decoupling.md`](spec/agent-channel-decoupling.md)); pulls granted context, pushes proposals back. **Code + on-chain selectors keep `agent`** (rename = deferred major-version cutover). | `agent`, `agent_omni`, `registerAgentDevice`, `SidecarRegistry` (frozen) |
| `AI runtime` | **The external AI application** a delegate equips — never our identity. Canonical is **AI runtime**, not bare "runtime". | Claude Code, Hermes, xiaozhi; avoid bare "agent"/"runtime" |
| `context system` | **The general agent-context substrate** — one curation-gated lifecycle (delegate working copy → inbox push → master curates → canonical → distribute, §17.6) carrying typed context: `knowledge`, `skills`, `persona`, `resources`. Gate strictness + runtime application vary per type, never the machinery. Wire spellings frozen: `DataClass::Memory`, `memory:<ns>` / `inbox:<ns>`. | "memory system", "shared memory" (pre-#390) |
| `context flows` | **The two sanctioned master↔delegate context conduits** (§17.6): distribution (delegate reads canonical) + absorption (delegate proposes to the inbox). Canonical prose grant names: **`context-sub:<ns>`** (read canonical) / **`context-pub:<ns>`** (propose) — the D11 pub/sub direction vocabulary shared with channels. **Wire ids stay frozen: `memory:<ns>` / `inbox:<ns>`** (rename rides the major-version cutover). | **"the two channels"** (pre-2026-07 name — retired so `channel` names the [§22e](#22e-channels--agent--device-decoupling-design) concept), `memory:<ns>` / `inbox:<ns>` (wire, frozen) |
| `policy` (data class) | **The control-plane data class** (#201): NL policy, taxonomy, compiled grants — access-control on the access-control; master-only, never agent-loadable. Code/infra spellings frozen: `DataClass::Config`, `agentkeys-worker-config`, `$CONFIG_BUCKET`, `/v1/cap/config-{store,fetch}`. | `config` / `Config` (frozen) |
| `gateway` | **The capability boundary between externally-authenticated humans and agents** (#407, §22e phase 2 / D4): custodies the ONE scarce transport credential (a WeChat bot, #384 pattern — never in any agent env), authenticates each `contact` by transport identity (the weixin sender id — openid under the `oa` driver, ilink user id under `ilink`; spec §7), enforces L3 BEFORE anything reaches an agent, and routes (`/alias` deterministic; the advisory router is phase 5). **A PEP, never an authority** — grants stay master-signed + chain-verified. Code: `agentkeys-worker-channel-weixin`. | WeChat gateway |
| `contact` | **An externally-authenticated, KEYLESS principal** (#407, §22e phase 2 / D5): the transport authenticates the family member (openid); the master maps + tiers them (household template `owner/partner/elder/kid/helper/guest`, model-proposed + master-confirmed, D10). NEVER an actor — no omni, no keys, no caps; **zero feed-history visibility** (D13). Stored in the master-authored `policy`-class contact registry. | family member, household member |
| `channel` (data class) | **The pub/sub feed data class** (#406, §22e phase 1): durable, envelope-encrypted feed events at `bots/<actor>/channel/<id>/<event>.enc`; the channel worker is the only write path and serves the §14.12 NRT worker-held long-poll. Per-direction grants `channel-pub:<id>` / `channel-sub:<id>` (distinct on-chain service-ids — granting one never grants the other). Code/infra spellings: `DataClass::Channel`, `agentkeys-worker-channel`, `$CHANNEL_BUCKET`, `/v1/cap/channel-{pub,sub}`, `/v1/channel/{publish,poll,teardown}`. | `channel` / `Channel` |
| `agentkeys-pair://claim` | **The §10.2 pairing deep-link** shown as QR: `agentkeys-pair://claim?code=<pairing_code>&broker=<broker_url>`. | pairing deep-link, claim URL |
| `K3` | The 32 bytes inside the signer enclave; per-epoch. | `K3_v[N]`, `master_secret` (discouraged) |
| `session JWT` (= K6) | The bearer at `~/.agentkeys/<id>/session.json` / keychain; K1-signed; master plane persists coords for restart-resume (#220). | `session_jwt`, `J1`, `master-session.json` |
| `OIDC JWT` (= K7) | Per-mint short JWT (K2-signed) for `AssumeRoleWithWebIdentity`; carries `agentkeys_actor_omni`. | `oidc_jwt`, `JWT_A/B` |
| `cap-token` | The broker-issued bearer authorizing ONE operation; K10 sig + optional K11 assertion + K1 co-sig (§19). | `cap`, `capability_token`, `op_cap` |
| `credential_kek` | 32-byte AES key per operator: `HKDF-SHA256(salt="agentkeys.kek-salt.v2", ikm=K3_v[epoch], info="agentkeys.user.v1" \|\| actor_omni)`. | `KEK`, `cred_kek` |
| `credential_envelope` | Wire format of one stored credential (`0x04 \|\| epoch \|\| nonce \|\| ct \|\| tag`, §18) at `s3://$VAULT_BUCKET/bots/<operator>/credentials/<service>.enc` — **single-vault, master-sovereign** (store = master-self only, hard-gated broker+worker; fetch = master-self or delegated #216/#286 under the on-chain `cred:<service>` grant). | `envelope`, `<service>.enc` |
| `vault/memory/config/channel/audit/email/payment_audit bucket` | One S3 bucket per data class (§17); per-actor prefix `bots/<actor_omni_hex>/` (config per-operator, master-only; channel per-actor feeds, #406). | `$VAULT_BUCKET` … |
| `AGENTKEYS_WORKER_<svc>_URL` | Canonical env family for worker base URLs (`AGENTKEYS_BROKER_URL` stays bare). | legacy bare `AGENTKEYS_MEMORY_URL` (retired; MCP fallback only) |
| `policy` / `scope` / `namespace` / `category` / `service` | **Distinct pipeline stages, NOT synonyms:** policy (NL intent, off-chain) → COMPILE → scope (on-chain `(operator, actor, serviceHash)` grant) over categories → service (the signed cap string; memory `service = memory:<ns>`). Full table: [`wiki/policy-scope-namespace.md`](wiki/policy-scope-namespace.md). | "tag" = classifier category (≠ AWS PrincipalTag) |

The most common confusion: **`actor_omni` ≠ `current_master_wallet`** — the first is the immutable anchor (L1), the second the rotation-volatile chain identity (L2). Everything keys off `actor_omni`.

**Channel family (spec §3 one-question-per-term definitions):** `channel` (data class) + `channel-pub:<id>` / `channel-sub:<id>` **PROMOTED at phase 1 (#406 — see the `channel` row above)**; `gateway` + `contact` **PROMOTED at phase 2 (#407)**; `device` (= channel endpoint) **PROMOTED at phase 3 (#408 — a paired box whose grants are ONLY `channel-pub/sub:<id>`, signs its own channel caps via `ak_device_cap_pop_sig`, hosts no runtime)**; `channel adapter` + `channel feed` **PROMOTED at phase 1** (the `agentkeys-worker-channel` IS the adapter + the durable feed, #406); `default delegate` is **DEFINED** (the onboarding auto-spawn that instantiates it is the veFaaS-live gate, #409). The channel-family names are now fully promoted ([`spec/agent-channel-decoupling.md`](spec/agent-channel-decoupling.md) §3).

## 6. Identity model — three layers + HDKD actor tree

**Layer 1 — cryptographic anchor (immutable):** `actor_omni = SHA256("agentkeys" || "evm" || initial_master_wallet_K3_v1)`, frozen at the managed-wallet attestation. Survives K3 rotation, wallet rotation, device changes. Keys **everything**: S3 paths, PrincipalTags, AAD, scope index, cap fields, KEK/K4 derivation.

**Layer 2 — current chain identity (rotatable):** `current_master_wallet = HKDF(K3_v[epoch], O_master)`; `msg.sender` in sovereign mode; rotates per K3 epoch.

**Layer 3 — operational uses:** each identifier where natural — L1 everywhere durable; L2 only as chain submitter + explorer trail. Full table: v2 §6.1.

**HDKD actor tree:** `O_master` roots; children `O_master//<label>` = `SHA256("agentkeys-hdkd-v1" || O_parent || "//" || label)` — **public + recomputable** (#144); what's secret is each node's **wallet** (K4, signer-derived), and only the master can *bind* a child (claim + master-submitted `registerAgentDevice`). Every node gets its own wallet + S3 prefix + PrincipalTag. Why per-agent omnis: compromise containment, first-class audit attribution, atomic revocation, tree-as-data-model. Diagram + worked hashes: v2 §6.2.

### 6.3 Identity ≠ actor ≠ machine ≠ capability

| Axis | Answers | Realized by |
|---|---|---|
| **Identity** | who is the human? | identity omni (email/OAuth/EVM/passkey) — transient |
| **Actor** | master, or which agent? | `actor_omni` — a HDKD node; **the unit every grant/cap/prefix/audit row keys on** |
| **Machine** | which box is signing right now? | K10 per machine (+K11 master); **a device, a sandbox, and a workstation are all machines** |
| **Capability** | what may this actor do? | on-chain `AgentKeysScope` + host-local policy; master-issued, revocable |

**Master vs agent are roles on the actor axis** — master: HDKD root, holds K11, spawns/authorizes; agent (delegate): `//label` child, K10-only, bootstraps only via master-claimed pairing. A **device** is likewise an actor whose grants are channel-only (§22e). One human → many actors; one actor → many machines; role = what grants the actor holds. Full tables: v2 §6.3; operator reference: [`wiki/agent-role-and-usage-hdkd-per-agent-omni.md`](wiki/agent-role-and-usage-hdkd-per-agent-omni.md).

## 7. Upstream backend classes — exercise vs distribution

**Exercise** (is this call authorized?) vs **distribution** (how does the credential reach only the right agent — always ours). Three classes, pinned per upstream: **A — per-request authorization** (AWS-native: STS + PrincipalTag IS the auth); **B — bearer-token** (OpenRouter/Anthropic/SaaS: provisioner-scraped key, vault-stored, sidecar-injected; provider-side caps are the enforcement point); **C — on-chain/payment (irreversible)**: strict one-shot CAS-burn caps + K11 above threshold. Full rationale + granularity matrix: v2 §7 + [`wiki/upstream-backend-classes-exercise-vs-distribution.md`](wiki/upstream-backend-classes-exercise-vs-distribution.md).

## 8. Mental model — four orthogonal axes

A cap-mint request is "this **identity**, bound to this **actor**, signed by this **machine**, requesting this **capability**" — each axis independently verifiable on chain (§6.3). Full table: v2 §8.

## 9. Cold-start (master device bootstrap)

Terminology guard: **WebAuthn** = the protocol; **K11** = the credential; **Touch ID** = the presence gate; the stage-1 **identity ceremony** (email/OAuth/SIWE) is NOT WebAuthn. The **software P-256 passkey** is a CI/headless stand-in with file-key custody — real crypto, weaker custody, fenced by run-mode + WARN until attestation verification lands (§22b.1).

| Stage | What |
|---|---|
| 0 | daemon generates K10 locally |
| 1 | identity ceremony (email link / OAuth / SIWE / passkey) → `binding_nonce` |
| 2 | WebAuthn binding — K11 created; challenge commits `SHA256(binding_nonce \|\| D_pub)` |
| 3 | wallet derive + **managed-wallet attestation** → long-lived J1; `actor_omni` **freezes** |
| 4 | on-chain register. **Canonical = the #164 ERC-4337 passkey-account path**: the master IS a `P256Account`; K11 signs the `userOpHash`. **#278 one-op collapse:** `/v1/register/{build,submit}` = ONE paymaster-sponsored UserOp (`initCode` + `executeBatch([registerFirstMasterDevice])`), one Touch ID, zero deployer txs in the user path. EOA register is a deprecated loud escape (`AGENTKEYS_REGISTER_MODE=eoa`). |

Sequence diagram + per-identity-type stage-1 table + the Q7 email-compromise defense + K11 intent rendering: v2 §9–§10.1; [`wiki/k11-webauthn-intent-rendering.md`](wiki/k11-webauthn-intent-rendering.md).

## 10. Per-actor binding ceremonies

### 10.1a Touch-ID-gated (sensitive) operations — the canonical list

**Rule: every mutation of master authority is a `P256Account` UserOp, and every such UserOp is K11/Touch-ID-gated** (the passkey signs the `userOpHash` = the complete intent). Register first/additional master · **bind an agent** (accept = ONE `executeBatch([registerAgentDevice, setScope])`, #225/#249) · **unbind** (`/v1/revoke/{build,submit}`; fleet-revoke before master reset, #260) · revoke master device (M-of-N) · recovery threshold · **grant/replace scope** (`/v1/scope/{build,submit}`, set-replace, #248) · add/remove passkey · guardian recovery · audit-root mint · typed-data sign. `resetMaster` is a deployer-gated dev escape (NOT Touch ID) pending guardian recovery. **Deliberately NOT per-op gated:** cap-mint + worker reads/writes — K11 is the *authority* boundary, not the *usage* boundary; lone exception: payments above `payment_k11_threshold`. Full status table: v2 §10.1a.

### 10.2 Agent bootstrap (agent-initiated pairing — single path)

One bootstrap path: the machine shows a one-time pairing code; an authenticated master claims it (#144 method A — the Matter/HomeKit model). Identifier data model: [`spec/agent-pairing-data-model.md`](spec/agent-pairing-data-model.md); key-custody + trust-chain diagram: [`assets/device-bind-sandbox-spawn-security.svg`](assets/device-bind-sandbox-spawn-security.svg).

1. **The agent machine generates K10 ON ITSELF** — daemon on a VM/sandbox; device-core in firmware flash/NVS (#367). The sandbox is ONE kind of agent machine, not the generation locus. `D_priv` persists, never leaves, never auto-regenerates.
2. Machine → broker `POST /v1/agent/pairing/request {D_pub, pop_sig}` (no bearer — PoP-gated; bad sig writes no row) → broker stores an **UNBOUND** request (names no master, TTL 600 s, supersedes prior open requests per device) → returns `{request_id (secret), pairing_code (display)}`.
3. Machine displays the QR (`agentkeys-pair://claim`); master scans + claims (`/v1/agent/pairing/claim`, J1-gated) → broker derives the child omni, binds the request, returns the device artifact inline for review.
4. Master approves with **ONE Touch ID**: `executeBatch([registerAgentDevice, setScope])` — install + permissions = one gesture (#225/#249); broker relays, never signs chain.
5. Machine polls (`/v1/agent/pairing/poll`, fresh pop_sig per attempt) → J1 minted **at retrieval** (no bearer at rest); scope live at inclusion → cap-mint works. Bound devices re-resolve J1 on every boot via `/v1/agent/resolve` (chain is the SoT).

**Trust chain:** master human → K11 → master J1 + master-submitted on-chain binding → machine K10 binding. The pairing request is Sybil-safe because it is unbound + inert until claimed. **The broker never writes chain** (#144). Under the channel plan (§22e) this same ceremony binds *devices* (claim attaches ≥1 channel grant, nothing spawns — the accept card carries `is_device` + the §14.10 broker warn, #408 shipped) and *delegate sandboxes* (headless in-band claim, no QR). Full 15-step listing: v2 §10.2.

### 10.3–10.7 Device lifecycle + the permission-grant framing

- **New master device** (§10.3.1): new K10'+K11' enrolled; cross-device confirmation requires a WebAuthn assertion from the EXISTING master (defeats email-compromise → takeover); `recovery_threshold` per operator.
- **K10 rotation** (§10.3.2): `agentkeys device rotate` — K11 signs `SHA256(old || new || nonce)`; broker drops caps bound to the old key.
- **Agent re-bootstrap** (§10.4): fresh sandbox → fresh K10 → re-pair under the same label/omni; multiple concurrent device keys per agent omni is the default. **No human re-presence needed** for ephemeral-sandbox re-pairs.
- **Where D_priv lives** (§10.5): OS keychain when available, else file (0600); hardened option: TPM/enclave passthrough. Ephemeral sandboxes re-pair per restart — the orchestrator holds long-lived authority, the sandbox only short-TTL bearers.
- **Trust shape** (§10.6): leaked K10 = cap-mint as that one actor until rotation; K11 required for anything structural.
- **Permission-grant ceremony** (§10.7): the mobile-OS analog — install (pairing) → first-launch prompt (accept card) → per-permission grant (`setScope`) → OS-enforced (non-LLM gate, §22d) → revoke in Settings. Per-category structured grants (`Scope.grants`) are a deferred additive extension; the scope recommender (presets + classifier + policy history) is **advisory** — only the master's K11 grants. Full mapping: v2 §10.7.

## 11. Recovery — M-of-N device quorum (no anchor wallet, no seed phrase)

Surviving master device signs revoke(+rotate) with K10 + a K11 biometric assertion; quorum = `recovery_threshold` (default 1; prompt to 2 at the third device). Chain emits `DeviceRevoked` → broker SSE → daemons zero caches; attacker locked out in ~2 min + cache TTL. No third-party recovery; all devices lost = tree lost (mitigate: device diversity, an offline recovery-only master). Timeline: v2 §11.

## 12. Sidecar daemon

The trust boundary between agent processes and the cap system: holds K10 (+K11 master), runs the localhost proxy (Unix socket `SO_PEERCRED` / pod-TCP / TEE-IPC), enforces host-local policy (per-caller service allowlists, method/path filters, spend quotas, per-call audit, **fail-closed on stale broker**), and keeps a 5-min in-memory credential cache (TTL + SSE-drop eviction). Cloud-enforced (`ScopeContract`) vs host-local (method/path/spend) is the authority split: a compromised sidecar can drive allowed services within cap TTL but cannot escape the actor's scoped set.

**Cap-mint flow:** agent → proxy → (cache miss) K10-signed mint at broker → broker verifies chain (scope, binding, epoch) → cap → worker re-verifies chain + decrypts via signer KEK → plaintext cached + injected. The agent process never sees the credential. **Master-self skip:** when `operator_omni == actor_omni` the scope check is skipped at BOTH broker and worker (the operator owns its own data; device binding still pins the actor — it can never open another prefix). Sequence diagram + policy tables + bootstrap env: v2 §12.

## 13. Broker

Mints session JWTs, OIDC JWTs (STS), and cap-tokens after on-chain verification (K10 sig, per-actor binding, service-in-scope, epoch); relays master UserOps to the bundler; pushes SSE drop events; hosts the auth ceremonies. It does **NOT** hold credentials/K3, derive wallets, decrypt, reach AWS, mutate scope, or write chain. **Stateless posture** (channel-plan §14.3): durable authority on-chain; policy/registry docs in encrypted S3/TOS; only TTL'd caches + transient pairing-rendezvous rows in memory.

Endpoint surface (details v2 §13.3): `/v1/auth/{email,oauth2,wallet,passkey,bind}` · `/v1/agent/pairing/{request,claim,poll}` + `pending-bindings{,/ack}` + `/v1/agent/resolve` · `/v1/wallet/*` · `/v1/cap/{cred-store,cred-fetch,memory-put,memory-get,memory-canonical-get,memory-append,config-store,config-fetch,channel-pub,channel-sub,audit-append,classify,email-*,payment}` · `/v1/cap/{canonical,inbox}-sts` (server-side A′ STS, issued to workers) · `/v1/{register,accept,scope,revoke}/{build,submit}` (sponsored UserOps) · `/v1/sse/operator/<omni>` · `/v1/mint-oidc-jwt` · `/.well-known/{jwks.json,openid-configuration}` · health/metrics.

## 14. Signer (TEE-protected K3 vault)

Holds K3 epochs sealed in an attested enclave (SEV-SNP / TDX / Nitro); derives K4 wallets + credential KEKs on demand; mints STS; verifies K10/K11 on behalf of workers; checks the on-chain epoch on every call. Typed RPC over attested mTLS, callers = broker + workers only: `/derive-address`, `/derive-cred-kek`, `/sts-credentials`, `/sign/{siwe,typed-data,audit-row}`, `/verify/{k10-sig,k11-assertion}` — wire shape pinned by [`spec/signer-protocol.md`](spec/signer-protocol.md). Rotation: new epochs generated in-enclave, historical retained for old blobs (§21). Attestation hash pinned by broker + workers; drift fails the handshake.

## 15. Workers (per-service)

One worker per data class — independent IAM, deploy lifecycle, blast radius. Common shape: accept cap + payload → verify K10 sig against chain (per-actor binding) → verify broker K1 co-sig → **independently re-verify scope on chain** → epoch check → execute → emit audit row. Runtimes: Lambda / axum / Cloudflare / Tencent SCF.

### 15.1 credentials-service

`fetch-cred` / `store-cred` / `teardown-actor` on `$VAULT_BUCKET`; KEK via signer mTLS; **single-vault, master-sovereign** (§5 `credential_envelope`): store = master-self only (hard-gated broker+worker); fetch = master-self or **delegated** (#216/#286) under the on-chain `cred:<service>` grant, S3 read under caller-relayed operator-tagged STS. OIDC federation: callers pass their STS via `X-Aws-*` headers so IAM PrincipalTag fires at AWS (with `AGENTKEYS_WORKER_REQUIRE_STS=1` header-less → 401).

### 15.2 memory-service

- **Namespace = signed service (#147):** memory `service = memory:<ns>` — a signed cap field, so the namespace is tamper-proof and authorized by the on-chain `isServiceInScope` gate; storage key, envelope AAD, and scope check all derive from it. Canonical prose direction names: `context-sub/pub:<ns>` (§5 `context flows`).
- **STS session policies** give the agent direct S3 for high-frequency ops within TTL; the worker is not in the LLM hot path.
- **Default-key discovery is off-chain** (#216): the `CredManifest` lists authorized service *names* + the master default (chain stores only hashes — it verifies, never enumerates); every fetch still re-verifies on-chain.
- **Engine seam (Position C):** the worker stays **store + gate only**; ranking/extraction rides the `MemoryEngine` adapter trait (`agentkeys-memory-engine`; OpenViking adapter `agentkeys-memory-openviking` shipped, opt-in); delivery via the `pre_llm_call` hook (#141), never a runtime memory-provider. Decision record: `research/memory-build-vs-gate-decision.md` (operator-internal); user explainer: [`wiki/memory-providers-and-agents.md`](wiki/memory-providers-and-agents.md).
- **Classifier-service — the write-side dual (#207/#322):** `agentkeys-worker-classify`, a **compute-only** gate (same cap+chain verify, no bucket/KEK): compiles NL intent → the structured policy attribute (catalog tier-0 deterministic; `engine:"llm"` = the deferred open-vocabulary tail — no model on the gate, ever). Daemon bridge: `/v1/master/classify/{tag,propose}` — propose writes no scope; only the K11 grant path does.
- **Channel-service — the pub/sub feed data class (#406, §22e):** `agentkeys-worker-channel`, same cap+chain verify as memory/config but with `DataClass::Channel`, its own `$CHANNEL_BUCKET`+role, and the **§14.12 NRT worker-held long-poll** (a held `/v1/channel/poll` is completed in-process the instant a `/v1/channel/publish` lands — the worker is the only write path; S3/TOS stays the durable record). Direction is the signed cap op (`channel_publish` ↛ `/poll`). The `session` `ChannelKind` (#408) is direct-transport, no feed.
- **WeChat gateway — the human-interaction PEP (#407, §22e):** `agentkeys-worker-channel-weixin`, a **per-transport gateway worker** (not a data-class worker) with **two weixin drivers behind one relay core** (`AGENTKEYS_WEIXIN_TRANSPORT`, spec §7 decision 2026-07-09): `ilink` — the Tencent iLink personal-bot long-poll (the openclaw-weixin wire protocol; the first-experiment path, `--login` QR ceremony, no public endpoint) — and `oa` — the 公众号 webhook (production/compliance). It custodies the ONE bot credential (#384 pattern; the iLink bot token or the OA app-secret), verifies transport authenticity (bearer session / callback signature), authenticates each `contact` by sender id, enforces L3 + the `/alias`/advisory router (#410 — structurally can-never-widen), stamps `GatewayRelay`/`ContactBind` audit rows, and exposes the operator-only D13-safe `GET /v1/gateway/contacts`. A PEP, never an authority.

### 15.3 audit-service

Three tiers: **A** hosted relay (Merkle-batched root, shared relay wallet; the #281 tier-A anchors ride ungated `appendV2`) · **B** self-hosted relay · **C** direct-write per event (sovereign default). Choice independent of the §20 mode.

### 15.3a Unified audit envelope — `AuditEnvelope v1`

Every audit-producing surface emits one canonical envelope; the chain + explorer consume it. Wire shape (deterministic CBOR; `envelope_hash = keccak(canonical_cbor)`):

```
AuditEnvelope { version:u8=1, ts_unix:u64, actor_omni:[u8;32], operator_omni:[u8;32],
                op_kind:u8, op_body:CBOR, result:u8, intent_text?:String, intent_commitment?:[u8;32] }
```

Worker: `POST /v1/audit/append` → hash; `GET /v1/audit/envelope/<hash>`. On-chain: `CredentialAudit.appendV2(operatorOmni, actorOmni, opKind, envelopeHash)` + tier-A `appendRootV2(operatorOmni, merkleRoot, opKindBitmap)` — **event-only**, indexed topics, no contract redeploy for new kinds.

**Canonical `op_kind` registry (PRs adding kinds MUST append here; numbers never reused/reordered; families in 10-blocks):**

| Kind | Byte | `op_body` schema | Emitter |
|---|---|---|---|
| `CredStore` | 0 | `{service, payload_hash}` | credentials-service |
| `CredFetch` | 1 | `{service, cap_hash}` | credentials-service |
| `CredTeardown` | 2 | `{actor_target}` | credentials-service |
| `MemoryPut` | 10 | `{key, payload_hash}` | memory-service |
| `MemoryGet` | 11 | `{key, cap_hash}` | memory-service |
| `MemoryTeardown` | 12 | `{actor_target}` | memory-service |
| `MemoryInboxAppend` | 13 | `{key, payload_hash}` | memory-service (#339 absorption) |
| `SignEip191` | 20 | `{message_digest, wallet}` | CLI sign orchestrator (#97) |
| `SignEip712` | 21 | `{chain_id, verifying_contract, primary_type, type_hash, domain_separator, digest}` | CLI sign orchestrator (#97) |
| `PaymentEscrowRedeem` | 30 | `{escrow_addr, amount, recipient, chain_id}` | payment-service (P-2) |
| `PaymentDirect` | 31 | `{rail, ref, amount_minor, currency}` | payment-service (P-1/P-3) |
| `ScopeGrant` | 40 | `{agent_omni, service_ids[], read_only, max_per_call, max_per_period, max_total, period_seconds}` | broker submit relay (#97) |
| `ScopeRevoke` | 41 | `{agent_omni}` | broker submit relay (#97) |
| `DeviceAdd` | 50 | `{device_key_hash, role_bits, attestation_hash}` | broker submit relay (#97) |
| `DeviceRevoke` | 51 | `{device_key_hash}` | broker submit relay (#97) |
| `K10Rotate` | 52 | `{old_device_key_hash, new_device_key_hash}` | SidecarRegistry hook |
| `SandboxSpawn` | 53 | `{device_key_hash, sandbox_id, function_id}` | broker sandbox lifecycle (#377 — emitted only on an actual create; an idempotent reuse is silent) |
| `SandboxTeardown` | 54 | `{device_key_hash, sandbox_id, reason}` | broker sandbox lifecycle (#377 — `reason: "unpair"` on a confirmed `revokeAgentDevice`; veFaaS timeout expiry is not broker-observed) |
| `EmailSend` | 60 | `{to_hash, subject_hash, message_id}` | email-service |
| `EmailReceive` | 61 | `{from_hash, message_id, payload_hash}` | email-service |
| `K3EpochAdvance` | 70 | `{old_epoch, new_epoch, gov_tx}` | K3EpochCounter hook |
| `ConfigPut` | 80 | `{key, payload_hash}` | config-service (#201/#229) |
| `ConfigGet` | 81 | `{key, cap_hash}` | config-service (#201/#229) |
| `ConfigTeardown` | 82 | `{actor_target}` | config-service (#201/#229) |
| `GateTurn` | 90 | `{device_id, api_key_id, model, streamed, outcome, prompt/completion/total/cached/reasoning_tokens}` | `agentkeys-gate` (#384/#332) |
| `ChannelPublish` | 100 | `{key, channel_id, event_id, payload_hash}` | channel-service (#406/#229) |
| `ChannelSubscribe` | 101 | `{channel_id, cursor, event_count, cap_hash}` | channel-service (#406/#229) |
| `ChannelTeardown` | 102 | `{channel_id, actor_target}` | channel-service (#406/#229) |
| `GatewayRelay` | 103 | `{transport, contact_id, tier, target_alias, decision, message_hash}` | WeChat gateway (#407) — contact provenance, message text NEVER stored (D13) |
| `ContactBind` | 104 | `{transport, contact_id, outcome, tier, reach_count}` | WeChat gateway (#407) — the master-confirmed bind write |

Unclaimed bytes in each 10-block + `103-255` are reserved — the device family claimed `53`/`54` for the sandbox lifecycle per #377, so `55-59` (not `53-59`) is what remains free there; the channel family claimed `100-104` at §22e phases 1-2 (#406 channel 100-102 + #407 gateway 103-104), so `105-109` is what remains in that block. `GateTurn` attribution: envelope omnis both carry the OWNING USER; device/api-key are body-level rollup dimensions (`GET /v1/usage`).

**Emit sites are live:** data-plane (#229 — cred/memory/config workers emit per store/fetch/teardown via the shared `AuditEmitter`; bodies carry hashes, never plaintext; `AGENTKEYS_WORKER_REQUIRE_AUDIT=1` = the fail-closed flip) and control-plane (#97 — the broker submit relay decodes the CONFIRMED `executeBatch` calldata → `DeviceAdd`/`ScopeGrant`/`ScopeRevoke`/`DeviceRevoke`; the CLI sign orchestrator emits 20/21). Receipts (`audit_envelope_hashes`) thread through to the UI; `/v1/audit/:id/decode` fetches the real envelope. Forward-compat invariants (open `u8` enum, stable envelope fields, version bumps only for envelope-level changes, generic fallback renderer, opaque body passthrough, op_kind-agnostic contract, this registry table, 3 tests per new kind): v2 §15.3a.

### 15.3b How to add a new op_kind — the 5-step ritual

1. Claim the next byte in the right family block (table above). 2. Append the table row here. 3. Add the Rust variant (`agentkeys-core/src/audit/{op_kind,bodies,mod}.rs`). 4. Wire the emit site via `envelope_for(...)` + `AuditClient::append`. 5. Ship the three tests (CBOR roundtrip; old-explorer graceful-unknown; byte-uniqueness — `op_kind::tests::all_byte_values_unique`). Never bump `ENVELOPE_VERSION` for a new kind. Guide: [`wiki/audit-envelope-add-op-kind.md`](wiki/audit-envelope-add-op-kind.md).

### 15.4 email-service

SES send (K9 DKIM in the worker, TEE/KMS pattern) + S3-backed per-actor inbox (`bots/<omni>/{inbound,sent}`; aliasing at the SES routing Lambda). **Deprioritized as a channel kind** — runs as-is outside the §22e channel model until prioritized. Spec: [`spec/ses-email-architecture.md`](spec/ses-email-architecture.md).

### 15.5 payment-service

Irreversible upstream ⇒ distinct primitives: three modes (**P-1** service-pool / **P-2** escrow / **P-3** direct — wallet-exposure choice), strict **one-shot CAS-burn** nonces, per-cap + per-period quotas enforced at broker AND worker, **K11 above `payment_k11_threshold`**. Wire shape + mode table: v2 §15.5.

## 16. On-chain layer (single source of truth)

Four plain-Solidity contracts (full listings: v2 §16.1; deployed addresses: the chain profile, §5 note):

- **`AgentKeysScope`** — `scope[operator][agent] = { services[], read_only, payment_k11_threshold, max_per_call/period/total, updated_at }`; `set_scope_with_webauthn` / `revoke_scope_with_webauthn` (K10+K11). NOTE: `read_only` is a **dead flag** (never consulted by `isServiceInScope`) — direction lives in the service id (`memory:` vs `inbox:`, `channel-pub:` vs `channel-sub:`).
- **`SidecarRegistry`** — `device[pubkey_hash] = { operator_omni, actor_omni, tier, roles (CAP_MINT|RECOVERY|SCOPE_MGMT), k11_cred_id, attestation, registered/revoked_at }`; register master/agent device, revoke (M-of-N), rotate, recovery threshold. Per-actor binding is THE anti-impersonation gate.
- **`K3EpochCounter`** — monotonic epoch; governance-gated `bump_epoch`.
- **`CredentialAudit`** — v1 events + `appendV2`/`appendRootV2` (§15.3a).

Ops + signature requirements table: v2 §16.2. **Submitter modes:** sovereign default (`current_master_wallet` signs; explorer-visible) / hosted relay (subsidized, `actor_omni` still in events) / self-hosted relay — flips Layer 2 only; workers re-verify regardless (v2 §16.3, §20). **K3 rotation** (§21, v2 §16.4): one epoch bump, zero migration; eager re-encrypt optional. The master account itself is an **ERC-4337 `P256Account`** (EntryPoint v0.7 + factory + `VerifyingPaymaster` live on Heima; #164/#171/#278) — every master mutation is a K11-signed UserOp.

## 17. Storage layout — per-data-class buckets, per-actor prefixes

`bucket = data class × deployment × environment; prefix = actor_omni_hex`. Both axes required: bucket-level settings conflict across classes (versioning/Object-Lock/lifecycle/KMS — the table: v2 §17.1) and **one IAM role per bucket** keeps blast radii separate (§17.2). Layout:

```
$VAULT_BUCKET    bots/<actor>/credentials/<service>.enc      $AUDIT_BUCKET  bots/<actor>/audit/<batch>
$MEMORY_BUCKET   bots/<actor>/memory/<key>                   $EMAIL_BUCKET  bots/<actor>/{inbound,sent}/...
$CONFIG_BUCKET   bots/<operator>/config/<service>.enc        $PAYMENT_AUDIT_BUCKET bots/<actor>/payments/...
```

`$CONFIG_BUCKET` = the **policy data class** (#201): master-only (governed agents hold no cap — access-control on the access-control), rides the master-self skip; config v3 envelopes are **client-encrypted under the signer-derived KEK** (#372 — the worker can't open them). The **cloud axis**: AWS default, Volcano Engine mirror (TOS + `AssumeRoleWithOIDC`, inline session policy replacing PrincipalTags — [`spec/ve-broker-runtime-port.md`](spec/ve-broker-runtime-port.md)); a **stack = (chain, cloud/broker)** and every stack-aware surface keys on the pair (#373). Bucket names are variables (globally unique). Full detail: v2 §17.1–17.4.

### 17.5 Per-data-class cap-token binding (issue #90)

The cap carries a signed `data_class`; the broker mints **one endpoint per (data-class, op)** so the route statically fixes the class (user input can never pick it):

| Endpoint | CapPayload |
|---|---|
| `/v1/cap/cred-{store,fetch}` | `{op: Store\|Fetch, data_class: Credentials}` |
| `/v1/cap/memory-{put,get}` | `{op: Store\|Fetch, data_class: Memory}` |
| `/v1/cap/config-{store,fetch}` | `{op: Store\|Fetch, data_class: Config}` (master-only) |
| `/v1/cap/audit-append` | `{op: Append, data_class: Audit}` |
| `/v1/cap/memory-canonical-get` | `{op: CanonicalFetch, data_class: Memory}` (#295 distribution) |
| `/v1/cap/memory-append` | `{op: Append, data_class: Memory}` (#339 absorption; distinct `inbox:<ns>` grant) |
| `/v1/cap/classify` | `{op: Classify, data_class: <signed body field>}` (#207 — the one compute gate) |
| `/v1/cap/channel-{pub,sub}` | `{op: ChannelPublish\|ChannelSubscribe, data_class: Channel}` (#406 — the route fixes the DIRECTION; pub cap ↛ `/poll`, sub cap ↛ `/publish`) |

Workers reject mismatched classes with 403 `cap_data_class_mismatch` — the cap-layer twin of the IAM cross-bucket gate. The channel worker additionally rejects a cross-DIRECTION cap (a `channel_publish` cap at `/v1/channel/poll`, or vice-versa) with 403 `cap_op_mismatch` (#406 D2 direction isolation).

**Four-layer defense in depth:**

| Layer | Invariant | Enforced by | Canonical test |
|---|---|---|---|
| 1. Broker cap-mint | session omni == operator; device binding + ROLE_CAP_MINT; service in scope; K10 PoP when supplied | `handlers/cap.rs` | `e2e/suite-3-isolation.sh` step 13 |
| 2. Worker chain-verify | independent re-check of broker_sig + device + scope + epoch + data_class (+ PoP presence once `REQUIRE_CAP_POP=1`) | `verify::check_*` (shared crate) | steps 11+12+14+15 |
| 3. AWS IAM PrincipalTag | STS scopes S3 ARNs via `${aws:PrincipalTag/agentkeys_actor_omni}` (+ `s3:prefix` on ListBucket) | role + bucket policies | steps 4-9 (cred + memory); step 19 (config) |
| 4. Per-data-class buckets | each role reaches only its own bucket | provision scripts | step 10 (cred ↔ memory); step 19 (config) |

**Test discipline (hard rule, also in AGENTS.md):** a new data class = two cap endpoints + `DataClass` variant + mirrored worker + provision scripts + **stage-3 negatives across all four layers**; `config` (#201) is the template.

**Sanctioned cross-actor context flows** (the §17.6 exceptions — worker-mediated, never a weakening): **distribution / canonical READ** (#295): a delegate mints `CanonicalFetch` with its OWN session under the on-chain `memory:<ns>` grant; the **worker** performs the read server-side under an **exact-object** operator-STS (issued to the worker, never the delegate) and returns plaintext only — the delegate holds no S3 credential (the "A′" model). **Absorption / inbox APPEND** (#339): the write-side twin — a delegate pushes a *proposal* to `bots/<operator>/inbox/<delegate>/…` under the **distinct** `inbox:<ns>` grant (read never implies push); server-side write STS scoped to that one write-only sub-prefix; **provenance stamped by the worker from the cap-signed `actor_omni`, never delegate-supplied**; the master curates into canonical (a PR model). Namespaces are validated (`*?/..` rejected) before use as S3 keys or IAM resources. Full rationale incl. the rejected hand-the-delegate-STS cut: v2 §17.5 + `plan/master-hub-topology.md` §7a (operator-internal).

### 17.6 Master-as-hub topology — the context flows (#295 / #339)

> Naming: these two flows were called **"the two channels"** before 2026-07; that name is retired — `channel` now names the §22e conduit concept, and these are **context flows** with grant prose names `context-sub:<ns>` / `context-pub:<ns>` (wire ids `memory:`/`inbox:` frozen). See §5.

The **master is `origin`** (git mental model): the bare, canonical, authoritative store + authorizer; each **delegate** is a working clone that **pulls** granted context (distribution, `context-sub`) and **pushes** learnings to a staging inbox for **curated merge** (absorption, `context-pub` — never a blind fast-forward; the injection-vector defense). Master: global visibility, never proxies, never hosts an app, daemon-optional. Delegate: equips exactly one AI runtime, always runs a daemon, sandbox-resident (§22e). Cross-delegate sharing is **hub-mediated, never mesh**. Memory keeps three spaces: delegate working memory (untouched), master canonical, master inbox.

**The flows carry typed *context*** (the `context system`, §5; #390): `knowledge` (light curation, recalled per turn), `skills` (strict diff-review gate; near-executable), `persona` (master-authored `SOUL.md`, versioned + validated, locked base layer always appended, applied fresh per turn; `/v1/master/persona` editor), `resources` (deferred). Invariant: **nothing enters canonical except through the master's curation gate** — gate strictness varies per type, machinery never does. The **policy data class stays outside** this system (master-only, never agent-loadable). Landed surface (#390): wire `ContextKind`, per-kind curate gates (daemon+web+CLI), the persona editor + sandbox apply/restart. Full design: `plan/master-hub-topology.md` (operator-internal).

### 17.7 Durable homes for pairing-adjacent readable metadata (#424)

The chain is **notary / permission-registry / clock**: hash-anchored authority, no PII, no per-edit gas. Everything *readable* that pairing produces lives in the master-only **Config data class** (§17.5 layers apply); daemon RAM and gateway-host files are rebuildable caches ONLY; the broker stays stateless (pre-accept pairing rendezvous is transient by design — recovery is the idempotent re-request, and the **durability boundary is the accept**). Per entity:

| Entity | Durable home |
|---|---|
| device binding (hash), scope grants (keccak service-ids), audit anchors | **chain** (`SidecarRegistry` / `AgentKeysScope` / `CredentialAudit`) |
| bound-actor label + **delegate-vs-device kind** + granted service NAMES | config: **`binding-manifest`** — written at accept (`ack_pairing`) + on every scope commit; read by the #233 fleet reconcile, so kind + channel chips survive a daemon restart |
| memory namespace names | config: `memory-taxonomy` (#201) |
| channel definitions (id → display name) | config: `channel-registry` (#404) |
| gateway contact registry | config: **`gateway-contact-registry`** — the daemon write-throughs the gateway's registry after every contact mutation and restores it onto an EMPTY (rebuilt) gateway host; the gateway's `0600` file is the working cache |
| gateway message history + contact-audit activity | gateway-host JSONL **caches** today; the durable home is the **channel-class feed** once the gateway holds an actor identity (follow-up — config's single-doc get/put is the wrong shape for unbounded append logs) |
| pending pairing rendezvous (requests / claims) | — transient (broker TTL store); a broker restart drops them; the agent re-runs `--request-pairing` (#224 supersede keeps one open row) |

**Two recorded decisions (2026-07-12, #424):**

1. **Device-vs-delegate kind: OFF-chain in #424; the on-chain split is SCHEDULED — it rides the #425 agent-slot allowance (#427).** On-chain today, devices and delegates are NOT decoupled: both bind via `registerAgentDevice` as `TIER_AGENT` rows — the chain records `(operatorOmni, actorOmni, deviceKeyHash, tier, roles)` and no kind; the #404 decoupling is enforced at accept time (`scope_is_device_only`) + IA. #424 deliberately ships NO contract change: kind alone adds no enforcement power (the authority boundary is the per-service scope grant set, already on-chain — a device holds only `channel-pub/sub:<id>` grants, so it cannot mint memory/cred caps regardless of any kind flag), and a standalone `SidecarRegistry` redeploy would orphan every live operator binding on two mainnets (the deployed-contracts hard-stop). **The #425 epic (owner-resolved O1/S1, 2026-07-12) then makes the kind load-bearing on-chain:** the agent-slot allowance charges per DELEGATE — a spawn consumes a slot, an archive frees it — while a device bind consumes nothing, and a HARD on-chain quota therefore requires the registration path itself to distinguish the two kinds (otherwise a bare `registerAgentDevice` bypasses the slot gate). So the #427 contract change — already a VERSION-bump ceremony — carries the on-chain device/delegate decoupling (a `TIER_DEVICE`-class distinction or a distinct slot-consuming delegate-spawn entrypoint): exactly the "next breaking registry version" this decision reserved, never a standalone redeploy. Either way the **binding manifest ships and stays** — it is the durable home for the READABLE layer (label, preset id, granted service names — PII that never goes on-chain; #425 consumes it: every spawn/archive lands a manifest row), and post-#427 the fleet-reconcile hydration simply gains a chain cross-check for kind.
2. **Channels stay split: grants on-chain, definitions off-chain.** The channel *authority* is already on-chain — `channel-pub:<id>` / `channel-sub:<id>` keccak service-ids in `AgentKeysScope` (grant/revoke anchored, per-direction). The channel *definitions* (id → household display name) are mutable PII → the config-class `channel-registry`. Putting definitions on-chain would cost per-edit gas + put household names on a public chain and still not remove the client-side naming layer.

Stage-3 negative: suite-3 step 24 — a cross-actor (agent) `config-fetch` mint for `binding-manifest` / `gateway-contact-registry` → ServiceNotInScope (these docs are master-only; layers 3-4 ride the step-19 config proof).

## 18. Encryption envelope

`KEK = HKDF-SHA256(salt="agentkeys.kek-salt.v2", ikm=K3_v[epoch], info="agentkeys.user.v1" || actor_omni)` (signer-derived over mTLS). Blob: `version(0x04) || k3_epoch || nonce(12) || ciphertext || tag(16)`, `AAD = "agentkeys.cred.aad.v2|" || actor_omni_hex || "|" || service` — misrouted/tampered blobs fail authentication; the epoch byte selects the K3 version. Config uses the v3 client-encrypted variant (#372, §22b.2). **K3 rotation = zero migration** (paths/tags/AAD all key on the stable `actor_omni`; §21).

## 19. Cap-token shape + lifecycle

```json
{ "ver": 2, "op": "cred-fetch", "operator_omni": "...", "agent_omni": "...", "actor_omni": "...",
  "service": "openrouter", "issued_at": ..., "expires_at": ..., "nonce": "...", "k3_epoch": 5,
  "request_hash": "...", "device_pubkey": "...", "k10_sig": "...", "k11_assertion": "?", "broker_sig": "..." }
```

| Category | Examples | K11? | CAS-burn? | TTL |
|---|---|---|---|---|
| Read-only fetch | cred-fetch, memory-get | no | no | 5 min |
| Write (non-financial) | cred-store, memory-put, audit-append, email-send | no | no | 5 min |
| Master mutation | scope-set, device-bind/revoke, k10-rotate | **yes** | effectively (chain tx) | 60 s |
| Payment | payment | above threshold | **yes** | 60 s |

Worker verification order: broker K1 sig → K10 sig → **per-actor binding** (`device.actor_omni == cap.agent_omni`) → not revoked → (master mutation) SCOPE_MGMT role + K11 → **scope contains service** → epoch fresh → TTL window → (CAS caps) nonce burn → (payment) quotas. Steps re-run the chain independently of the broker.

## 20. Mode selection — sovereign default, hosted-relay opt-in

Chain-submitter identity per deployment: **sovereign** (default — `current_master_wallet` signs, explorer-transparent, operator pays gas) · **hosted relay** (subsidized + batched; events still carry `actor_omni`; trust = relay won't omit — workers re-verify so forgery is detectable) · **self-hosted relay** (sovereign + private via a separable relay wallet). Orthogonal to per-class tier choices (§15.3, §15.5). Full detail: v2 §20.

## 21. K3 rotation

Governance bumps `K3EpochCounter` (1 tx) → signer generates `K3_v[N+1]` in-enclave (historical retained) → broker SSE-drops cached caps → new writes carry the new epoch byte; old blobs decrypt via retained epochs. **Nothing else changes** (paths, tags, policies, AAD, omnis — all stable). Lazy re-encrypt on read; eager re-encrypt tool for confirmed-compromise response. Timeline: v2 §21; operator runbook: `heima-k3-rotate.sh`.

## 22. Pluggable surfaces

| Axis | v2 default | Swap mechanism |
|---|---|---|
| Auth method | email-link, oauth2_google, SIWE | broker auth-plugin trait (`plugins/auth/`), `BROKER_AUTH_METHODS` |
| Signer backend | attested TEE | binary behind `signer.<zone>`; wire pinned by signer-protocol.md |
| Audit destination | tier C (A/B optional) | audit-service trait, per operator |
| Chain layer | `heima` (built-in default) | **named chain profiles** (§22a): 7 built-ins + `$AGENTKEYS_CHAIN_PROFILE_FILE` |
| Worker runtime | Lambda / axum / CF / SCF | uniform §15 shape |
| Payment rail | P-1/P-2/P-3 × upstream | per-mode plugins over §15.5 |
| Clear-signing metadata (#82) | bundled ERC-7730 set | `ClearSigningCatalog` trait; bundled → registry → on-chain |
| Category catalog (#207) | bundled + signed vendor overlays (floor-bounded) | same progression; the classifier's deterministic tier-0 |
| Memory engine (#147) | none by default (store+gate only); OpenViking adapter shipped opt-in | `MemoryEngine` trait; delivery via `pre_llm_call` hook |

No single backend is load-bearing; the contracts (traits, wire shapes, chain ABI) are.

## 22a. Chain profiles — how to switch between EVM backbones

Resolution order: `$AGENTKEYS_CHAIN_PROFILE_FILE` → `--chain` → `$AGENTKEYS_CHAIN` → built-in default `heima`. Production = `heima` (chain 212013; consumer tier) + `base` (8453, partner tier, own stack — #282 dual-stack, one chain per broker process, no per-request routing); dev = `heima-paseo` (Alice sudo — testnet-only, never an AgentKeys auth path; v2 §22a.5a); local/CI = `anvil`. Profile JSON bundles chain_id, `chain_kind` (finality + gas + signing strategy), RPC/explorer/token/finality/gas/deploy config + the **contract registry** (`contracts[]` + `contract_set_version`, #251) + `funding{}` (#294). Built-ins: heima, heima-paseo, base, base-sepolia, ethereum, sepolia, anvil. Cap-mint freshness follows the profile's finality (`heima` ~6 s → ~2 s after elastic scaling; `base` waits `safe`). Schema + tables: v2 §22a.

## 22b. Stage-1 simplifications inventory

Stage-1 shortcuts are listed here with their hardening pointers; **any source file taking one MUST cite this section by name** (`per arch.md §22b …`) + the issue link — drift is must-fix in review. Full text of each: v2 §22b.

### 22b.1 K11 assertion bytes — stub by default, real Touch ID via `--webauthn`

CLI k11 stub satisfies the on-chain length-gate only; `--webauthn` runs the real platform ceremony. The **software P-256 passkey** (`k11 software-{keygen,sign}`) is real crypto with file-key custody — it cannot impersonate a hardware-registered master (different key), but a master *enrolled* with it has file-key blast radius. The cryptographic refusal is **attestation verification (stage 2, #90)**; until then: e2e selects hardware for LOCAL runs, software only under `--ci`, plus unconditional WARNs.

### 22b.2 Worker KEK — env var instead of mTLS-derived

Creds/memory workers read `AGENTKEYS_{WORKER,MEMORY}_KEK_HEX` (WARN at boot; #91 adds attested-mTLS KEK derivation). **Config graduated (#372):** v3 envelopes are client-encrypted under the signer-derived KEK — the worker stores them verbatim; `AGENTKEYS_CONFIG_KEK_HEX` is legacy-v2-only; `AGENTKEYS_CONFIG_REQUIRE_V3=1` is the staged flip.

### 22b.3 Attestation bytes — empty on device registration

Contracts store but don't verify `attestation` (and stage-1 `k11CredId` was zero). Stage 2: real attestation statements (master) + on-chain link-code redemption checks (agent).

### 22b.4 Cap-mint K10 proof-of-possession — mechanism landed (#76); enforcement staged

Cap-mint requests MAY carry a K10 `client_sig` (domain-separated, request-bound); broker validates when present; workers **always verify a supplied PoP** and reject a MISSING one only under `AGENTKEYS_WORKER_REQUIRE_CAP_POP=1`. Flip closes the broker SPOF once every actor's K10 is registered (master K10 rides `registerAdditionalMasterDevice` — `setup-heima.sh` step 15; needs live verification).

### 22b.5 Audit chain anchoring — direct tx per entry (tier C)

Open-append v1 `append` per event; tier-A Merkle batching landed via `appendRootV2` (#281) with the relay posture in §15.3.

### 22b.6 Cross-references from code

Search `arch.md §22b` for the shortcut sites (k11.rs, worker `state.rs` files, `cap.rs` PoP, the deprecated EOA register script, agent-create/scope-set stubs). List: v2 §22b.6.

## 22c. AgentKeys app surface — CLI + web UI + daemon as one distribution

**One binary, three surfaces** (#134): CLI (`agentkeys <cmd>`), daemon (`agentkeys daemon` — the always-running trust core), web UI (`agentkeys web` / hosted parent-control), MCP server (subcommand or standalone). All share the daemon (§12); the MCP server's backend variant (Daemon/Http) decides where tool calls resolve.

- **22c.2 Backend wiring — four AI-runtime shapes:** hosted LLM (vendor cloud; broker mediates) · local LLM (Claude Code-class; co-located daemon, in-process cap-mint) · task agent (sandboxed VM; the daemon is the security boundary) · chat agent (our hosted management surface). Same MCP server + backend trait.
- **22c.3 Multi-device master:** add-master QR flow (existing K11 signs over the new device), replace-master via §11 quorum, 90-day K10 rotation. **Phone-first master plane:** one portable `agentkeys-core` behind `lib/client` — wasm (web), native lib (mobile), daemon (desktop); event-driven + biometric-gated, broker is the only always-on piece. **The master is an ERC-4337 P-256 account** (#171) — no client custodies secp256k1. **Restart resumability (#220):** persisted master-session coords; valid J1 = zero prompts, expired = one passkey re-auth, never full re-onboarding.
- **22c.4 Vendor device pairing:** the v2 text described binding a vendor device to an actor via a vendor token. **Superseded in design by §22e:** a device binds via §10.2 to its OWN actor and its claim attaches **channel grants (≥1)** — it is a channel endpoint, never a delegate root; vendor-cloud stacks integrate as certified stacks (§22d.3). v2 §22c.4 preserved for the vendor-token JWT mechanics.
- **22c.5:** the daemon does NOT become the agent runtime (no inference, no untrusted code, no model hosting); the web UI is not a trust plane (compromise leaks a TTL'd UI JWT, never keys).
- **22c.7 prior art:** agentmemory (shape), iii (trigger-taxonomy vocabulary only), xiaozhi-mcphub (aggregate-backend pattern if ever needed).

## 22d. IAM-guarantee delivery — hooks and the certified-stack in-path endpoint

**IAM tool vs IAM guarantee:** a tool is a function the LLM may call; a guarantee is a **non-LLM gate in the execution path** that fails closed. Two agent-first seams deliver guarantees:

- **22d.2 Hooks** (primary for Task Hosts — Claude Code, Codex, Hermes, OpenClaw): lifecycle hooks synchronously invoke the policy check; the runtime guarantees firing. Delivery: `agentkeys wire <runtime>` (#133) — idempotent hook-config writer per the AGENTS.md output convention.
- **22d.3 Certified-stack in-path endpoint** (primary for device stacks): the one point where the stack resolves the LLM turn. Shipped instance: the sandbox's LLM egress = **`agentkeys-gate`** (#384) — the metered key-custody relay holding the ONE vendor key (Ark is Bearer-only), per-user budgets (429 pre-burn), `GateTurn` audit. **Custody + metering only — never a control point**; control stays hooks + caps. The generic OpenAI-compatible proxy for unmanaged hosts was **dropped** (2026-06-19) — agent-first, no gateway mission-creep.
- **22d.3a Relay placement** (decided 2026-07-03): operator-run sandboxes → central gate (now); user-owned delegates, text traffic → daemon-local relay with broker-minted TTL'd temp keys (long run); **voice turns run in ONE place end-to-end** (today the central gate host; end-state vendor-side RTC) — never split across placements; BYOK = relay optional.
- **22d.4:** neither seam makes AgentKeys a Task Host or a generic gateway (strategy §2.4 line). The **channel gateway (§22e) is likewise a PEP, never an authority**; the routing/tier classifiers stay advisory (the #410 router SHIPPED with this invariant enforced structurally — its candidate set is ⊆ the contact's on-file reach, so no message can widen authority).

## 22e. Channels — agent ↔ device decoupling (ALL PHASES SHIPPED; live/hardware legs operator-gated)

> **Canonical design spec: [`spec/agent-channel-decoupling.md`](spec/agent-channel-decoupling.md)** (the definition study it draws on — `research/bytedance-agent-channel-model.md` — is operator-internal). Status: **phases 1-2 SHIPPED** — phase 1 substrate (#406 — `DataClass::Channel`, the `channel-pub:<id>`/`channel-sub:<id>` grants, `/v1/cap/channel-{pub,sub}`, `agentkeys-worker-channel` with the §14.12 NRT worker-held long-poll, channel-family audit op_kinds 100-102, the `channel` bucket+role) + phase 2 the **WeChat gateway MVP** (#407 — `agentkeys-worker-channel-weixin`: the ONE bot credential custodied the #384 way, the master-curated `contact` registry with household tiers, L3 enforcement + `/alias` routing, GatewayRelay/ContactBind op_kinds 103-104, contact-zero-history D13); phase 3 the **devices-as-endpoints** substrate (#408 — `is_device` accept + §14.10 ≥1-channel warn, `ak_device_cap_pop_sig` FFI, the `session` `ChannelKind`); phase 4 the **lifecycle-decoupling** core (#409 — **device pairing NEVER spawns** (D9): a channel-only §10.2 claim skips the #377 create-on-pair sandbox spawn via `scope_is_device_only`; the **#369 delegation-sig retirement switch** `AGENTKEYS_DELEGATION_RETIRED=1` (§14.11) that makes every `/v1/agent/delegation/*` endpoint refuse loudly once the one-firmware-cycle migration is done); phase 5 the **advisory router + parent-control read surface** (#410 — the #322-pattern router that picks a no-`/alias` message among the contact's reachable agents and **can never name an out-of-reach agent** even under prompt injection (candidate set is structurally ⊆ reach), `routed_by` worker-stamped, disabling degrades to `/alias`-only not failure; the admin-gated D13-safe `GET /v1/gateway/contacts` view — tier+reach, never openids/history); phase 6 promoted the surface into arch.md §5/§15/§17.5 + the user-manual + threat-model (#411, this section is now a shipped-surface reference not a DESIGN summary); post-epic, the **weixin transport decision** (2026-07-09, spec §7) shipped two drivers behind one relay core — `ilink` (Tencent iLink personal-bot long-poll, the first-experiment path) and `oa` (公众号 webhook, production) — and the veFaaS-live legs (default-delegate onboarding auto-spawn, channel-event wake-on-reason for a hibernated delegate, the #369 firmware re-bind cycle) are operator/hardware-gated follow-ups on this substrate; owner decisions resolved 2026-07-07/08 (spec §14). This section is the arch-level summary; the spec's §12 promotion map amends §5/§10.2/§15/§17.5/§17.6/§22c.4/§22d as phases land. The independent regression gate is `e2e/channel-e2e-demo.sh` (#405). Diagrams: [`assets/agent-device-decoupling-topology.svg`](assets/agent-device-decoupling-topology.svg) (topology) · [`assets/device-bind-sandbox-spawn-security.svg`](assets/device-bind-sandbox-spawn-security.svg) (bind/spawn key-custody).

- **A `channel`** is a declarative, master-owned, policy-bearing conduit `(id, kind, directions, adapter, counterparty space, owner, policy)` — hardware modules (mic/display/touch/camera), chat sessions, messaging (weixin/telegram), UI feeds. The *live* parts are its **adapter** and (async kinds) its **durable feed** (new `channel` data class per the #201 recipe). **Feed channels are the near-real-time tier** (worker-held long-poll + write-through wakeup; p50 sub-second to an awake consumer); `session` kinds stream direct with no feed; continuous speech/video stays on the §22d.3a path.
- **Every device is a channel endpoint** — its own actor + K10 (generated + signed on-device; the ESP32 already does this, §10.2), claim attaches **≥1 channel grant**, never a runtime. **Every delegate is sandbox-resident** (the sandbox's K10 is the identity root); the **default delegate** spawns at onboarding, more by option; **device pairing never spawns** (spawn-on-reason). The legacy #369 device→sandbox delegation-sig is transitional (one-firmware-cycle migration).
- **Grants:** per-direction service ids `channel-pub:<id>` / `channel-sub:<id>` on the SAME cap machinery (mint → chain re-verify → §17.5 four layers; devices mint caps exactly like delegates). Policy layers: **L1** access grant (on-chain) · **L2** interaction policy (per-actor×channel doc in the policy class, worker/gateway-enforced) · **L3** audience (**contacts** — externally-authenticated keyless principals: household-template tiers `owner/partner/elder/kid/helper/guest`, model-proposed, master-confirmed) · channel-registry defaults.
- **The gateway** answers "how capably can many externally-authenticated humans interact with agents through a channel" — authenticates contacts, enforces L2/L3, routes (`/alias` deterministic + advisory router), and custodies scarce transport credentials (one WeChat bot per KYC'd account — the #384 custody pattern). A **PEP, never an authority**.
- **Visibility:** operator-global (parent-control only, silent), **contact-zero-history** — contacts get live deliveries + agent-mediated answers; policy changes are forward-only by construction.
- **Unchanged invariants:** channel events are data, never instructions; no credential ever reaches a delegate; hub-and-spoke, never mesh; the two-gesture floor; worker chain re-verify.

## 23. Cargo workspace

```
crates/  agentkeys-{types,core}            shared types · the library (CredentialBackend, signer/sidecar clients, init, omni)
         agentkeys-protocol                the ONE owner of wire types (wasm-safe; ts-rs → apps/parent-control/lib/generated)
         agentkeys-backend-client          native client half (cap-mint 6 endpoints, STS relay, memory:<ns> builder)
         agentkeys-broker-server           K1/K2 authority; auth; chain reads; SSE; UserOp relay
         agentkeys-bundler                 loopback ERC-4337 v0.7 handleOps submitter (#230; degraded-boot capable)
         agentkeys-signer                  TEE signer (typed mTLS RPC)
         agentkeys-worker-{creds,memory,config,audit,email,payment,classify}   per-class workers (§15)
         agentkeys-gate                    metered LLM-egress relay (#384)
         agentkeys-cli · agentkeys-daemon  the binary + sidecar
         agentkeys-mcp{,-server}           legacy adapter lib · standalone MCP server (stdio/HTTP/WS; http backend only)
         agentkeys-memory-engine{,-openviking}  engine seam + reference adapter
         agentkeys-catalog                 shared category catalog (+PolicyIntent, #322)
         agentkeys-device-core             device FFI (K10 keygen/sign for firmware)
         agentkeys-provisioner             spawns TS scrapers
         agentkeys-chain                   Solidity contracts + bindings
provisioner-scripts/                       TypeScript+Playwright scrapers (one per upstream)
firmware/esp32s3-touch-lcd-4b/             the device firmware (#348)
apps/{parent-control,website,mobile-mock,design-system}   front-ends; viz/ + crates/agentkeys-fleet are operator-internal
```

**One language per process:** trust-boundary code is Rust; browser automation is the TS exception (subprocess, no crypto material). Full annotated tree: v2 §23.

## 24. Deployment topology

nginx fronts every public hostname on :443 (broker / signer / per-worker hosts); services on loopback ports or Lambda; the host firewall drops everything else. Daemons reach broker + workers over public TLS — caller auth is the cap-token, never IP. The signer host is TEE-attested and pinned. Bring-up = the three idempotent entry points (AGENTS.ops.md); diagram: v2 §24.

## 25. Cross-references

- **The channel decoupling design** — [`spec/agent-channel-decoupling.md`](spec/agent-channel-decoupling.md) (§22e)
- **Frozen v2 full text** — [`archived/arch_V2.md`](archived/arch_V2.md)
- Typed signer RPC — [`spec/signer-protocol.md`](spec/signer-protocol.md) · K3 threat model — [`spec/threat-model-key-custody.md`](spec/threat-model-key-custody.md) · CredentialBackend — [`spec/credential-backend-interface.md`](spec/credential-backend-interface.md)
- Milestones — `plan/milestones-roadmap.md` (operator-internal) · CI test fleet — [`spec/ci-parallel-test-fleet.md`](spec/ci-parallel-test-fleet.md)
- Agent-role operator reference — [`wiki/agent-role-and-usage-hdkd-per-agent-omni.md`](wiki/agent-role-and-usage-hdkd-per-agent-omni.md) · upstream classes — [`wiki/upstream-backend-classes-exercise-vs-distribution.md`](wiki/upstream-backend-classes-exercise-vs-distribution.md)
- User-facing behavior — [`user-manual.md`](user-manual.md)

## 26. What v2/v3 guarantees

No seed phrase (K10 keychain + K11 hardware) · M-of-N device recovery, no third parties · no IdP lock-in after day 0 (`actor_omni` binds to the wallet hash) · agents never hold credential bytes (sidecar injection) · device keys bound per-actor (no sibling impersonation) · K11 presence on every master mutation · K3 rotation with zero S3 migration · chain as single source of truth, workers re-verify every cap · wallet-privacy modes · per-data-class compromise isolation · vendor pluggability · CAS-burn on irreversible ops · K11 above payment threshold · three audit tiers. Enforcement table: v2 §26.

## 27. What's NOT in this doc

Per-endpoint request/response shapes (per-surface canonical docs + crate READMEs) · env-var inventories (operator runbooks) · the K3 retroactive-confidentiality threat model (spec) · build-history (plan/) · v3+ hardening items (per-(user,service) KEK, ZK cap minting, threshold signer — tracked as issues). **The full v2 prose this doc compacts: [`archived/arch_V2.md`](archived/arch_V2.md).**

---
