# AgentKeys — Step 1 Analysis: Auth Layer Sub-Problem

**Date:** 2026-04-07 (updated 2026-04-08, revised 2026-04-09)
**Stage:** pre-spec sub-analysis, auth layer only
**Scope:** this doc is **narrower** than the parent product spec. It zooms into the authentication and session-key layer between the user, the master device, the agent sandboxes, and the Heima TEE backend.

**Parent docs (authoritative for product vision):**

- `[./design-spec.md](../archived/design-spec.md)` — executive summary of AgentKeys: browser-automation provisioning, MCP delivery, x402 billing, Heima TEE storage
- `[/Users/hanwencheng/Projects/project-life/.omc/specs/deep-interview-agentkeys.md](../../../../.omc/specs/deep-interview-agentkeys.md)` — full deep-interview spec (11 rounds, 19% ambiguity, PASSED)

**Companion research docs:**

- `[../../../lifeKnowledge/heima.md](../../../lifeKnowledge/heima.md)` — Heima parachain capability analysis
- `[../../../lifeKnowledge/heima-auth.md](../../../lifeKnowledge/heima-auth.md)` — existing Heima auth mechanisms (from Wildmeta dexs-backend)
- `[./heima-cli-exploration.md](./heima-cli-exploration.md)` — feature-by-feature 1Password CLI comparison + 5 blockchain-native moves
- `[./agent-infra-sandbox-analysis.md](agent-infra-sandbox-analysis.md)` — Round 12 source-only analysis of agent-infra/sandbox
- `[./agent-infra-sandbox-runtime-probe.md](agent-infra-sandbox-runtime-probe.md)` — Round 13 empirical runtime probe, **supersedes the Round 12 doc on three findings** (memfd_secret works, Landlock doesn't, supervisord exists as PID 1) and documents the sudo-bypass deadlock

**Architecture + posture docs:**

- `[./architecture.md](../arch.md)` — 13-component inventory, Rust/TypeScript language split, Cargo workspace layout
- `[./open-source-posture.md](./open-source-posture.md)` — licensing, reproducible builds, supply chain, threat model
- `[./heima-open-questions.md](./heima-open-questions.md)` — Kai meeting agenda

**Next doc:** `2-step-analysis.md` — after the demo-workflow question (Criteria dimension) is resolved.

---

## 0. What this doc is (and isn't)

**Is:** a focused design exploration of how the AgentKeys user and their agents authenticate to Heima — who holds which session key, how sessions are minted, where they live, how they're revoked, how recovery works when a sandbox dies.

**Is not:** a redo of the main product spec. The parent `design-spec.md` and `deep-interview-agentkeys.md` already establish:

- AgentKeys is a **credential provisioning platform** (not a credential proxy, not a password manager).
- Credentials are **acquired** by browser-automation agents creating real accounts on third-party services (OpenRouter, Brave, GitHub, etc.).
- Credentials are **stored** in Heima's TEE-secured auth layer.
- Credentials are **delivered** to agents via MCP tools (`agentkeys.get_credential`, `agentkeys.list_credentials`) AND CLI (`agentkeys read`, `agentkeys run -- cmd`).
- Payment is via **x402 + USDC**.
- Target sandbox is **agent-infra/sandbox** (Docker, REST + MCP, browser + shell + filesystem).
- Language is **Rust end-to-end**.
- MVP is **CLI-first, no web UI**.
- Commands: `agentkeys init` / `store` (CLI) or `agentkeys.provision` (MCP) / `usage` / `teardown`.

This doc adds the missing piece: **the authentication layer that holds the whole thing together**. The parent spec says "credentials stored in Heima TEE-secured auth layer" and "agents consume via MCP" — but it doesn't specify how the user authenticates to trigger provisioning, how the MCP server knows the agent is authorized, or how session keys are bound to agents vs the master user.

## 1. The auth-layer problem statement

Everything in the parent spec relies on Heima knowing:

- **Who is the user?** (so it can debit their x402 wallet, attribute provisioned services to them, and enforce policies)
- **Which agents does this user own?** (so `agentkeys usage` and `agentkeys teardown` can enumerate and act on them)
- **Which credentials may this specific agent fetch from the MCP Credential Server?** (scope enforcement — agent-A gets OpenRouter, agent-B gets Brave, neither gets the other's)
- **What do we do when a sandbox dies?** (recovery path)
- **What do we do when a session is stolen?** (revocation path)

These are all resolved by the **session-key-based Connect flow** Heima already has (per `heima-auth.md` and the flow diagram captured in round 4). The question of this sub-analysis is: *how do we wire that flow specifically for the user + master-device + child-agent topology AgentKeys needs?*

## 2. Research inputs (distilled)

### Heima provides (verified in source)

1. **Connect flow with session keys:** Passkey/Google/DCAP → Auth layer → fingerprint → Heima TEE → "is first login?" → create OmniAccount or look up → optional identity graph attach → return session key → user caches locally → all subsequent calls authenticated by session key.
2. **Auth methods in dexs-backend:** Google OAuth (3-stage redirect), Wallet signature (EIP-191, 45-min window), Email + password + TOTP, HeimaLogin (Omni bridge for upstream-verified identities), Passkey as OmniAccountType (actual WebAuthn verification in the TEE worker, not in dexs-backend).
3. **Reusable primitives:** `pallet-teebag` (DCAP attestation), `pallet-omni-account` (custom origin, TEE-gated), `pallet-evm-assertions.secrets` (encrypted blob precedent), `pallet-bitacross` (TEE-held key precedent), `Identity` enum (Substrate/EVM/BTC/Solana/Twitter/Discord/Github/Google/Email), `omni-executor` crypto modules.

### Heima is missing (for AgentKeys specifically)

- **No general credential store pallet** scoped per-agent. Probably needs to be added or layered on `pallet-evm-assertions.secrets`.
- **No first-class "agent" entity** in the identity graph. Agents are currently just "children" in the OmniAccount graph; AgentKeys needs to attach scope/policy to them.
- **No scoped session-key minting** (master → child with subset of capabilities). Needs to be added.
- **No MCP Credential Server** — this is net-new AgentKeys code.

### 1Password CLI pain points AgentKeys targets

(from `heima-cli-exploration.md`, abbreviated)

- Long-lived bearer `OP_SERVICE_ACCOUNT_TOKEN` is the only headless path.
- Immutable SA scope, fully manual rotation.
- Audit log is opaque and vendor-owned.
- 100 SA/org cap hostile to agent fleets.
- SSH / git signing are desktop-only.

AgentKeys' answer is structurally different from 1Password: **we don't hand users a CLI to read secrets. We provision credentials on their behalf, store them in a TEE, and deliver them through MCP calls from agents.** The CLI is for management, not for data-plane access.

## 3. Auth-layer architecture decisions (from rounds 1–4 of this sub-interview)

### 3.1 Identity model

- **Master identity** = the human user. Anchored to a **recoverable** identity method: Google OAuth, synced passkey (iCloud Keychain / Google Password Manager / 1Password / Bitwarden), or email (magic link).
- **Child identity** = an agent (e.g., `agent-A`). Can use any identity method the master provisions — including non-recoverable ones like Heima-native device code (interpretation B) and non-synced passkeys — because children are re-issuable from the master.
- **DCAP is explicitly out** for portability. AgentKeys must work on commodity Docker sandboxes without SGX.
- **Policy enforced by Heima TEE** (one-line check): `if first_login_for_identity and identity_type not in {google, synced_passkey, email}: reject`. Cannot create a new OmniAccount from a non-recoverable identity.

### 3.1a Canonical name = x402 wallet address (Round 6)

- **Every account — master and child — has an EVM wallet address as its canonical, public, stable name.**
- The keypair is generated **inside Heima TEE** on account creation (same pattern as `pallet-bitacross` for BTC/ETH/TON custodial wallets — private key never leaves the enclave, only the pubkey/address goes on chain).
- The address is the primary key in audit logs, CLI output, and MCP-server authorization checks.
- Maps directly to Heima's existing `Identity::Evm(Address20)` enum variant — no new identity type needed.
- **Three identity concepts collapse into one namespace:**


| Concept                             | What it is                                                       | Public?                                       |
| ----------------------------------- | ---------------------------------------------------------------- | --------------------------------------------- |
| OmniAccount (internal)              | Heima account primitive derived from identity-method fingerprint | No                                            |
| Session key (ephemeral)             | Current authentication token                                     | No                                            |
| **x402 wallet address (canonical)** | secp256k1 pubkey-derived EVM address, minted in TEE              | **Yes — printed in UI, logs, block explorer** |


- **Consequence for billing:** each account's wallet **holds its own USDC**. Master funds child wallets with `agentkeys fund agent-A 10`. When a child's wallet runs out, the child stops working — **natural spend limit, no on-chain enforcement code needed**. This is the point of x402 being ERC-20 USDC: the balance itself is the limit.
- **Consequence for x402 integration:** any x402-compliant upstream HTTP endpoint can accept payment directly from the agent's wallet. AgentKeys does not operate a shared billing pool that has to be reconciled back to agents — **x402 is the native billing rail, not a bolted-on layer**.
- **Consequence for audit logs:** every on-chain event is self-describing: `block N | 0x9c3e...f4a2 READ op://openrouter ✓`. No internal IDs to resolve.
- **Consequence for recovery:** "attach sandbox to agent-A" becomes "give this sandbox a session key authorized to sign as wallet 0x9c3e...f4a2". The wallet is persistent; the session key is ephemeral; the sandbox is disposable.

### 3.2 Session key tiers

> **Correction (2026-04-12, verified against Heima source `tee-worker/omni-executor/core/src/auth/auth_token.rs`):** The original table below described session "keys" (keypairs) stored client-side. Heima's actual implementation uses **JWT-based stateless auth tokens**: the TEE signs a JWT with its RSA private key, and the client holds the JWT string as a bearer token — NOT a private key. The security properties and storage requirements are different from what the original table assumed. OS keychain is no longer required (a JWT can go in a plain file); `keyring-rs` complexity drops significantly. The table is preserved below as the original design-time thinking, with the correction noted.


| Tier                  | Lifetime                                                         | Storage (original spec)                           | Storage (corrected, JWT model)                        | Usage                                                                                                         |
| --------------------- | ---------------------------------------------------------------- | ------------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| **Master auth token** | 30 days (canonical AgentKeys policy per `docs/wiki/session-token.md`; `AuthOptions.expires_at` can shorten per-session) | OS keychain | Plain file or env var (JWT string, not a private key) | Management commands: `agentkeys init`, `store`, `usage`, `teardown`, `approve`. Never used by running agents. |
| **Agent auth token**  | Long (hours to days)                                             | Sandbox filesystem (`~/.agentkeys/session`, 0600) | Same (JWT string in file, 0600)                       | MCP Credential Server authentication. Scoped to specific credentials for a specific agent.                    |


### 3.3 Storage choices (Rounds 5–6)

**Master side — OS keychain (still recommended, but for different reasons).** The original analysis recommended `keyring-rs` because it assumed the client holds a session private key. Under the JWT model (verified against Heima source), the client holds a signed JWT string — a bearer token, not a private key. OS keychain is **still the recommended default** for the master CLI because a JWT is still a bearer credential that grants access until expiration, and keychain provides app-level ACL against malware-as-same-user on developer machines. Plain file (mode 0600) is an acceptable **fallback** for daemon/sandbox/CI environments where keychain isn't available. The blast radius of a JWT leak is bounded by TTL (~~24h) + on-chain revocation (~~6s) — less catastrophic than a private key leak, but not zero. The macOS keychain double-prompt issue from the Stage 4 investigation (see `docs/wiki/key-security.md`) is a v0-only testing annoyance (caused by `security(1)` as an external inspector), not a production concern for stable binaries.

**Agent side — sequential stack: S1, then S2, then S3.** Resolved in Round 6:


| Layer  | Mechanism                                                                                                | Status                                                                                                                                                                                                                                       |
| ------ | -------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **S1** | **Hardened at-rest file + process isolation via dedicated daemon** (full Linux kernel design, see §3.3a) | **v0: REQUIRED**                                                                                                                                                                                                                             |
| **S2** | Rolling ratchet: session key auto-rotates every N minutes, stolen dump expires in minutes                | **v0.1: add after S1 is stable**                                                                                                                                                                                                             |
| **S3** | Bind to specific sandbox provider attestation (instance identity signed by the sandbox provider)         | **v0.2: only for providers that expose the primitive (agent-infra/sandbox capability TBD)**                                                                                                                                                  |
| ~~S4~~ | ~~In-memory only, re-auth on cold boot~~                                                                 | **REJECTED**: breaks autonomy (re-auth requires human on every cold boot); and any memory-cache approach for credentials themselves would break per-call audit-trail integrity, because Heima-side audit events only fire on extrinsic calls |
| ~~S5~~ | ~~Split-key (master holds share)~~                                                                       | **REJECTED**: breaks sandbox autonomy — master-online dependency                                                                                                                                                                             |


**Honest v0 claim:** *"The session key is stored with every layer of Linux kernel protection a non-HW-TEE sandbox can offer. In the worst case — host root compromise — the attacker gets the scoped subset of credentials for this one agent for ≤ 4 hours, and the audit log on Heima is already reporting the abuse in real time. 1Password service accounts give the attacker everything, forever, silently."*

### 3.4 The in-sandbox agentkeys-daemon: two interfaces, one backend (Round 7)

**Decision:** there is **no central hosted "MCP Credential Server."** The component shown in the design-spec diagram is reinterpreted as a **local sidecar** running inside the agent's own sandbox — it's the same `agentkeys-daemon` that holds the session key from §3.3a, now extended with two interface adapters. No AgentKeys-operated service is ever in the hot path.

**Why no central server:**

- A hosted `mcp.agentkeys.dev` would be a **metadata sink** (sees every "who asks for what, when"), even if E2E-encrypted.
- It would be a **single point of failure, censorship, and compromise** that breaks the "operationally self-sovereign" claim.
- It would add latency (2x round trips) for no functional gain.
- Heima's public RPC endpoint (`wss://rpc.litentry-parachain.litentry.io`) is already reachable from any sandbox — there is no routing problem to solve.

**The daemon is a pure relayer.** It holds nothing long-term beyond the session key (which §3.3a protects). Every credential fetch is a fresh Heima TEE call; the credential bytes exist in the daemon only for the duration of the response forwarding, then are `explicit_bzero`'d.

**Two interfaces on the same backend:**

```
┌─ inside the agent-infra sandbox ──────────────────────────────────┐
│                                                                    │
│  ┌─────────────┐                        ┌────────────────────┐   │
│  │ agent code  │ ◄── MCP over stdio ───►│                    │   │
│  │ (Claude     │     (/var/run/         │ agentkeys-daemon   │   │
│  │  Code,      │      agentkeys-mcp     │                    │   │
│  │  Cursor,    │      .sock)            │  ┌──────────────┐  │   │
│  │  etc.)      │                        │  │ internal API │  │   │
│  └─────────────┘                        │  │  get_cred    │  │   │
│                                          │  │  list_svcs   │  │   │
│  ┌─────────────┐                        │  │  sign_chal   │  │   │
│  │ master user │ ◄── line protocol ───► │  │  attach_agt  │  │   │
│  │ `agentkeys  │     (/var/run/         │  └──────┬───────┘  │   │
│  │  read ...`  │      agentkeys.sock)   │         │          │   │
│  │ CLI tests   │                        │  session key in    │   │
│  │ shell script│                        │  memfd_secret      │   │
│  └─────────────┘                        │  (per §3.3a)       │   │
│                                          └──────────┬─────────┘   │
│                                                     │             │
└─────────────────────────────────────────────────────┼─────────────┘
                                                      │
                                                      │ HTTPS + wss
                                                      │ (session-key-signed
                                                      │  extrinsics)
                                                      ▼
                                            ┌──────────────────┐
                                            │  Heima TEE       │
                                            │  - decrypts      │
                                            │  - emits audit   │
                                            │    extrinsic     │
                                            └──────────────────┘
```

**Interface roles:**

- **MCP interface** — for **agents**. Exposed as an MCP tool provider: agent frameworks (Claude Code, Cursor, any MCP-native runtime) auto-discover tools like `agentkeys.get_credential(service)`. Zero custom glue code needed per framework.
- **CLI interface** — for **master user operations** (`agentkeys read`, `agentkeys list`, `agentkeys status`, etc.) and for **all unit tests** of the daemon. Testing the daemon through the CLI is cleaner than testing it through the MCP protocol — no protocol mocking, no stdio framing, just process invocation and stdout parsing.

**Why both:**

- CLI is more Unix, more auditable, and is the natural test-harness interface.
- MCP is the ecosystem-native interface for AI agent frameworks and preserves the design-spec's MCP commitment.
- Both interfaces map to **the same internal Rust API inside the daemon**, so the "two interfaces" are adapters of ~100 LoC each over a shared core.
- The daemon, the CLI binary, and the MCP manifest are **all open-source** so any user can read exactly what the daemon does in the credential path.

**Consequence for unit testing:** every behavior of the daemon (policy enforcement, scope checks, session key rotation, audit event emission, error handling, rate limiting) is testable through the CLI with a simple subprocess test harness. No MCP client mocking required for the test suite.

### 3.4a CLI UX — implicit agent ID and env-var injection (Round 8)

**Two Round 8 refinements to the CLI surface:**

**(1) Agent ID is optional on a machine that hosts exactly one agent.** The `agentkeys-daemon` knows which agent it was attached to (the daemon is itself per-agent), so all CLI commands default to that agent. Explicit form uses the **x402 wallet address** as the canonical ID:

```
# implicit (default to the agent this sandbox is attached to)
agentkeys read openrouter
agentkeys list
agentkeys run -- ./openclaw

# explicit (needed if multiple agents are attached to the same machine,
# or from a master CLI context that manages many)
agentkeys read openrouter --agent 0x9c3e...f4a2
agentkeys list --agent 0x9c3e...f4a2
agentkeys run --agent 0x9c3e...f4a2 -- ./openclaw
```

No human-assigned agent-name identifiers in the protocol layer — the wallet address is the ID. Friendly names (like "agent-A") are a client-side convenience: the master CLI keeps a local alias table mapping names to wallet addresses, used only for typing convenience. On the daemon side, everything speaks wallet addresses.

**(2) Primary consumption model is env-var injection, not dynamic MCP tool calls.**

Most real CLI tools — openclaw, Claude Code, `aws`, `gh`, `gcloud`, `openai`, `curl` — read credentials from environment variables at startup. They cannot be retrofitted to call an MCP tool mid-execution. Therefore the 80% usage pattern is:

```bash
agentkeys run -- ./openclaw --model kimi-k2 --task "summarize this repo"
```

Under the hood, `agentkeys run`:

1. Connects to `/var/run/agentkeys.sock`.
2. Daemon authenticates with its session key (held in `memfd_secret`).
3. Daemon fetches **every** credential provisioned for this agent from Heima in parallel.
4. Daemon returns them to the CLI wrapper.
5. Wrapper sets standard env vars in the child process (e.g., `OPENROUTER_API_KEY=...`, `BRAVE_SEARCH_API_KEY=...`, `ANTHROPIC_API_KEY=...`).
6. Wrapper `execve()`s the child. Child sees standard env vars and runs without modification.
7. Child process exits. Env vars exist only in its address space and die with it. Wrapper `explicit_bzero`s its own copies.

This is intentionally analogous to `op run -- cmd`. It is the migration path for every existing tool. It does NOT require the target CLI to know anything about AgentKeys, MCP, or Heima.

**Service → env-var name mapping** is stored in a per-service provisioning template maintained in the daemon (e.g., `openrouter → OPENROUTER_API_KEY`, `brave-search → BRAVE_SEARCH_API_KEY`, `anthropic → ANTHROPIC_API_KEY`). User can override with `agentkeys run --env FOO=openrouter -- ./cmd`.

**MCP interface remains valuable for:**

- Agents that fetch credentials during reasoning (rare for credentials specifically, common for search/database tools).
- Agent frameworks with native MCP tool discovery (Claude Code, Cursor) where surfacing AgentKeys as a tool provider is ergonomic.
- Mid-execution credential rotation without re-spawning the child process.

But env-var injection via `agentkeys run` is the **primary, default, unit-tested** path for v0.

### 3.3a S1 at-rest design — Linux kernel hardening (Round 6 deep dive)

> ⚠️ This section describes the ORIGINAL Round 6 design. It has been superseded by §3.3c (Round 13 runtime reality check). On stock agent-infra/sandbox: no UID split, no Landlock, no AppArmor, session at `/home/gem/.agentkeys/session` (not `/var/lib/agentkeys/`), daemon runs as `gem`. See §3.3c for what actually ships in v0.

The target runtime is **agent-infra/sandbox**, a Docker container on a Linux host. No SGX/TDX, no vTPM in the container, no systemd-creds (no systemd inside the sandbox), no Linux kernel keyring (`keyctl` is typically blocked in unprivileged containers), no Secret Service API (no desktop session). The available kernel features are: POSIX DAC, LSM (AppArmor/SELinux if the host policy passes through), `chattr +i`, `memfd_secret()` (kernel >= 5.14), `mlock2()`, `prctl(PR_SET_DUMPABLE)`, `prctl(PR_SET_NO_NEW_PRIVS)`, `seccomp-bpf`, `Landlock` (kernel >= 5.13), capability dropping, user namespaces, mount namespaces.

**Defense has to be layered because no single mechanism is sufficient:**

**Layer 1 — at rest (the file on disk):**

> ⚠️ Superseded by §3.3c.3: on stock sandbox, path is `/home/gem/.agentkeys/session`, owner is `gem`, no dedicated UID, no AppArmor/SELinux, no `chattr +i`. See §3.3c for the v0 reality.

```
[Original Round 6 design — retained for historical reference]
Path:     /var/lib/agentkeys/session
Mode:     0600
Owner:    agentkeys:agentkeys   (dedicated UID, not root, not the agent's UID)
Parent:   /var/lib/agentkeys/   mode 0700, same owner
Mount:    parent mounted with nosuid,nodev,noexec
Attrs:    chattr +i              (immutable — prevents in-place tamper; daemon briefly toggles it off on rotation)
LSM:      AppArmor profile labels the file so only /usr/bin/agentkeys-daemon can read it
          (or SELinux type agentkeys_session_t on RHEL-flavored hosts)
```

**Layer 2 — at runtime (when the daemon reads the key):**

See §3.3c.3 for which of these steps actually work on stock sandbox. Summary: steps 1-6 work; step 7 (seccomp) works because baseline is `seccomp=unconfined`; step 8 (Landlock) does NOT work (`CONFIG_SECURITY_LANDLOCK=n`).

1. Drop capabilities before opening the file: `prctl(PR_SET_NO_NEW_PRIVS, 1)`, `prctl(PR_SET_DUMPABLE, 0)` — blocks core dumps and ptrace attachment, prevents any `/proc/PID/mem` reads by another process with CAP_SYS_PTRACE.
2. Open and read the session file. Kernel enforces DAC + LSM here.
3. Copy bytes into `**memfd_secret()` pages** (kernel >= 5.14, `CONFIG_SECRETMEM`). These pages are explicitly excluded from the kernel direct map, unreachable from `/dev/mem`, `/proc/kcore`, `process_vm_readv`, and resistant to kernel speculation side-channels (Spectre/Meltdown class).
4. `explicit_bzero` the heap copy.
5. `mlock2(MLOCK_ONFAULT)` the secretmem pages so they never get swapped to disk.
6. `capset(empty)` — drop every capability the daemon no longer needs.
7. Load a **seccomp-bpf** filter that denies: `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`, `keyctl`, opens on `/dev/mem` and `/dev/kmem`, and `userfaultfd`.
8. ~~Apply a **Landlock** ruleset restricting filesystem access to: read `/var/lib/agentkeys/`, write `/var/run/agentkeys.sock`. Nothing else.~~ **❌ Landlock not available on stock sandbox kernel (`CONFIG_SECURITY_LANDLOCK=n`). Skip gracefully, do not abort. See §3.3c.1.**

**Layer 3 — architectural (the single biggest win):**

**The agent process never holds the raw session key.** A dedicated `agentkeys-daemon` runs inside the sandbox. It is the ONLY thing that reads the session file. The agent process talks to the daemon over `/var/run/agentkeys.sock` (Unix domain socket) and asks high-level questions — "sign this Heima challenge", "fetch credential for openrouter". The daemon replies with the result; the raw session key never crosses the socket.

If the agent process is RCE'd (prompt injection, dependency vuln, logic bug), the attacker gets **the socket**, not the key. They can invoke the socket's API until the session is revoked or the TTL expires, but they cannot exfiltrate the session key, cannot move laterally to another agent's secrets, and every call they make hits the on-chain audit log.

This is exactly the **ssh-agent model** — battle-tested, simple, and it's what PGP agents, yubikey-agent, and 1Password's own SSH agent all do.

> ⚠️ On stock sandbox, Layer 3's UID isolation is NOT enforced (gem has NOPASSWD sudo — see §3.3c.2). The ssh-agent model still provides separation of concerns, but a compromised agent with sudo can read daemon memory directly.

**Layer 4 — revocation coupling:** the whole design is defensible ONLY because revocation is instant (one extrinsic, propagates within one block ~6 seconds). If you can't kill a stolen session in seconds, none of the above matters. The master CLI's `agentkeys revoke 0x9c3e...` is the emergency brake.

### What this does NOT protect against (be honest)

> ⚠️ See §3.3c.6 for the updated threat model on stock sandbox. The list below is the original Round 6 version assuming the full kernel hardening design.

- **Host root on the Docker daemon.** If the attacker has root on the host and can enter the container's namespace, they can attach to the agentkeys-daemon process, read its `memfd_secret` pages from `/proc/<pid>/mem` (yes, despite the syscall — host root bypasses per-process protections), or just dump the ext4 filesystem where the session lives. **No kernel primitive fixes this without hardware TEE or provider attestation (S3).**
- **Compromise of the agentkeys-daemon binary itself.** If the daemon has a bug that lets a caller read arbitrary memory, the socket boundary collapses. Defense: keep the daemon small, Rust-only, fuzz it.
- **Cold-boot RAM attacks.** Not realistic in a Docker sandbox (you'd need physical host access).
- **Side-channel attacks on the shared host.** Noisy-neighbor Spectre variants are partially mitigated by `memfd_secret` but not entirely. The state of the art here is ugly.

### Open prerequisites (Round 6 new — **Round 12 reality-checked, see §3.3b; Round 13 further revised, see §3.3c**)

1. What host kernel version does agent-infra/sandbox run on? (>= 5.14 for `memfd_secret`, >= 5.13 for Landlock) — **A1 ✅ PASS on demo image (6.10.14-linuxkit), UNVERIFIABLE for production hosts**
2. Is `CONFIG_SECRETMEM` enabled in the host kernel? — **A2 ✅ VERIFIED WORKING** (reversed from Round 12's "PROBABLE FAIL" — Round 13 runtime probe confirmed `memfd_secret()` returns fd=3)
3. Does the host pass AppArmor/SELinux labels through to containers, or do we need our own in-container LSM? — **A3 ❌ LSM dead** (no `CAP_MAC_ADMIN`, not implementable from inside the container)

3-bonus. Landlock availability? — **A3-bonus ❌ Landlock dead** (`landlock_create_ruleset()` returns ENOSYS — kernel built with `CONFIG_SECURITY_LANDLOCK=n`)
4. Does the sandbox run as root with user namespaces, or as a non-root UID already? Can we create an `agentkeys` UID via the sandbox's build or at runtime? — **A4 ⚠️ mixed** (UID creation works, but revoking sudo from gem breaks gem-server — see §3.3c.2)
5. Does agent-infra/sandbox block `CAP_SYS_PTRACE` by default? — **A5 ⚠️ baseline blocked but sudo bypasses** (Docker drops the cap but `sudo strace` works via NOPASSWD sudo)
6. Does it expose `/dev/mem`, `/proc/kcore`, or allow `ptrace_attach` across PID namespaces? — **A6 ✅ partial** (`/dev/mem` blocked, but `seccomp=unconfined` leaves `process_vm_readv` open; our own seccomp-bpf filter can close it)

**See `[./agent-infra-sandbox-analysis.md](agent-infra-sandbox-analysis.md)` for the full evidence trail with file:line citations. Round 12 verdict below.**

### 3.3b Reality check against agent-infra/sandbox — Round 12 deltas to §3.3a

> ⚠️ This section describes Round 12 source-only recommendations. Several were reversed by Round 13 runtime probe: Landlock does NOT work (skip gracefully, don't abort), init-container with sudo revocation breaks gem-server (do NOT implement), supervisord IS PID 1 (no Rust supervisor needed). See §3.3c.

**Verdict:** The Round 6 design as written in §3.3a is **not buildable on a stock agent-infra/sandbox image** without modifications. Key findings:

1. **The `docker/` directory in the repo is empty.** The open-source repo is SDK + docs + OpenAPI spec only; the Dockerfile, entrypoint, sudoers config, and seccomp baseline are all closed-source and published only as a built image. Half the kernel-capability questions are unanswerable from source alone without running the image directly or asking maintainers.
2. **The stock image grants sudo to the default user.** `sudo: bool` is a first-class parameter on every file-mutation API in the OpenAPI spec (`openapi.json:5191, 5226, 5265, 5358`). The default user is documented as "with sudo privileges" (`sandbox.mdx:140`). This means a compromised agent process can `sudo cat /var/lib/agentkeys/session` and read the session file regardless of DAC perms, chattr+i, or LSM labels. **The entire Round 6 "dedicated UID" isolation story collapses unless we actively strip sudo in an init step.**
3. **The image mandates `seccomp=unconfined`** (`README.md:35`, `docker-compose.yaml:6`). The syscall deny-list §3.3a Layer 2 step 7 wants to add is the *only* thing standing between a tenant and `ptrace` / `process_vm_readv`. On the upside: because there's no host-imposed filter, AgentKeys can install its own strict bpf filter without fighting a baseline.
4. **No LSM control from inside a container.** AppArmor profiles are loaded at the host level via `apparmor_parser` which requires `CAP_MAC_ADMIN`. The §3.3a Layer 1 line "AppArmor profile labels the session file so only `/usr/bin/agentkeys-daemon` can read it" is **not implementable** on a stock sandbox. Drop it from v0.
5. `**/var/lib/agentkeys/` is ephemeral.** The writable layer dies on `--rm`. The sandbox documents `${WORKSPACE}` (typically `/home/gem`) as the persistence path, or a named docker volume. Session storage path needs to move.
6. **No init system / supervisor.** ~~There's only container-level `restart: unless-stopped`. AgentKeys needs its own in-container init + supervisor to double-fork the daemon and expose health.~~ **Reversed by Round 13: supervisord IS PID 1. See §3.3c.1.**

#### The seven Round 12 edits to §3.3a

Priority-ordered, each actionable:

**1. Drop the AppArmor/SELinux line from Layer 1.** Replace with: *"DAC + ~~Landlock~~ seccomp-bpf + sudo-revocation provide the entirety of v0's filesystem isolation."* Addresses A3. *(Note: Landlock also dropped per Round 13.)*

**2. ~~Add an `agentkeys init-container` step as Layer 0.**~~ **❌ REVERSED by Round 13.** The init-container approach that revokes gem's sudo breaks `gem-server` (the sandbox's own HTTP control plane). Do NOT implement. See §3.3c.2 for the full deadlock analysis.

~~Original Round 12 init-container proposal retained for reference:~~

```bash
# DO NOT IMPLEMENT — breaks gem-server (Round 13 finding)
# useradd -r -s /usr/sbin/nologin -d /var/lib/agentkeys agentkeys
# echo 'gem ALL=(ALL) !ALL' > /etc/sudoers.d/agentkeys-deny-sudo
# ...
```

**3. Reframe the storage path.** ~~Two options — pick one at deployment time.~~ **Resolved by Round 13:** `/home/gem/.agentkeys/session` (the workspace IS `/home/gem`). See §3.3c.3.

**4. Kernel self-check at daemon startup — no silent degradation.** On startup, the daemon probes:

- `uname -r` → parse version, abort if < 5.14
- `memfd_secret(0)` → if fails, fall back to `mmap(MAP_ANONYMOUS|MAP_PRIVATE) + mlock2(MLOCK_ONFAULT) + madvise(MADV_DONTDUMP|MADV_WIPEONFORK)`, log the degradation explicitly
- ~~`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` → if fails, abort (no silent degradation for Landlock — it's load-bearing)~~ **Reversed: Landlock is NOT load-bearing. Skip gracefully if unavailable.**
- `prctl(PR_SET_NO_NEW_PRIVS, 1)` → if fails, abort

On failure to meet the minimum kernel, refuse to start with a clear `AGENTKEYS_FATAL_KERNEL_INSUFFICIENT` error. Document minimum kernel as 5.14 in the README. Addresses A1, A2.

**5. ~~Add a Rust supervisor (~200 LoC).**~~ **Reversed by Round 13.** supervisord is already PID 1 in the sandbox. Register as a `[program:agentkeys-daemon]` in `/opt/gem/supervisord.conf` instead. See §3.3c.1.

**6. Update the honest threat model.** See §3.3c.6 for the final v0 threat model on stock sandbox.

**7. Add a "production hardening" follow-up** to the open questions list: *"Is there a maintained fork (or upstream PR) of agent-infra/sandbox that ships seccomp-on, sudo-off, no Jupyter/VSCode/VNC, and a dedicated non-root UID by default — a 'headless production agent runtime' variant intended for this use case? If not, the durable answer is for AgentKeys to build one."* This is the long-term path vs. trying to harden the daemon from inside an unhardened image indefinitely.

#### The revised honest v0 security claim (replaces the §3.3 claim)

> ⚠️ This claim is from Round 12. It has been further superseded by the Round 13 claim in §3.3c.4, which is strictly weaker (no UID isolation, no Landlock) and strictly more honest. See §3.3c.4 for the current v0 claim on stock sandbox.

*"The session key gets every protection a non-HW-TEE Docker container with sudo-stripped agent UID can offer: dedicated non-root UID via init-container, DAC 0600 + chattr+i, memfd_secret (when kernel >= 5.14) or mlock2-locked anonymous memory (fallback), seccomp denying ptrace/process_vm_readv/kcmp/keyctl/dev-mem-opens, Landlock restricting FS access to the data dir + socket, and architectural isolation via the ssh-agent-model Unix socket. In the worst case — host root, sandbox-image vendor compromise, or failure to run the init-container — the attacker gets the scoped subset of credentials for this one agent for <= 4 hours, and the on-chain audit log is already reporting the abuse in real time. Critically, we are NOT protected against an in-container adversary that retains sudo, because the upstream sandbox grants sudo by default; users who do not run the AgentKeys init-container step get ONLY the revocation-latency guarantee, not the UID isolation."*

### 3.3c Round 13 runtime reality check — THREE REVERSALS and a v0 scope decision

**Source:** empirical probe of a live `agent-infra/sandbox v1.0.0.152` instance via its HTTP API, 2026-04-08. Full report in `[./agent-infra-sandbox-runtime-probe.md](agent-infra-sandbox-runtime-probe.md)`. Raw probe: `/tmp/agentkeys-probe-output.txt`.

Round 12 was a source-only analysis. Round 13 actually ran the image. Three significant findings **reverse Round 12's source-only conclusions**, and one new empirical finding **reverses the viability of §3.3b's init-container approach itself**.

#### 3.3c.1 Three reversals vs Round 12


| Finding                               | Round 12 source-only                                    | Round 13 runtime (this section)                                                                                                                                                                  |
| ------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `memfd_secret()` / `CONFIG_SECRETMEM` | **PROBABLE FAIL** (linuxkit default assumed to lack it) | **✅ VERIFIED WORKING** — Python ctypes `syscall(447, 0)` returned `fd=3`. Docker Desktop's current linuxkit builds with `CONFIG_SECRETMEM=y`.                                                    |
| Landlock availability                 | **PASS on kernel version** (6.10 > 5.13 threshold)      | **❌ FAIL with ENOSYS** — `landlock_create_ruleset()` returns errno 38. This kernel is built with `CONFIG_SECURITY_LANDLOCK=n`.                                                                   |
| In-container init/supervisor          | **FAIL — no init system, only container-level restart** | **✅ supervisord IS PID 1** — `/usr/bin/python3 /usr/bin/supervisord -n -c /opt/gem/supervisord.conf`. AgentKeys can register as a supervisord program, no need to write our own Rust supervisor. |


**Consequences for the design:**

- **Use `memfd_secret` as the primary path, not a fallback.** The Round 12 "degrade to mlock2" fallback path is still needed for *other* hosts, but on Docker Desktop-hosted sandboxes it's dead code.
- **Drop Landlock from §3.3a Layer 2 step 8.** It's load-bearing in the original design but not enforceable here. Fall back to seccomp-bpf denying `openat` on sensitive paths (weaker, more complex, incomplete).
- **Drop the "add a 200-line Rust supervisor" item from the §3.3b delta list.** Instead: write a supervisord `[program:agentkeys-daemon]` snippet and register it via `/opt/gem/supervisord.conf` (requires sudo during initial provisioning, done once).

#### 3.3c.2 The sudo-bypass deadlock — the really bad finding

**Round 12 source analysis identified that `gem` has passwordless sudo and recommended stripping it via init-container. Round 13 tried to implement this empirically and discovered it cannot be done without breaking the sandbox itself.**

What we ran (probe2):

1. `sudo useradd -r -s /usr/sbin/nologin -d /var/lib/agentkeys -m agentkeys` → **worked**, created UID 999
2. `sudo install -o agentkeys -g agentkeys -m 0700 -d /var/lib/agentkeys` → **worked**
3. `sudo runuser -u agentkeys -- bash -c "echo TESTSESSION > /var/lib/agentkeys/session"` → **worked**
4. `echo 'gem ALL=(ALL) !ALL' | sudo tee /etc/sudoers.d/zz-test-agentkeys` → **worked**
5. `sudo visudo -c` → **confirmed valid syntax**
6. Verify: `sudo -n id` → **correctly returned "sudo: a password is required"** — the deny rule works as designed
7. Cleanup: `sudo rm -f /etc/sudoers.d/zz-test-agentkeys` → **HUNG FOREVER** — because the deny rule had just blocked sudo, the cleanup's own sudo call was waiting for a password prompt forever
8. **The entire `gem-server` HTTP API then wedged.** Even non-sudo API calls like `GET /v1/sandbox` started timing out.

**Root cause — this is the killer architectural finding:** `gem-server` (the Python service implementing `/v1/*` on port 8088) **runs as the `gem` UID** (verified in probe1's `ps auxf` output). When an API call triggers any privileged operation, gem-server spawns `sudo <command>` as a child process. When the deny rule fires, those children hang on the password prompt forever, and gem-server apparently has no timeout around them — the entire control plane locks up.

**Implication:** the sandbox's own HTTP API structurally depends on gem having NOPASSWD sudo. You literally cannot revoke gem's sudo without breaking the sandbox. The §3.3b Round 12 delta #2 ("add an `agentkeys init-container` step that writes the sudo-deny rule") is **not implementable on stock `agent-infra/sandbox`** regardless of how surgical the approach.

Even a narrower "deny sudo for specific paths" approach likely fails, because we don't know which paths gem-server needs for its own operations. We'd have to reverse-engineer the gem-server source (which is closed; `docker/` in the public repo is empty) to build an allow-list.

#### 3.3c.3 v0 scope decision (locked in Round 13)

**User decision:** *"we use 'Build a hardened fork' as TODO suggestion which will need talk to the agent-infra team. Currently we accept that v0 on stock sandbox gives you only revocation-latency isolation, and document it specially for agent-infra/sandbox."*

**Translation to the design:**

1. **v0 runs on stock `agent-infra/sandbox`.** No init-container step that touches sudo. The AgentKeys daemon runs as the `gem` UID like every other service. No UID split. No `/etc/sudoers.d/` changes.
2. **The daemon still uses all the kernel features that ARE available** — `memfd_secret()` (works), `mlock2()` (works), `prctl(PR_SET_DUMPABLE, 0)` (works), `prctl(PR_SET_NO_NEW_PRIVS, 1)` (works), seccomp-bpf (we install our own filter — the sandbox's baseline is `seccomp=unconfined` so there's no conflict), and capability drops (works). Landlock is NOT used.
3. **Storage path: `/home/gem/.agentkeys/session`** (mode 0600, owner gem). Not `/var/lib/agentkeys/` (which is root-owned and would require the broken init-container approach). Not `${WORKSPACE}` because `/workspace` doesn't exist on this image — the workspace IS `/home/gem`.
4. **The daemon registers as a `[program:agentkeys-daemon]` in `/opt/gem/supervisord.conf`** during the initial provisioning flow. This requires sudo once at provisioning time, which is fine because at that moment gem still has sudo — we just don't touch gem's sudo ourselves.
5. **The entire defense in depth for v0 is revocation latency.** The session key file is readable by any process running as gem (which includes the agent itself via sudo escalation). Our defense against a compromised agent is that the session key can be revoked on-chain in <= 1 Heima block (~6 seconds), and has a hard TTL of 4 hours regardless.

#### 3.3c.4 The honest v0 security claim (supersedes the §3.3 and §3.3b claims for stock-sandbox deployments)

> *"On stock `agent-infra/sandbox v1.0.0.152`, the session key is stored using every kernel hardening feature that actually works on the image: `memfd_secret()` (runtime-verified), `mlock2()` to prevent swap, `prctl(PR_SET_DUMPABLE, 0)`, `PR_SET_NO_NEW_PRIVS`, a strict seccomp-bpf filter denying ptrace/process_vm_readv/kcmp/keyctl/dev-mem-opens, and capability drops to an empty set after initialization. It does NOT have UID isolation (gem has NOPASSWD sudo and the sandbox's own control plane depends on this — actively breaking it wedges the whole sandbox), does NOT have Landlock (this kernel is built without `CONFIG_SECURITY_LANDLOCK`), and does NOT have AppArmor/SELinux (no LSM operational inside the container). In the worst case — RCE of the agent process — the attacker has immediate full access to the session file and to daemon memory via `sudo strace`. Our defense against a compromised agent is NOT isolation; it is **rapid on-chain revocation**. A stolen session dies in <= 1 Heima block (~6 seconds) once detected, and has a hard TTL of 4 hours regardless. Compared to 1Password service-account tokens — which have no TTL, no per-call signing, no instant revocation, and an opaque vendor-owned audit log — this is still a meaningful upgrade, but it is **strictly weaker** than the §3.3a Round 6 design. Users who need kernel-enforced isolation between their agent process and their credential daemon must wait for a hardened fork of `agent-infra/sandbox` (see §8 long-term TODO) or deploy AgentKeys on a different sandbox product entirely."*

#### 3.3c.5 New long-term TODO — hardened fork of agent-infra/sandbox

**Added to §8.2 as a long-term item.** The durable answer to the sudo-bypass problem is a variant of `agent-infra/sandbox` designed for production agent runtimes:

- **Move `gem-server`, `python-server`, `mcp-server-browser` to run as `root` or a dedicated `sandbox` UID** — break the dependency on gem having sudo.
- **Remove sudo from gem by default** — `/etc/sudoers.d/gem` omitted or replaced with a minimal deny rule.
- **Remove interactive dev services** — no Jupyter, no VSCode/code-server, no VNC, no browser-as-default.
- **Ship seccomp-on by default** — remove the `seccomp=unconfined` requirement.
- **Build the kernel with `CONFIG_SECURITY_LANDLOCK=y`** so Landlock actually works.
- **Enable AppArmor passthrough** — ship an AppArmor profile as part of the image.
- **Pre-create an `agentkeys` UID** so the init-container step becomes a one-line enable.
- **Publish the Dockerfile** — the `docker/` directory in the public repo is currently empty, so building a fork requires re-deriving the image first.

**Prerequisites:** conversation with the agent-infra/sandbox maintainers (no existing channel — would need to open a GitHub Discussion or file an issue), OR maintaining our own fork long-term (roughly 1 week initial work + ongoing patches to keep parity with upstream releases).

#### 3.3c.6 What the new threat model says (supersedes §3.3a "what this does NOT protect against" on stock sandbox)

On stock `agent-infra/sandbox`, AgentKeys v0 does NOT protect against:

- **Any process running as gem.** That includes the agent process itself — gem has NOPASSWD sudo, so anything running as gem can `sudo cat` the session file, `sudo strace` daemon memory, `sudo ptrace` the daemon, etc. There is no UID isolation on this image.
- **Host root or sandbox-image vendor compromise.** Same as every earlier v0 claim.
- **Side-channel attacks on the shared host.** Same as earlier.
- **Compromise of `gem-server`, `python-server`, or any other gem-UID service.** A bug in any of these exposes the session file to the same attacker.

AgentKeys v0 DOES protect against:

- **Non-gem userspace adversaries inside the container.** There aren't any by default, but if the user runs an additional service under a different UID, that service cannot read the session file (DAC 0600 owner gem).
- **Memory exfiltration via `/proc/<pid>/mem` from a non-root process.** `PR_SET_DUMPABLE, 0` blocks it.
- **Swap-based exfiltration.** `mlock2(MCL_CURRENT|MCL_FUTURE)` prevents the session key from being paged to disk.
- **Kernel speculation attacks on the session key pages.** `memfd_secret()` excludes them from the kernel direct map.
- **Stolen-session replay beyond TTL.** Hard 4-hour TTL enforced on chain.
- **Stolen-session replay after detection.** On-chain revocation, propagation latency <= 1 Heima block (~6 s).

### 3.5 What self-sovereignty means here (pinned)

- **Operational, not strict.** User does not hold a seed phrase; they hold a Google account and/or a synced passkey.
- **No centralized operator can read secrets** (TEE-enforced).
- **No AgentKeys operator can lock the user out** — recovery is via the user's Google account.
- Ciphertext lives on a public chain.
- The writeup must be explicit about this trade-off — it's a design choice, not a weakness.

## 4. User flows

> ⚠️ Flows 2, 5, and 7 below use the original `agentkeys attach` / `agentkeys setup` model with direct HTTP push to sandbox. This has been superseded by the child-initiates rendezvous model. See tech-brief.md Flows A-F for the current flows. Flows 1, 3, 4, 6, 8 remain valid.

These are the canonical flows wiring together the parent product spec with this doc's auth-layer architecture. Each flow is annotated with which session key is in play.

### Flow 1 — First-time onboarding

```
User            Mac CLI                   Heima TEE                 x402 Wallet Svc
 │                 │                          │                          │
 │ brew install agentkeys                     │                          │
 │ agentkeys init ►│                          │                          │
 │                 │ open browser             │                          │
 │                 │ Google OAuth ───────────►│                          │
 │                 │                          │ fingerprint = hash(      │
 │                 │                          │   "google", email)       │
 │                 │                          │ first login → create     │
 │                 │                          │ OmniAccount + wallets    │
 │                 │                          │ mint master session key  │
 │                 │ ◄─── master session key  │                          │
 │                 │ store in macOS Keychain  │                          │
 │                 │ (biometric-gated)        │                          │
 │                 │ create x402 wallet ─────────────────────────────────►│
 │                 │ ◄─── wallet address + funding QR                    │
 │ ◄── "fund this wallet with USDC to begin"  │                          │
 │                 │                          │                          │
 │ (user sends USDC externally)               │                          │
```

**Auth keys in play:** master session key (created, stored on Mac).
**Why a recoverable identity only:** if the user later loses their Mac, they sign in from any browser with the same Google account → same fingerprint → same OmniAccount → full access.
**Failure modes:**

- User tries this on an ephemeral sandbox instead of a real device → **Heima TEE still accepts because Google fingerprint is recoverable**, but UX-wise they lose the Keychain-backed storage and have to re-login on every sandbox boot. Discouraged by CLI messaging, not enforced.
- User picks a non-recoverable identity (YubiKey without sync) as their first login → Heima policy rejects: "master identity must be recoverable."

### Flow 2 — Agent provisioning (the core product move)

> ⚠️ **SUPERSEDED.** This flow uses the original `agentkeys setup` command with direct HTTP push to sandbox. The current model splits this into two commands: `agentkeys store` (CLI, human-driven manual credential storage) or `agentkeys.provision` (MCP tool, agent-driven automated provisioning). The session key delivery uses the child-initiates rendezvous model (`agentkeys approve <pair-code>`) instead of direct HTTP push. See tech-brief.md Flows A-F for the current flows.

```
User     Mac CLI               Heima TEE        Provisioner sandbox    3rd-party service
 │          │                      │              (agent-infra)         (e.g. OpenRouter)
 │          │                      │                    │                       │
 │ agentkeys setup agent-A \       │                    │                       │
 │   --services openrouter,brave   │                    │                       │
 │ [NOW: `agentkeys store` (CLI)   │                    │                       │
 │  or `agentkeys.provision` (MCP)]│                    │                       │
 │ ───────► │                      │                    │                       │
 │          │ auth with master     │                    │                       │
 │          │ session key ────────►│                    │                       │
 │          │                      │ debit x402 for     │                       │
 │          │                      │ expected cost      │                       │
 │          │                      │ spawn provisioner  │                       │
 │          │                      │ ──────────────────►│                       │
 │          │                      │                    │ launch browser        │
 │          │                      │                    │ open openrouter.ai    │
 │          │                      │                    │ click sign up ───────►│
 │          │                      │                    │ handle email verify   │
 │          │                      │                    │ handle CAPTCHA        │
 │          │                      │                    │ navigate → API key    │
 │          │                      │                    │ ◄── obtains API key   │
 │          │                      │                    │ (same for brave)      │
 │          │                      │                    │ encrypt credentials   │
 │          │                      │                    │ to Heima shielding key│
 │          │ ◄── encrypted creds  │                    │                       │
 │          │                      │ store in TEE,      │                       │
 │          │                      │ tag with           │                       │
 │          │                      │ (owner, agent-A,   │                       │
 │          │                      │  openrouter)       │                       │
 │          │                      │ mint agent-A       │                       │
 │          │                      │ session key scoped │                       │
 │          │                      │ to its creds       │                       │
 │          │ ◄── provisioned +    │                    │                       │
 │          │   agent session key  │                    │                       │
 │ ◄── "agent-A provisioned.       │                    │                       │
 │      Approve sandbox pairing    │                    │                       │
 │      with: agentkeys approve    │                    │                       │
 │      <pair-code>"               │                    │                       │
```

**Auth keys in play:** master session key (authorizes), agent session key (minted, handed to user).
**Key design points:**

- The provisioner sandbox is **ephemeral and disposable** — it creates accounts and dies. Credentials flow through it but aren't stored on it.
- Heima TEE stores `(owner_omni, agent_id, service, encrypted_credential)` tuples.
- The agent session key is **scoped**: it can only ask the MCP Credential Server for credentials tagged with its `agent_id`. Everything else returns DENIED.
- x402 is debited up-front (expected cost) with reconciliation against actual usage later via `agentkeys usage`.

### Flow 3 — Agent runtime (credential fetch — the hot path) — Round 7 revised

```
Agent process            agentkeys-daemon              Heima TEE
(agent-infra sandbox)     (same sandbox, §3.3a          (stores creds,
                           hardening, §3.4 daemon)       enforces policy)
 │                              │                             │
 │ MCP tool: get openrouter     │                             │
 │ (stdio / unix socket)        │                             │
 │ ───────────────────────────► │                             │
 │                              │ check scope locally         │
 │                              │ (agent wallet 0x9c3e... may │
 │                              │  read openrouter? yes)      │
 │                              │ build extrinsic, sign w/    │
 │                              │ session key from            │
 │                              │ memfd_secret                │
 │                              │ wss://rpc.litentry... ─────►│
 │                              │                             │ verify sess key
 │                              │                             │ verify wallet scope
 │                              │                             │ decrypt cred in enclave
 │                              │                             │ emit audit event
 │                              │                             │ (on-chain, signed)
 │                              │ ◄── encrypted response      │
 │                              │ decrypt using daemon's      │
 │                              │ ephemeral pubkey            │
 │                              │ explicit_bzero intermediate │
 │                              │ buffers                     │
 │ ◄── credential (plaintext)   │                             │
 │ use for LLM call             │                             │
 │                              │                             │
 │ (same flow works via         │                             │
 │  CLI: `agentkeys read        │                             │
 │   openrouter` → stdout)      │                             │
```

**Auth keys in play:** agent session key only (held inside the daemon, never in the agent process memory). Master is not involved in the hot path.
**Key properties:**

- **No central server in the path.** The daemon speaks directly to Heima's public RPC endpoint.
- **No caching.** Each call is a fresh Heima extrinsic → every credential use generates an on-chain audit event.
- **No AgentKeys-operated service** in the hot path at all. The only AgentKeys-operated thing is the installer/docs.
- **Same hot path for both MCP and CLI callers** — the daemon treats them identically after adapter-layer translation.

### Flow 4 — Denied request (scope enforcement demo)

```
Agent-A      MCP Server      Heima TEE
 │              │                │
 │ get github   │                │
 │ ────────────►│                │
 │              │ check scope ──►│
 │              │                │ agent-A not
 │              │                │ provisioned for
 │              │                │ github
 │              │ ◄── DENIED     │
 │              │ log attempt    │
 │              │ on-chain       │
 │ ◄── DENIED   │                │
```

**Why this matters:** this is one of the parent spec's explicit acceptance criteria ("Agent A requests GitHub credential → DENIED"). It's also the **demo moment** that proves multi-agent isolation.

### Flow 5 — Usage monitoring

> ⚠️ **SUPERSEDED in part.** The `agentkeys usage` command concept remains valid, but the underlying data retrieval may use the rendezvous model for cross-sandbox queries. See tech-brief.md for current flow.

```
User         Mac CLI               Heima TEE
 │              │                      │
 │ agentkeys usage                     │
 │ ───────────►│                       │
 │              │ auth w/ master ─────►│
 │              │ query audit events   │
 │              │ for owner            │
 │              │ ◄── per-(agent,      │
 │              │      service) stats  │
 │              │ query x402 balance   │
 │              │ + spend history      │
 │              │ ◄── wallet state     │
 │              │ format table         │
 │ ◄── table    │                      │
```

**Auth keys in play:** master session key.
**Source of truth:** on-chain audit events. `agentkeys usage` is a *view* over the chain; no off-chain database required.

### Flow 6 — Teardown

```
User      Mac CLI            Heima TEE           Teardown sandbox     3rd-party service
 │           │                    │                    │                      │
 │ agentkeys teardown agent-A     │                    │                      │
 │ ────────► │                    │                    │                      │
 │           │ auth w/ master ───►│                    │                      │
 │           │                    │ mark agent-A creds │                      │
 │           │                    │ as revoked         │                      │
 │           │                    │ (MCP calls now fail│                      │
 │           │                    │  immediately)      │                      │
 │           │                    │ spawn teardown     │                      │
 │           │                    │ ──────────────────►│                      │
 │           │                    │                    │ login, navigate,     │
 │           │                    │                    │ delete account ─────►│
 │           │                    │                    │ ◄── deleted          │
 │           │                    │ delete encrypted   │                      │
 │           │                    │ credential blob    │                      │
 │           │                    │ final x402 settle  │                      │
 │           │ ◄── done           │                    │                      │
 │ ◄── confirmation               │                    │                      │
```

**Auth keys in play:** master session key.
**Note:** revocation in Heima TEE is instant (< 1 block). Third-party account deletion is best-effort and may take longer / require human follow-up. The writeup should be honest about this.

### Flow 7 — Recovery (sandbox dies)

> ⚠️ **SUPERSEDED.** This flow uses `agentkeys attach` with direct HTTP push to the sandbox's REST API. The current model uses **child-initiates rendezvous**: the new sandbox runs `agentkeys pair` to generate a pair-code, and the master approves via `agentkeys approve <pair-code>`. No direct HTTP push needed. See tech-brief.md Flow D for the current recovery flow.

```
[Original Round 6 flow — retained for historical reference]
Old sandbox dies (disk gone, agent session key gone with it)
         │
         ▼
User      Mac CLI              Heima TEE         New sandbox (same agent-A)
 │           │                       │                    │
 │ agentkeys attach agent-A          │                    │
 │ [NOW: `agentkeys approve          │                    │
 │  <pair-code>` — child initiates   │                    │
 │  via rendezvous model]            │                    │
 │ --sandbox https://new.agent-infra.sandbox/              │
 │ ─────────►│                       │                    │
 │           │ auth w/ master ──────►│                    │
 │           │                       │ verify agent-A     │
 │           │                       │ belongs to owner   │
 │           │                       │ mint NEW agent-A   │
 │           │                       │ session key        │
 │           │ ◄── new sess key      │                    │
 │           │ push to new sandbox   │                    │
 │           │ via sandbox REST API  │                    │
 │           │ ─────────────────────────────────────────►│
 │           │                       │                    │ store at
 │           │                       │                    │ ~/.agentkeys/session
 │           │                       │                    │ agent resumes
 │ ◄── "attached" ────────────────────────────────────────┤ MCP reads same creds
```

**Auth keys in play:** master session key (mints new child), new agent session key (replaces old one).
**Key invariant:** credentials live in Heima TEE. Losing the sandbox loses nothing of value. The new sandbox inherits the same `agent-A` identity with the same scoped access.
**Alternative:** user could instead run `agentkeys init` inside the new sandbox and do Google OAuth there (same email = same OmniAccount); but then they'd still need a separate pairing step to bind the new sandbox to an existing agent. The flow above assumes the master-on-Mac is the more ergonomic path.

### Flow 8 — Revocation (suspected compromise)

```
User         Mac CLI             Heima TEE           Compromised sandbox
 │              │                      │                    │
 │ agentkeys revoke agent-A            │                    │
 │ ──────────► │                       │                    │
 │              │ auth w/ master ─────►│                    │
 │              │                      │ invalidate agent-A │
 │              │                      │ session key in     │
 │              │                      │ policy table       │
 │              │                      │ (< 1 block)        │
 │              │ ◄── revoked          │                    │
 │              │                      │                    │ next MCP call:
 │              │                      │                    │ denied immediately
 │ ◄── done     │                      │                    │
 │              │                      │                    │
 │ (optional: immediately re-provision with agentkeys approve │
 │  <pair-code>, getting a fresh session key via rendezvous)  │
```

**Auth keys in play:** master session key (revokes).
**vs. 1Password:** 1P service account rotation requires manual redeployment to every machine holding the token. Here, revocation is one extrinsic; every sandbox breaks on the next MCP call automatically.

## 5. Alignment with the parent design-spec

This section explicitly reconciles any points where earlier rounds of this sub-interview drifted from the parent spec.


| Earlier (narrow interview)                            | Correct (per parent spec)                                                                                                                                                                                                                                                               |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "CLI reads secrets directly via `hk read op://...`"   | **Credentials delivered via MCP tools AND CLI (`agentkeys read`, `agentkeys run -- cmd`).** The `agentkeys` CLI is for management AND runtime consumption; the MCP Credential Server provides the agent-framework-native interface.                                                     |
| "Master web app for managing children"                | **No web UI in MVP.** Management via `agentkeys usage` / `revoke` / `teardown` CLI. Block explorer for raw audit. Web app is a post-MVP consideration.                                                                                                                                  |
| "Demo on any commodity VM (DigitalOcean, Vast, etc.)" | **Demo target is agent-infra/sandbox specifically.** Docker-based, already has REST + MCP + browser. Other runtimes are post-MVP.                                                                                                                                                       |
| "Writing `hk` CLI in any language"                    | **Rust end-to-end.** Aligns with Heima/Substrate stack.                                                                                                                                                                                                                                 |
| "Secrets created by the user and stored"              | **Credentials obtained by Agent Provisioner (browser automation) from third-party services.** Users don't import existing credentials in MVP — AgentKeys creates fresh ones per agent. (Note: this is a significant divergence from 1Password and should be emphasized in the writeup.) |
| "Payment is operational cost"                         | **x402 + USDC** billing: user funds a wallet, system debits per provisioning operation and ongoing service subscription.                                                                                                                                                                |


## 6. Open questions (auth-layer specific, blocking for spec)

1. ~~**Where does the MCP Credential Server run?~~ ✅ RESOLVED in Round 7.** There is no central MCP Credential Server. The component is a **local sidecar inside the sandbox** — the same `agentkeys-daemon` that holds the session key (§3.3a), now extended with two interface adapters (MCP + CLI, §3.4). No AgentKeys-operated service is in the hot path. The daemon speaks directly to Heima's public RPC endpoint.
2. ~~**Is a credential returned to the agent cached or fresh-per-call?~~ ✅ RESOLVED in Rounds 6-7.** **Fresh-per-call, no caching.** Rejected by the user in Round 6: "memory can run as a cache, but that will make the audit non-trackable." Every credential fetch generates an on-chain Heima extrinsic, which is the authoritative audit log. Caching would short-circuit this and break the audit integrity claim.
3. ~~**How does the master CLI push an agent session key to a new sandbox?~~ ✅ RESOLVED by rendezvous model.** The master CLI does NOT push directly to the sandbox. Instead, the child sandbox initiates pairing by running `agentkeys pair`, which generates a short-lived pair-code. The master approves via `agentkeys approve <pair-code>`. Session key delivery happens through Heima's relay, not via direct HTTP to the sandbox's REST API. No network reachability from master to sandbox required.
4. ~~**Does `agentkeys attach agent-A --sandbox <url>` work across the public internet?~~ ✅ RESOLVED by child-initiates model.** The rendezvous model eliminates this question entirely. The child initiates the connection to Heima (outbound HTTPS/WSS, which works from any network). The master approves via Heima (also outbound). Neither party needs to be reachable by the other directly.
5. **What exactly is in the audit log?** Minimum: `(timestamp, owner_omni, agent_id, service, action, result)`. Open: does it include the MCP tool name? The originating LLM model? The prompt length? How much is on-chain vs in an off-chain indexer?
6. **Does Heima currently support scoped session key derivation** (master session → child session with a strict capability subset)? If yes, reuse. If no, this is a TEE worker change — worth a conversation with Kai early.
7. ~~**Bootstrap issue for recovery Flow 7~~ ✅ RESOLVED by rendezvous model.** The child sandbox runs `agentkeys pair` on its own (outbound to Heima). No need for the master CLI to reach the sandbox before agentkeys runs there. The pair-code is displayed to the user (or relayed via the sandbox's own UI), and the master approves it from any device.

## 7. What's resolved after Rounds 4-7 of this sub-interview


| Question                                          | Answer                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Auth method for master                            | Google OAuth or synced passkey (hybrid), email baseline                                                                                                                                                                                                                                                                                                                                                                                                   |
| Auth method for agents                            | Any (device code, non-synced passkey, etc.) — children don't need recoverable identities because the master can re-issue                                                                                                                                                                                                                                                                                                                                  |
| Hardware dependency                               | **None** (DCAP ruled out)                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Master identity policy                            | Must be recoverable (policy check in Heima TEE)                                                                                                                                                                                                                                                                                                                                                                                                           |
| **Canonical account name (Round 6)**              | **x402 wallet address (EVM), minted in Heima TEE on account creation. Same primary key for master and each child.**                                                                                                                                                                                                                                                                                                                                       |
| **Billing model (Round 6)**                       | **Each account's wallet holds its own USDC. Master funds children. Empty wallet = agent stops. No on-chain spend-limit code needed — the balance IS the limit.**                                                                                                                                                                                                                                                                                          |
| Master session storage                            | OS keychain (Keychain Services / Credential Manager / libsecret), biometric-gated                                                                                                                                                                                                                                                                                                                                                                         |
| Master session TTL                                | 30 days (canonical AgentKeys policy per `docs/wiki/session-token.md`)                                                                                                                                                                                                                                                                                                                                                                                          |
| **Agent session storage**                         | **On stock sandbox: `/home/gem/.agentkeys/session`** (mode 0600, owner gem) + memfd_secret runtime pages + seccomp-bpf process restrictions + daemon with Unix socket (ssh-agent model). **On cloud LLM or custom sandbox: `$HOME/.agentkeys/session`** with the same hardening stack. *(Original Round 6 design specified `/var/lib/agentkeys/session` with dedicated UID + LSM + Landlock — see §3.3a for historical reference, §3.3c for what ships.)* |
| **Storage stack order (Round 6)**                 | **S1 (this Round 6 hardening) → S2 (rolling ratchet) → S3 (provider attestation). S4 and S5 rejected.**                                                                                                                                                                                                                                                                                                                                                   |
| Agent session TTL                                 | 30 days (same policy as master CLI per `docs/wiki/session-token.md`; may be shortened in a future defense-in-depth tweak)                                                                                                                                                                                                                                                                                                                                      |
| Scope                                             | Each agent session bound to its specific service credentials only                                                                                                                                                                                                                                                                                                                                                                                         |
| Revocation                                        | Instant via master CLI (`agentkeys revoke 0x...`)                                                                                                                                                                                                                                                                                                                                                                                                         |
| Recovery                                          | New sandbox runs `agentkeys pair` → master runs `agentkeys approve <pair-code>` (mints new session for same wallet address). *(Original design used `agentkeys attach agent-A` with direct HTTP push — superseded by rendezvous model.)*                                                                                                                                                                                                                  |
| Self-sovereignty level                            | Operational                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| **MCP Credential Server (Round 7)**               | **Does not exist as a central service.** The component is a local `agentkeys-daemon` sidecar inside the sandbox, merged with the §3.3a session-key daemon.                                                                                                                                                                                                                                                                                                |
| **Daemon interfaces (Round 7)**                   | **Both MCP (agents) and CLI (master users, unit tests). One Rust internal API, two thin adapters.** CLI drives all unit tests.                                                                                                                                                                                                                                                                                                                            |
| **Credential caching (Rounds 6-7)**               | **None.** Every fetch is a fresh Heima extrinsic = authoritative on-chain audit event.                                                                                                                                                                                                                                                                                                                                                                    |
| **Hot-path infrastructure operated by AgentKeys** | **Zero.** Only the installer, docs, and open-source binaries. Runtime path: agent → daemon (in sandbox) → Heima public RPC.                                                                                                                                                                                                                                                                                                                               |
| **Open source posture**                           | Daemon, CLI binary, MCP manifest are all open source. Users can audit the exact credential path.                                                                                                                                                                                                                                                                                                                                                          |


**Sub-interview ambiguity:** ~22% (down from 28% after Round 7). Nearly at the 20% threshold. Remaining blockers: kernel-capability prerequisites in §3.3a (6 items), items 5-6 in §6 (items 3, 4, 7 now resolved by rendezvous model), and the v0 demo workflow (Criteria dimension, ~0.25).

## 8. TODOs and remaining open questions

### 8.1 Blocking for v0 spec (must resolve before coding starts)

1. ✅ ~~**§3.3a kernel-capability prerequisites** (6 items)~~ — **Rounds 12-13 resolved.** See §3.3b for the Round 12 reality-check deltas, §3.3c for Round 13 reversals. Key outcome: v0 runs as `gem` on stock sandbox, no UID split, no Landlock, no AppArmor. Defense is revocation latency + the kernel features that do work (memfd_secret, seccomp-bpf, mlock2, capability drops).
2. **Single concrete v0 demo workflow** — Criteria dimension still the weakest. Four candidates named in §9. **Now the #1 remaining blocker.**
3. **§6 items 5-6** — audit event contents, Heima TEE scoped-session-key derivation support. *(Items 3, 4, 7 resolved by rendezvous model.)*
4. **Heima TEE work required** — needs a conversation with Kai to confirm what's already implemented vs net-new. See `heima-open-questions.md`.
5. **Writeup format** — blog / paper / talk / repo. Shapes what "v0 done" means.
6. **Is there (or can we build) a hardened fork of agent-infra/sandbox?** Round 12 recommendation: long-term the right answer is a "headless production agent runtime" variant — no sudo by default, seccomp on, no Jupyter/VSCode/VNC, dedicated non-root UID, persistence via named volume. Near-term: either find an existing one or do all the hardening at runtime via the init-container approach.

### 8.2 Concrete build TODOs (for v0 or v0.1, not blocking the spec but worth listing)

#### 8.2.1 Automated account provisioning flows (v0 scope — core product feature)

The Agent Provisioner uses browser automation (Playwright-in-Rust, probably via `[playwright-rust](https://github.com/octaltree/playwright-rust)` or Chromium DevTools Protocol directly) inside a disposable agent-infra/sandbox to create third-party accounts. Each target service has its own onboarding shape, ranked below by implementation complexity:

**Tier 1 — easy (v0 MVP targets):**

- **OpenRouter** — email + password → dashboard → API key page. Single-service test target. Probably the first integration.
- **Brave Search API** — create new account with email, verify via email code, navigate to dashboard, obtain API key. Similar difficulty to OpenRouter.

**Tier 2 — medium (v0.1):**

- **Notion API** — requires OAuth flow + creating an integration inside a workspace. Workspace provisioning is nontrivial.
- **OpenAI (Whisper / standard API)** — email + password + phone verification + payment method attachment. Phone verification is the blocker (see §8.2.2).

**Tier 3 — hard (v0.2+):**

- **Twitter** — Google SSO is broken (Twitter blocked it for programmatic signups), forcing the email path with:
  - Email verification code
  - **Human CAPTCHA check** (Arkose Labs / Twitter's FunCAPTCHA)
  - Possibly phone verification
  - Aggressive bot detection — fingerprinting, TLS fingerprinting, behavioral analysis
  - Needs stealth browser automation (`playwright-stealth` equivalent) + possibly a CAPTCHA-solving service (2Captcha, Anti-Captcha, CapMonster)
  - **Legal/ToS question:** automated signups violate Twitter's ToS — be explicit about this in the writeup if Twitter is demonstrated.
- **Google Account** — KYC via mobile number (SMS verification, hard to automate ethically) or a business Workspace account. Arguably the hardest target.
- **1Password** — requires a business account + billing setup. Not a good early target since the whole point of AgentKeys is to *replace* 1P for agents; demoing 1P provisioning is weird.

#### 8.2.2 Cross-cutting provisioning infrastructure (needed before Tier 2+)

- **Ephemeral email service integration** — each agent account needs an email. Options: user's Gmail with plus-addressing (`user+agentA@gmail.com` — simplest but ties to the user's real email), burner email providers (SimpleLogin, DuckDuckGo Email, AnonAddy, ForwardEmail — better privacy, adds dependency), or a Google Workspace with a domain and programmatic subaddress creation (most robust, most setup).
- **Email code retrieval** — the provisioner must read the verification code from whichever email backend is in use. If burner service, call its API; if Gmail plus-addressing, IMAP read from the user's inbox (requires OAuth or app password).
- **Phone verification strategy** — Tier 2+ services increasingly require phone verification. Options: skip those services (simplest), SIP numbers, Twilio subaccounts, or punt to the user ("give us a phone number").
- **CAPTCHA handling** — for Tier 3. Either integrate a CAPTCHA-solving service (paid, adds cost per account creation, legal gray area) or use stealth automation that avoids CAPTCHA triggers (harder, less reliable).
- **Per-service scrapers/flows** — each target service needs its own Playwright script that knows the current DOM structure and signup flow. These break when the service changes its UI. Needs monitoring + CI tests against the real signup flow.
- **Failure recovery** — what happens when a provisioning flow half-completes (account created, API key not obtained)? Clean up or retry? Needs a state machine.

#### 8.2.3 Web GUI (post-MVP, add to roadmap)

- **Master-user web app** — after MVP, a local-first web UI (Tauri or Electron desktop app with an embedded webview, or a static web app loading the master CLI via a local HTTP bridge) for:
  - Managing all agents in one view (spawn, revoke, rename, refresh)
  - Live audit log stream (reads + writes from on-chain events)
  - x402 wallet balance + spend-per-service breakdown
  - Credential scope editing per agent
  - Provisioning wizard (guided flow for adding new services)
- **Authentication model for the web GUI** — same master session key as the CLI, stored in the OS keychain. The web GUI is a view over the same daemon the CLI talks to.
- **Scope policy:** no remote hosting. The web GUI runs locally or is opened from a browser pointed at a local loopback server. Not a SaaS.
- **Justification for adding it later:** design-spec MVP explicitly says "no web UI (CLI-first)." Web GUI is a post-MVP polish layer, not a v0 requirement.

#### 8.2.5 Hardened fork of agent-infra/sandbox (long-term, Round 13 new)

Full rationale in §3.3c.5. Summary: stock `agent-infra/sandbox` cannot enforce the §3.3a Round 6 UID split because the sandbox's own HTTP control plane depends on the default user having NOPASSWD sudo (empirically verified in Round 13 — trying to revoke gem's sudo wedges `gem-server`). The durable fix is a production-oriented variant of the image.

- **Open a GitHub Discussion on `agent-infra/sandbox*`* asking about a production-hardened variant. Questions: (a) is there an existing fork we're not aware of, (b) would maintainers accept upstream PRs adding a "production mode" build target, (c) what's the long-term roadmap for security posture?
- **Document the threat model gap publicly.** A blog post or GitHub Discussion titled "Why stock agent-infra/sandbox cannot enforce UID isolation for credential daemons" — explains the sudo-bypass finding with reproducible evidence. Useful for the research artifact writeup even if no fork materializes.
- **Scope the fork effort.** Approximately 1 week for initial fork (replicate the currently-empty `docker/` directory from a working image, move `gem-server`/`python-server`/`mcp-server-browser` to run as root or a dedicated UID, remove sudo from gem, rebuild kernel with `CONFIG_SECURITY_LANDLOCK=y`, ship a minimal seccomp profile, remove interactive dev services). Plus ongoing patches to track upstream releases (~1-2 days per upstream version bump).
- **Decide v0.1 vs v0.2.** Is the hardened fork a v0.1 requirement, or can v0.1 ship with the revocation-latency-only story and defer the fork to v0.2+? Current lean: defer to v0.2, because v0 + v0.1 can share the same stock-sandbox story and v0.2 can be marketed as "now with kernel-enforced isolation."
- **Prepare for the Kai conversation.** Although the hardened fork is agent-infra's domain (not Litentry's), the revocation-latency fallback depends on Heima TEE supporting fast revocation (Q9 in `heima-open-questions.md`). If Heima revocation is slow (> 30 seconds), the v0 security story is much weaker and the hardened fork becomes a v0 blocker instead of a v0.2 nice-to-have.

#### 8.2.4 Observability and documentation (throughout)

- **Audit log indexer** — a Subsquid or Subquery indexer that turns Heima extrinsics into a queryable per-owner, per-agent, per-service view. Used by `agentkeys usage` and (later) the web GUI.
- **Metrics and telemetry** — careful here: any telemetry AgentKeys collects is a "monitoring info in transmission" concern. Default should be **no telemetry**. Opt-in if needed.
- **Threat model document** — explicit writeup of what AgentKeys does and does not protect against (host root, daemon RCE, cold-boot RAM, side channels, etc.). The Round 6 "what this does NOT protect against" section in §3.3a is a starting point.
- **Reproducible builds** — so users can verify the published daemon binary matches the open-source code.

## 9. v0 demo suite — four demos, priority order (Round 8)

All four demos are in scope for v0. Priority order for build and for the meetup talk narrative: **1 → 2 → 3 → 4**. If time collapses, ship Demo 1 first; it is the one that most viscerally distinguishes AgentKeys from 1Password.

### Demo 1 (highest priority) — Multi-agent isolation + env-var injection into openclaw

**About openclaw:** [github.com/openclaw/openclaw](https://github.com/openclaw/openclaw) — an open-source **local AI assistant** that needs API keys for LLMs (OpenRouter, Anthropic, OpenAI, etc.) and for other service APIs (search, tools) passed in as environment variables at startup. It is a canonical example of the 80% env-var-injection consumption pattern described in §3.4a: a real, forkable, non-AgentKeys-aware CLI that AgentKeys can wrap transparently via `agentkeys run -- openclaw ...`. Because it's open source, the demo is reproducible — any viewer can fork it, point AgentKeys at it, and verify the flow.

**Setup:** two fresh agent-infra sandboxes, each running a separate AgentKeys daemon attached to a different agent (agent-A and agent-B). Provisioning done beforehand: agent-A has OpenRouter + Anthropic credentials; agent-B has Brave Search credentials only.

**Script:**

```bash
# on sandbox-A (agent-A attached; wallet 0x9c3e...)
$ agentkeys list
  openrouter     ✓
  anthropic      ✓
$ agentkeys run -- openclaw --task "summarize github.com/litentry/heima"
  # openclaw CLI reads OPENROUTER_API_KEY and ANTHROPIC_API_KEY from env,
  # runs, returns a summary. No human ever typed an API key.

# now the same user tries to grab brave on sandbox-A
$ agentkeys read brave-search
  ERROR: agent 0x9c3e... is not authorized to read brave-search.
         DENIED by Heima policy (extrinsic 0x3f2a... at block 1,234,567)

# switch to sandbox-B (agent-B attached; wallet 0x1e84...)
$ agentkeys run -- some-search-tool --query "substrate pallets"
  # Works via BRAVE_SEARCH_API_KEY injection. No access to agent-A's stuff.
```

**Then open the Heima block explorer** in a browser and show the raw extrinsics: two distinct wallet addresses, each only reading the services it's provisioned for, with the DENIED attempt recorded on-chain too.

**Punchline:** *"Two agents, two wallets, two scopes, one chain, zero API keys in any env file on disk. openclaw didn't have to know anything about AgentKeys — it just saw `OPENROUTER_API_KEY` in its environment like always. 1Password structurally cannot do this: service account scope is frozen at creation, audit logs live in their database, and the bootstrap requires a bearer token in an env var that outlives the VM."*

**Why this is the #1 demo:** it lands *four* of the system's distinguishing properties in one 90-second sequence — env-var injection compat with existing tools (no modifications), per-agent scope enforcement, on-chain audit with public verifiability, and DENIED being an auditable event rather than a silent failure. Every other demo builds on the architecture this one establishes.

### Demo 2 — Recovery (sandbox dies, wallet survives)

> ⚠️ **Command syntax updated.** The original `agentkeys attach agent-A` is superseded by the rendezvous model: the new sandbox runs `agentkeys pair` to get a pair-code, and the master approves via `agentkeys approve <pair-code>`.

**Setup:** agent-A is running happily in sandbox-A with the daemon holding its session key, having read a few credentials (visible in the block explorer).

**Script:**

```bash
# sandbox-A is destroyed (close the tab, docker kill, whatever — destructive)
# now spin up a completely fresh sandbox, sandbox-A'
$ curl -sSL get.agentkeys.dev | sh

# NEW sandbox initiates pairing:
$ agentkeys pair --agent 0x9c3e...f4a2
  Pair code: BLUE-FISH-4729
  Waiting for master approval...

# On the master device:
$ agentkeys approve BLUE-FISH-4729
  # Google OAuth popup → master authorizes →
  # Heima mints a new session key scoped to 0x9c3e... →
  # delivered to sandbox-A' via Heima relay

# Back on sandbox-A':
  Paired. Session key received.
$ agentkeys run -- openclaw --task "continue where we left off"
  # same credentials, same wallet, new session, zero data loss
```

**Then open the block explorer** and point at wallet `0x9c3e...f4a2`: pre-crash reads + new reads continue from the same wallet. The session key (internal) rotated, the public identity (wallet) persisted.

**Punchline:** *"The sandbox was the disposable thing. The wallet, the provisioned credentials, and the full audit trail survived it. If this had been 1Password, I'd have had to re-create the service account, redeploy the token, and the audit would show a gap in ownership."*

### Demo 3 — Provisioning-in-action with OpenRouter (using USDC, not x402 yet)

> ⚠️ **Command syntax updated.** The original `agentkeys setup --fund` is now split: credential storage uses `agentkeys store` (CLI, human-driven) or `agentkeys.provision` (MCP tool, agent-driven). Funding remains `agentkeys fund`. Session delivery to the sandbox uses the rendezvous model (`agentkeys pair` + `agentkeys approve`), not direct HTTP push.

**Why OpenRouter specifically:** OpenRouter accepts **USDC deposits** to fund its usage-based billing. This means the full provisioning + funding + consumption loop can be demonstrated end-to-end using the same crypto rails AgentKeys is already committed to. (Note: OpenRouter is **not x402-native** at time of writing — funding is a regular USDC transfer to an OpenRouter-controlled deposit address, not an x402-signed HTTP request. The demo should be explicit about this distinction and note that x402-native services would shorten the flow further.)

**Script:**

```bash
# master CLI on the Mac
$ agentkeys balance
  master wallet 0x4a7b...c391  balance 10.00 USDC

# Step 1: Provision credentials (via MCP tool or CLI)
$ agentkeys store agent-A --services openrouter
  # OR: agent calls agentkeys.provision(services=["openrouter"]) via MCP
  #
  # spawns a disposable provisioner sandbox with a visible browser.
  # SCREEN-RECORD this:
  #   → provisioner opens openrouter.ai
  #   → navigates to sign up, uses a burner email
  #   → fetches the verification code from the email backend
  #   → creates the account, reaches the API key page
  #   → copies the key, encrypts it to Heima shielding key
  # → provisioner sandbox dies.

# Step 2: Fund the agent
$ agentkeys fund agent-A 2
  # transfers 2 USDC from master wallet to OpenRouter's deposit
  # address (regular ERC-20 transfer, pending x402 support)

$ agentkeys list
  openrouter  ✓  (funded: 2.00 USDC deposited to OpenRouter)

# Step 3: Pair the sandbox (rendezvous model)
# On the agent sandbox:
$ agentkeys pair --agent 0x9c3e...f4a2
  Pair code: RED-HAWK-8814
# On master:
$ agentkeys approve RED-HAWK-8814

# Step 4: Use it
$ agentkeys run -- openclaw --task "write a haiku about Substrate"
  # openclaw picks up OPENROUTER_API_KEY, calls OpenRouter, returns.
```

**Punchline:** *"That OpenRouter account was created by a robot two minutes ago. It's real. The API key is real. The USDC payment is on-chain. You can verify all of it — the account creation via the browser replay, the USDC transfer via the block explorer, the credential fetch via Heima's audit log."*

**Honest caveat in the talk:** x402 native support is in progress; OpenRouter takes USDC directly today, so we use regular ERC-20. Once OpenRouter (or the upstream service in question) adds x402, the funding command can sign an x402 HTTP payment inline and skip the deposit-address step entirely.

### Demo 4 — Cost transparency with per-wallet spend breakdown

**Script:**

```bash
# fund master
$ agentkeys fund-master 10  # 10 USDC to master wallet

# fund a few agents
$ agentkeys fund agent-A 3
$ agentkeys fund agent-B 2
$ agentkeys fund agent-C 1

# let them run for 60 seconds
$ ...

# cost report
$ agentkeys usage
  ┌─────────────┬──────────────┬────────┬──────────┬──────────┐
  │ agent       │ wallet       │ calls  │ service  │ spent    │
  ├─────────────┼──────────────┼────────┼──────────┼──────────┤
  │ agent-A     │ 0x9c3e...    │    14  │ openrouter │ 0.82 USDC │
  │ agent-A     │ 0x9c3e...    │     3  │ anthropic │ 0.45 USDC │
  │ agent-B     │ 0x1e84...    │    22  │ brave    │ 0.18 USDC │
  │ agent-C     │ 0x7fab...    │     5  │ openrouter │ 0.27 USDC │
  └─────────────┴──────────────┴────────┴──────────┴──────────┘
  totals match block explorer: https://heima.subscan.io/account/0x...
```

**Punchline:** *"Per-agent, per-service spend. Directly on-chain. No reconciliation with an invoice, no trust in a vendor dashboard — the master wallet's outflow is the ground truth, and you can verify every row against the block explorer in real time."*

### Demo composition for the meetup talk

Five-minute format: **Demo 1 (2 min) → Demo 3 (2 min) → Demo 4 (30 sec)**. Demo 2 (recovery) is left as a "bonus slide" — mentioned verbally with a screenshot but not live-demoed unless there's time. Why: Demo 1 establishes the architecture, Demo 3 proves the auto-provisioning works on a real third-party service, Demo 4 closes with the ledger transparency. Recovery is best understood as "you already believe this is true from Demos 1-3" at that point.

### Open TODOs tied to the demo suite

- **Burner email integration for Demo 3** — pick one (SimpleLogin or Gmail plus-addressing for v0, migrate to Workspace later)
- **Playwright script for OpenRouter signup** — maintain against the live signup flow, CI test weekly
- **OpenRouter USDC deposit address discovery** — how does the provisioner know where to send USDC? Pull from OpenRouter's API or their settings page?
- **Block explorer URL template** for Heima — need the canonical subscan or equivalent
- **openclaw CLI verification** — `github.com/openclaw/openclaw` is a local AI assistant consuming LLM + service API keys from the environment. Concrete verification tasks: (a) clone the repo, read its README/config for the exact env var names it reads (likely `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, possibly `OPENAI_API_KEY`, search provider keys, etc.), (b) confirm it starts cleanly with those env vars set and nothing else, (c) confirm it does NOT require a config file with keys baked in (if it does, add a `--env-only` mode upstream or use `agentkeys inject -i config.tmpl -o config` as a fallback analogous to `op inject`). This is the single external dependency for Demo 1 to work, so it's worth doing first.

## 10. Ambiguity status after Round 8


| Dimension   | Score    | Notes                                                                                                                         |
| ----------- | -------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Goal        | 0.80     | Writeup format still slightly loose but the goal statement itself is crisp                                                    |
| Constraints | 0.92     | Round 7 daemon decision + Round 8 CLI UX + env-var model — all major constraints resolved                                     |
| Criteria    | **0.78** | All four demos specified with priority order. Only gap: empirical verification of openclaw + OpenRouter flows against reality |


**Ambiguity: ~17%** — **BELOW THE 20% THRESHOLD. Sub-interview ready to close.**

Remaining non-blocking cleanup work (can happen during implementation, not before):

- §3.3a kernel-capability prerequisites against agent-infra/sandbox (6 items)
- §6 items 5-6 (audit event contents, Heima TEE scoped-session support)
- §8.1 writeup format
- §9 open TODOs for the demo suite (openclaw verification, burner email choice, OpenRouter deposit discovery)

### What "close the sub-interview" means

At this point the auth-layer sub-analysis is tight enough to hand off to a planning stage (e.g., `/omc-plan --consensus --direct` or a manual technical spec). The next `2-step-analysis.md` should cover: the MCP adapter schema, the CLI command surface, the daemon's internal Rust API, the Heima TEE work items broken down for a conversation with Kai, and the Playwright provisioning templates for OpenRouter + Brave.

---

*This is a living checkpoint. Updated through Round 8 of the auth-layer sub-interview, with Round 12/13 reality-check annotations and Round 13+ rendezvous model updates applied 2026-04-09. Ready to hand off to 2-step-analysis.md for implementation planning.*