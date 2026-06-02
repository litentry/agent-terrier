# Key Security in AgentKeys

> **Updated 2026-04-26 — v0.1 storage column.** §1 used to say "v0.1 Heima: encrypted blob in `pallet-secrets-vault` (on chain)." That target is superseded. The canonical v0.1 design moves ciphertext **off-chain** (S3) under per-epoch DEKs that rotate; chain holds only pointer + hash. See [`docs/spec/threat-model-key-custody.md`](../spec/threat-model-key-custody.md) and [`docs/stage8-wip.md`](../stage8-wip.md). Stage 9 (memory hygiene; renumbered from Stage 8 in the same change) is unaffected.

Reference notes on how AgentKeys stores session tokens and user credentials, what the macOS Keychain prompt behavior actually means, and why our architecture looks different from 1Password-style local vaults.

These notes were compiled from a Stage 4 manual-test debugging session and are meant to answer the questions real testers and reviewers ask when they first see prompts pop up.

---

## 1. Two-tier storage model

AgentKeys splits secrets across two tiers with different security properties. Every discussion about "where are credentials stored" and "why did the keychain prompt me" resolves to which tier you are touching.


| Tier                        | What it is                                                                                                                | Where it lives (v0 mock)                                                                     | Where it lives (v0.1 Heima)                                                                                    |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| **Master session key**      | The CLI's own bearer token, used in `Authorization: Bearer ...` to authenticate to the backend. One per user-device pair. | OS keychain via `keyring-rs` (macOS Keychain / Windows Credential Manager / Linux libsecret) | Same                                                                                                           |
| **User-stored credentials** | The API keys the user's agents actually consume — `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, etc.                         | Encrypted blob in backend SQLite (axum + rusqlite)                                           | **Off-chain ciphertext in S3** under per-epoch DEK; chain holds `(blob_pointer, ciphertext_hash, epoch)` via `pallet-vault-pointers` (Stage 8). DEK wrapped under TEE shielding key, unwrapped per-request, destroyed on epoch rotation. |


Reference spec lines:

- `docs/spec/tech-brief.md:80` — "Client encrypts credential blobs to the TEE's public shielding key before storage — TEE decrypts on read."
- `docs/spec/1-step-analysis.md:105-108` — the session-tier table (master session key in OS keychain, agent session in sandbox FS).
- `docs/spec/1-step-analysis.md:76` — the direct contrast with 1Password: "we don't hand users a CLI to read secrets. We provision credentials on their behalf, store them in a TEE, and deliver them through MCP calls from agents. The CLI is for management, not for data-plane access."

The important implication: **user credentials never sit on the user's disk in plaintext**. Local storage is reserved for the session token that authenticates the CLI to the backend, and that is the only thing the keyring sees.

---

## 2. Where the auth token lives

> **Correction (2026-04-12):** An earlier version of this section was titled "Why the session key goes in the OS keychain" and described storing a session private key in the OS keychain via `keyring-rs`. After verifying against the actual Heima source (`tee-worker/omni-executor/core/src/auth/auth_token.rs`), Heima uses **JWT-format session tokens**, not session keypairs. The client holds a signed session token string — a bearer token, not a private key. This changes the storage requirements significantly.

### v0 (current mock): OS keychain or fallback file

The v0 mock backend uses a random bearer token (not a JWT, but functionally similar — an opaque string). The CLI stores it via `keyring-rs` in the OS keychain, with a file fallback at `~/.agentkeys/session.json`.

Implementation: `crates/agentkeys-cli/src/session_store.rs`. Keyring service is `"agentkeys"`, account is `"session"`. The save/load paths are wrapped in a 2-second timeout and fall back to the file path on keyring error.

This is what caused the macOS Keychain double-prompt issue that started this investigation (see Section 4). The keychain stores the bearer token as a "generic password" item, and accessing it from a different binary triggers ACL prompts.

### v0.1 (Heima): session token (keychain recommended, plain file as fallback)

Under the session token model, the client holds a signed token string like `eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIweD...` (JWT format on the wire). This is:

- **Not a private key** — it's a signed bearer token. Leaking it gives the attacker temporary access (until expiration), but they cannot forge new tokens or sign extrinsics.
- **Stateless** — the TEE verifies the session token cryptographically (RSA signature + expiration). No session table lookup needed.
- **TTL** — configurable via `AuthOptions.expires_at`. **AgentKeys policy: 30 days** (Heima SDK default is ~24h — AgentKeys sets the longer TTL explicitly). A 30-day bearer is high-value and warrants keychain protection + Stage 8 memory hygiene.
- **Reissue-able** — re-authenticate and get a new session token.

However, a session token is still a **bearer credential** — anyone with the string can impersonate the user until it expires. The blast radius is bounded (TTL + on-chain revocation list), but it's not zero. Storage recommendations:


| Context                   | Storage                                          | Why                                                                                                                                                                                                                                            |
| ------------------------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Master CLI on desktop** | **OS keychain** (recommended default)            | Malware-as-same-user is a real threat on developer machines. Keychain provides app-level ACL that plain files don't. The double-prompt issue from Section 4 only affects external inspectors (`security(1)`), not the AgentKeys binary itself. |
| **Daemon on desktop / Mac mini / Raspberry Pi** | **OS keychain** (per [#12](https://github.com/litentry/agentKeys/issues/12)), wallet-namespaced account (`service=agentkeys, account=daemon-<wallet>`) | macOS Keychain, gnome-keyring, and KDE Wallet are all reachable via `keyring-rs`. Wallet-based namespacing lets N daemons coexist on one host (multi-agent demo, Demo 1). |
| **Daemon in Docker/cloud sandbox** | **Plain file** (`~/.agentkeys/daemon-<wallet>/session.json`, mode 0600) | No keychain available in most sandbox environments. Kernel hardening (Stage 3: seccomp, memfd_secret, etc.) compensates. `AGENTKEYS_SESSION_STORE=file` forces this path. |
| **CI / testing**          | **Env var or plain file**                        | Ephemeral environment, no keychain. Set `AGENTKEYS_SESSION_STORE=file`.                                                                                                                                                                        |


The v0 code's dual-path structure (`session_store.rs`: try keychain first, fall back to file) is correct and should be preserved for v0.1 — just storing a session token string instead of a session JSON blob.

What the session token model **does** eliminate (compared to the private-key model):

- The client cannot **forge new tokens** (RSA signing key is in the TEE)
- The client cannot **sign chain extrinsics directly** (wallet key is in the TEE) — the TEE is a mandatory gateway that enforces rate limits and scope on every call, and an attacker with a stolen token cannot bypass it
- **Revocation is cleaner** — add account to on-chain revocation list (~6s) rather than rotate keys
- No **client-side signing code** needed (no `subxt`, no extrinsic building — just send a string in a header)

What the session token model does **NOT** eliminate (corrected after confirming 30-day TTL):

- `**memfd_secret` for the session token in the daemon** — a 30-day bearer credential in long-lived process memory is a high-value target, same as a private key. Restored to Stage 8 Priority A.
- `**zeroize`/`SecretString` for the session token** — same reasoning. Restored to Stage 8 Priority A.
- **OS keychain as recommended default** — a 30-day bearer warrants keychain protection (app-level ACL) on the master CLI.
- **The urgency of the keychain double-prompt fix** — unchanged, because a 30-day token leak is high-blast-radius.

See `[wiki/session-token.md](./session-token.md)` for the full session token definition, lifecycle, and storage recommendations.

---

## 3. Why user credentials are NOT in the OS keychain

Three candidate storage models were considered. Only one gives us the security properties the product actually needs.

### Option A — OS keychain (like `git-credential-osxkeychain`)


|      |                                                                                                                                                                                                                                                                                                                                                                                             |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Pros | Zero network dependency; OS-level encryption integrated with login; no separate unlock step                                                                                                                                                                                                                                                                                                 |
| Cons | Single-device (Keychain iCloud sync is Apple-only and explicitly not recommended for dev credentials); no scoping (any process that looks like agentkeys reads everything); cross-platform API differences (macOS Keychain vs libsecret vs Windows Cred Mgr are not feature-parity); no audit trail; no server-side revocation; sandbox apps can't share credentials across user boundaries |


### Option B — Encrypted file (1Password-style local vault)


|      |                                                                                                                                                                                                                                                                                                                                              |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Pros | Cross-device sync is easy (just sync the file); cross-platform portable (same format everywhere); user controls unlock policy; trivial backup                                                                                                                                                                                                |
| Cons | Rolls your own crypto surface (mitigated by proven libraries); single-process access semantics; once unlocked, any code in that process reads everything; secret material lives on disk (FDE is your only backstop); no server-side revocation (file leak = permanent compromise of every credential ever in it); no server-side audit trail |


### Option C — Remote backend + TEE (our plan)


|      |                                                                                                                                                                                                                                                                                                                                                |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Pros | **Scope enforcement** server-side (a compromised daemon cannot bypass the TEE); **revocation** is a real kill switch, not a local delete; **audit log** is tamper-evident (on-chain for Heima); multi-device by default; credentials never reside on the user's disk; blast radius of a stolen session token is time-bounded and scope-bounded |
| Cons | Requires network connectivity; per-fetch latency (mitigated by caching in agent sandboxes); trust in the backend or TEE attestation; cannot run fully air-gapped without a fallback                                                                                                                                                            |


### Side-by-side


| Property                     | **A. OS keychain**                                      | **B. Encrypted file**                  | **C. Remote + TEE**                                 |
| ---------------------------- | ------------------------------------------------------- | -------------------------------------- | --------------------------------------------------- |
| Cross-platform               | Painful (three different APIs)                          | Easy                                   | Easy                                                |
| Multi-device sync            | Hard, Apple-only                                        | Easy (file sync)                       | Trivial (server-side truth)                         |
| Scope enforcement            | None                                                    | Weak (in-memory only)                  | **Strong** (TEE enforces)                           |
| Revocation is a real button  | No (local delete only)                                  | No (already-exfil'd items stay leaked) | **Yes** (≤ 1 block on Heima)                        |
| Audit trail                  | None                                                    | None                                   | **Full, tamper-evident**                            |
| Offline / air-gapped         | Yes                                                     | Yes                                    | No                                                  |
| Casual extraction resistance | Weak (`security find-generic-password -w` + one prompt) | Weak once unlocked                     | **Strong** (credentials never on disk in plaintext) |
| Trust boundary               | User's machine                                          | User's machine                         | User's machine + backend/TEE                        |
| Fits agent sandboxes?        | No (sandbox FS is ephemeral)                            | No (sandbox FS is ephemeral)           | **Yes** (remote fetch over MCP)                     |
| Product-market fit           | `gh`, `aws`, `git`                                      | 1Password, Bitwarden (human vaults)    | Designed for non-interactive AI agents              |


### Why option C wins for AgentKeys

Three reasons, in weight order:

1. **Scope enforcement + revocation + audit cannot be simulated locally.** The moment a local vault is readable by the calling process (which it must be, to be useful), all three of those guarantees collapse to best-effort. A TEE that decrypts based on server-verified scope is the only way `agentkeys revoke` is a real kill switch and not a suggestion. `tech-brief.md:127` explicitly marks TEE-side scope enforcement as "P0 — security claim depends on this."
2. **Agent sandboxes are the deployment reality.** Agents run in Docker sandboxes, ephemeral cloud VMs, CI runners. Places where a persistent local vault either doesn't exist or doesn't survive across runs. Remote credential delivery over MCP matches how the product is actually used.
3. **1Password is for humans, AgentKeys is for agents.** 1Password's UX — master password, biometric unlock, copy-paste — is exactly what an AI agent cannot do. Ours — scoped session, MCP delivery, `agentkeys run` env injection — is exactly what a human doesn't need. Copying 1P's model would fight both directions at once.

---

## 4. Keychain prompt behavior: the double-prompt explained

During manual testing of Stage 4, `ak-keychain-show` (a shell helper defined in `docs/manual-test-stage4.md:45`) triggers **two** macOS Keychain dialogs per invocation:

1. *"security wants to access key 'agentkeys' in your keychain"*
2. *"security wants to use your confidential information stored in 'agentkeys' in your keychain"*

This is **not a bug in agentkeys**. It is a direct consequence of how macOS's Security framework authorizes access to a keychain item created by one binary and read by another.

### Mechanism

`ak-keychain-show` expands to `security find-generic-password -s agentkeys -a session -w`. That shells out to `/usr/bin/security`, which is a completely different binary from `agentkeys` itself. When `agentkeys init` created the keychain item via `SecKeychainAddGenericPassword`, macOS automatically placed the `agentkeys` binary's code-signing identity on the item's ACL, for both authorization operations:

- **Reference the item** — look it up, hold an item ref
- **Decrypt the payload** — read the plaintext password bytes

When `/usr/bin/security` tries to read the item:

- It is not on either ACL entry (different code-signing identity)
- macOS issues two separate authorization checks, one per operation
- Each check is gated by a user prompt
- Two prompts result, with distinct wording for the two operations

Click "Always Allow" on **both** dialogs and subsequent `security(1)` calls become silent, because the ACL now includes `security(1)` for both ops.

### Evidence in the test itself

`ak-keychain-meta` (which runs `security find-generic-password` without `-w`) ran with **no prompt** in the same test session. That is because attribute reads do not require decrypt authorization — they only need the item-reference check, which passes silently because `security(1)` is already trusted for that operation from the first run. This confirms the two-prompt behavior is per-operation, not per-invocation.

### Why `agentkeys` itself prompts zero times

The real `agentkeys` CLI does not hit this problem because it **is** the creator of the item. Verified empirically:

```bash
./target/debug/agentkeys --backend http://localhost:8090 init --mock-token real-cli-test
# Initialized. Wallet: 0x44d350f9d65c2f35b2a28f8d78fbd5a27a7ca111
# 1 prompt (first write from an ad-hoc-signed binary). Click Always Allow.

./target/debug/agentkeys --backend http://localhost:8090 usage 0x44d350f9d65c2f35b2a28f8d78fbd5a27a7ca111
# 0 prompts — silent read. The creator inherits full ACL trust.
```

The zero-prompt property is the default for any app that reads its own keychain items. `gh auth status` after `gh auth login`, `aws-vault exec`, `docker login` — all the same mechanic.

### Cargo debug builds complicate this during development

Each `cargo run` or `cargo build` that changes sources produces a new binary at `target/debug/agentkeys` with a **fresh ad-hoc code signature**. The ACL treats it as a new app and re-prompts. Two workarounds:

1. **Build once, run the binary directly.** As long as you do not recompile between calls, the identity stays stable and reads are silent.
2. **Ship release binaries with stable code-signing.** `cargo install --path crates/agentkeys-cli` or a properly signed `.pkg`. Real end users installing a signed release see one prompt at first `init` and zero afterwards, and the trust persists across upgrades that preserve the Designated Requirement.

---

## 5. The CLI deliberately does not expose the session token

There is no `agentkeys session show`, no `dump`, no `whoami --token`. Look at the subcommand list in `crates/agentkeys-cli/src/main.rs:30-132`: `init`, `store`, `read`, `run`, `revoke`, `teardown`, `usage`, `link`, `approve`, `feedback`. No way to print the bearer token.

This is the same pattern as `gh`, `aws`, `gcloud`, `docker login`. The bearer token is an internal detail the user should never need to see, and every way to expose it is a way to accidentally leak it — pasted into a chat, committed to a dotfile, echoed in a log, shown in a screenshot.

`ak-keychain-show` exists only in the manual-test doc as a debug inspector; it shells out to `/usr/bin/security` because there is no agentkeys-native way to retrieve the session blob. This is a test-tooling limitation, not a product limitation. End users never run it.

### The real round-trip proof

Test 0 in `docs/manual-test-stage4.md` verifies keychain storage correctness by running a second `agentkeys` process against the same keychain entry. That check — *"a second CLI invocation can load the session and call `usage`"* — is the real evidence the keychain round-trip works. The `ak-keychain-show | jq` line earlier in the same test is noise the test doesn't actually need, and it is the source of the double-prompt complaint.

Fix proposal for the test doc: add a minimal `agentkeys whoami` subcommand that prints non-sensitive session metadata (wallet, scope, expiry) and never prints the token. Replace `ak-keychain-show | jq .wallet_address` with `agentkeys whoami`. Zero prompts, zero token exposure, clean native path. See "Future hardening options" below.

---

## 6. The `agentkeys read` escape hatch

`agentkeys read [--agent <wallet|alias>] <service>` prints a stored credential to stdout. This is intentional — it is the debug / migration / emergency-retrieval path, matching `pass show`, `op item get`, `vault kv get`. Omit `--agent` to default to the current session wallet.

Important distinction: this applies only to **user-stored credentials** (tier 2), not to the **session bearer token** (tier 1). The session token stays invisible; user credentials are retrievable.

### Risk accepted

A malicious process running as the user can call `agentkeys read --agent 0xAGENT anthropic` and exfiltrate the key. This is **mitigated, not eliminated**:

- **Audit log** — every `read` writes a row to `audit_log`. See the five `INSERT INTO audit_log` sites in `crates/agentkeys-mock-server/src/handlers/credential.rs`. Compromise leaves a trail.
- **Session scope** — `session.scope.services` limits which services the session can read. A session scoped to `openrouter` cannot pull `anthropic`.
- **TTL** — stolen sessions expire in 24h (v0 mock backend default); 30 days under the v0.1 AgentKeys policy on Heima.
- **Revocation** — `agentkeys revoke` kills a session instantly on the v0 mock (SQLite flag flip); ~6s on v0.1 Heima (one block to update the on-chain revocation list). See [#17](https://github.com/litentry/agentKeys/issues/17) for the pending CLI fix.
- **High-value release gate** — `AuthRequestType::HighValueRelease` in the mock server is designed to wrap sensitive credentials in an explicit approval step (human-in-the-loop), similar to 1Password's unlock-per-access model. Not yet wired on the CLI `read` path.

### Preferred usage

For production agent execution, use `agentkeys run` instead of `agentkeys read`:

```bash
agentkeys run --agent 0xAGENT -- python my_agent.py
```

`run` injects the credential as a `SERVICE_API_KEY` env var into the child process without ever crossing the user's stdout, terminal buffer, or shell history. `read` is a debug path; `run` is the production path.

---

## 7. Daemon credential lifecycle and the two layers of hardening

The daemon (`agentkeys-daemon`, component #2 in `docs/arch.md:50`) is the long-lived process that holds credentials between backend fetches and agent deliveries. It is a richer target than the CLI and gets a much stronger hardening posture, split across two stages of work.

### The credential's path through the daemon

```
agent calls MCP get_credential(service)
   ↓
daemon validates session + scope
   ↓
daemon POSTs /credential/read to backend  ← session.token in Authorization header
   ↓
backend (mock SQLite or Heima TEE) decrypts blob, returns plaintext
   ↓
plaintext lands in daemon heap (Vec<u8>)  ← MEMORY HYGIENE WINDOW STARTS
   ↓
daemon serializes into MCP tool response
   ↓
MCP framing writes response over stdio / Unix socket
   ↓
daemon SHOULD wipe local copy and any intermediate buffers  ← gap today
   ↓
agent process reads the credential out of its own MCP client
```

Two distinct attack surfaces are open during the "memory hygiene window":

1. **External probes against the daemon process** — ptrace, `/proc/pid/mem`, swap files, core dumps, co-tenant memory scraping. These are kernel-mediated and require kernel-mediated defenses.
2. **Internal lifetime bugs** — credential bytes lingering in freed-but-unscrubbed heap allocations, cached longer than the agent needs, copied into intermediate buffers that nobody zeroes, or leaking into core files if the daemon crashes mid-handler. These are process-internal and require Rust-level discipline plus a secure allocator.

The two surfaces need two different mitigation layers, and they map directly to two stages of work in the plan.

### Layer 1 — Kernel hardening (already planned in Stage 3)

`docs/archived/development-stages-v2-2026-04.md` and `docs/arch.md:70` already specify the kernel-level defenses. They are required deliverables for Stage 3 (the daemon stage), with passing tests gating stage completion. Reproduced here for reference:


| Feature                                          | What it blocks                                                            | Verified by                                         |
| ------------------------------------------------ | ------------------------------------------------------------------------- | --------------------------------------------------- |
| `memfd_secret()` for runtime session key         | `/proc/pid/mem` reads of the session token                                | `daemon::memfd_secret_or_fallback`                  |
| `mlock2(MCL_CURRENT                              | MCL_FUTURE)`                                                              | Swap writes that would persist secrets to disk      |
| `prctl(PR_SET_DUMPABLE, 0)`                      | Core dumps + `/proc/pid/mem` reads from same UID                          | `daemon::dumpable_off`                              |
| `prctl(PR_SET_NO_NEW_PRIVS, 1)`                  | setuid/file-cap privilege escalation from a child                         | `daemon::no_new_privs`                              |
| Self-installed seccomp-bpf                       | `ptrace`, `process_vm_readv`, `kcmp`, `keyctl`, `/dev/mem`, `/proc/kcore` | `daemon::seccomp_installed` (filter mode 2)         |
| Capability drop to empty effective set           | Misuse of any inherited Linux capability                                  | `daemon::caps_dropped` (`CapEff: 0000000000000000`) |
| Session file at `~/.agentkeys/session` mode 0600 | Other-user reads of the at-rest mirror                                    | `daemon::session_file_permissions`                  |


This is **all kernel-side**. It assumes the daemon's own code is well-behaved and that credential bytes do not linger in heap allocations. That assumption is the gap Stage 8 closes.

### Layer 2 — Memory hygiene and credential lifecycle (planned in Stage 8)

`docs/archived/development-stages-v2-2026-04.md` Stage 8 (added after this Stage 4 investigation) covers the process-internal hardening. **Priority A items shrink the dominant exposure window — the agent-side window — not the daemon window.** This is the corrected framing after the Stage 4 review caught the original ranking inverting these.


| Priority A item                                                                                    | What it blocks                                                                                                                                                    | Verified by                                                                   |
| -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `zeroize` / `SecretString` wrappers on credential and session-token types                          | Plaintext lingering in freed heap pages until reallocation. **Foundational** — every other item assumes credentials flow through these types.                     | `daemon::credential_zeroize_on_drop`, `types::session_token_is_secret_string` |
| Daemon-mediated `cmd_run` for agentkeys-managed runtimes                                           | Credentials lingering in long-lived parent address spaces — daemon forks child, sets env in child, drops parent copy before `exec`. **Shrinks the agent window.** | `daemon::mediated_run_drops_parent_copy`                                      |
| `memfd_secret`-via-SCM_RIGHTS delivery for `agentkeys.get_credential` (agentkeys-managed runtimes) | Credentials entering the agent's regular heap — agent reads once from fd, closes, never touches `String`. **Shrinks the agent window** for the dominant MCP path. | `daemon::scm_rights_delivery_no_heap_copy`                                    |
| Idle credential eviction (configurable TTL, default 60s)                                           | Cached credentials surviving the agent's actual idle window                                                                                                       | `daemon::idle_eviction_fires`                                                 |
| Daemon-internal audit log of credential lifecycle events                                           | Detection of suspicious read patterns within a single agent session. Foundational for detection regardless of which mitigations are in place.                     | `daemon::audit_lifecycle_logged`                                              |


**Priority B items shrink only the ~50ms daemon window.** They are still worth doing — compromise of the long-lived daemon process is a real threat, and per-call drop removes the "retroactive enumeration" attack — but their marginal security win is small compared to Priority A. The Priority B set includes:

- Drop credential from daemon memory immediately after MCP delivery (*demoted from Priority A* because it only defends against daemon compromise + retroactive enumeration, not against the dominant agent-side exposure window)
- `setrlimit(RLIMIT_CORE, 0)`
- `pkey_alloc` + `pkey_mprotect` per-credential page protection
- Secure-scrubbing global allocator (`mimalloc` secure mode)
- `ptrace_scope` runtime check
- CI binary-hardening verification (`checksec`)
- Anti-debugger check (`TracerPid`)

**Priority C items** are reserved for v0.2+ generalizations: extending `memfd_secret`-via-SCM_RIGHTS to upstream agent runtimes that don't currently support fd-based credential reads, and generalizing daemon-mediated `cmd_run` to arbitrary parent processes. Both require runtime cooperation that we can't unilaterally provide.

See `docs/archived/development-stages-v2-2026-04.md` Stage 8 section for the full breakdown, the unit test matrix, and the reviewer E2E checklist.

### Where the credential actually lives

The reason for the priority correction is the actual exposure timeline:

```
backend         daemon                    agent
─────────────────────────────────────────────────────────────────
                  fetch ────►
       ◄──── plaintext (~50ms)
                  serialize MCP (~1ms)
                  send over socket ────►
                                    agent decodes
                                    agent uses credential for
                                    the entire task (minutes–hours)
                                    agent exits
─────────────────────────────────────────────────────────────────
       DAEMON WINDOW: ~50ms     AGENT WINDOW: minutes to hours
```

The credential's dominant residence is in **agent memory** after delivery, not in daemon memory before delivery. The agent window is 1000x to 100,000x longer. Items that only shrink the daemon window are defense in depth; items that shrink the agent window (`memfd_secret`-via-SCM_RIGHTS, daemon-mediated `cmd_run`) are the dominant defense. The original Stage 8 plan inverted this and was corrected.

### Why both layers are necessary

Stage 3 alone leaves the daemon vulnerable to internal bugs: a credential fetched from the backend lands in a `Vec<u8>`, gets serialized into the MCP response, and the original `Vec` drops without being scrubbed. The freed pages still hold plaintext until reallocated. If a later panic produces a backtrace or a debug print captures the wrong buffer, the credential leaks via a path that no kernel filter can catch.

Stage 8 alone leaves the daemon vulnerable to external probes: a process with `CAP_SYS_PTRACE` or write access to `/proc/pid/mem` can pull memory directly without going through the daemon's `Drop` impls. `zeroize` doesn't help if an attacker reads the bytes before drop runs.

Both layers stack: kernel features make external reads impossible, memory hygiene shrinks the window during which the credential exists in any readable form. The combination is what gets us to "credentials are not extractable from a running daemon without breaking the TEE attestation."

### What the CLI gets

The CLI is **deliberately less hardened** than the daemon because it is short-lived. Stage 8 still covers it, but with lower priority items: `zeroize` wrapping (cheap, consistent), `prctl(PR_SET_DUMPABLE, 0)` on startup, `whoami` and idempotent `init` for UX, plus optional Touch-ID gating and DEK+file storage as platform-specific extras. The CLI's defense is mostly "exit fast and let the OS reclaim memory," not "actively scrub during operation."

---

## 8. Why zero prompts on read is the right default

A credential manager for AI agents must be scriptable. If every `agentkeys read` required Touch ID, the product would be unusable — you cannot biometric-prompt a cron job, a CI runner, or a long-running agent task. `gh`, `aws-vault`, `docker login`, and `git-credential-osxkeychain` all made the same decision for the same reason.

The security story does not rely on per-read prompts. It relies on:

- **Scoped sessions** — blast radius is bounded by what the session can reach
- **TTL-bounded sessions** — stolen sessions expire quickly
- **Audit trail** — compromise is detectable after the fact
- **Server-side revocation** — kill compromised sessions from any authenticated device
- **Optional high-value release gate** — human-in-the-loop *only* for credentials that warrant it

These are server-side properties that survive even when the user's machine is compromised — which is the real threat model for a product whose users are running opaque AI agents on their behalf.

---

## 9. Hardening features and where they live in the plan

Every hardening item raised by this investigation has been mapped to a concrete stage in `docs/archived/development-stages-v2-2026-04.md`. None of these are floating ideas anymore — they are all in either Stage 3 (kernel-level, daemon-only, already planned) or Stage 8 (memory hygiene + CLI features + storage options, added during this Stage 4 investigation).

### Already in Stage 3 (kernel hardening, daemon)

These were in the spec from day one and gate Stage 3 completion. Reproduced from `development-stages-v2-2026-04.md`:

- `memfd_secret()` for runtime session key copy (fallback to `mlock2` if `ENOSYS`)
- `mlock2(MCL_CURRENT|MCL_FUTURE)` to prevent swap
- `prctl(PR_SET_DUMPABLE, 0)` to block `/proc/pid/mem` reads
- `prctl(PR_SET_NO_NEW_PRIVS, 1)` to block privilege escalation
- Self-installed seccomp-bpf filter denying `ptrace`, `process_vm_readv`, `kcmp`, `keyctl`, `/dev/mem`, `/proc/kcore`
- Capability drop to empty effective set after init
- Startup self-test that verifies each kernel feature
- Session file at `$HOME/.agentkeys/session` mode 0600

### Added to Stage 8 (Production Hardening, post-MVP)

Stage 8 was added during this investigation. It covers the gaps Stage 3 leaves open: memory hygiene inside the daemon's own code, CLI defensive features, and optional storage hardening for the master session.

#### Daemon Priority A (shrink the dominant exposure window — agent-side)

Items that shrink the **agent window** (where the credential actually spends most of its time) or that are foundational types every other item depends on. *This priority list was corrected during the Stage 4 review — see Section 7's "Where the credential actually lives" diagram for the rationale.*

- `**zeroize` / `SecretString` wrappers** on `Session.token`, credential payloads, and the MCP `get_credential` response builder. Drop impl actively zero-fills. **Foundational** — every other item below assumes credentials flow through these types.
- **Daemon-mediated `cmd_run` for agentkeys-managed runtimes.** Daemon forks child, sets env in child, drops parent copy before `exec`. CLI never touches plaintext. **Shrinks the agent window** by keeping the credential out of the long-lived parent address space. Achievable in v0.1 because we control both ends.
- `**memfd_secret`-via-SCM_RIGHTS delivery for `agentkeys.get_credential`** (agentkeys-managed runtime path). Daemon writes credential into a `memfd_secret`, sends fd via SCM_RIGHTS, agent reads once and closes. Bytes never enter the agent's regular heap. **Shrinks the agent window** for the dominant MCP path. Falls back to inline bytes for runtimes that don't advertise fd support.
- **Idle credential eviction** — configurable TTL (default 60s) wipes cached credentials even while the agent is still running.
- **Daemon-internal audit log** of every fetch / deliver / drop / evict event with timestamp, agent_id, service. Foundational for detection regardless of which mitigations are in place.

#### Daemon Priority B (shrink the daemon window — defensive depth)

Items that shrink only the ~50ms daemon window. Worth doing because compromise of the long-lived daemon process is a real threat (it removes the "retroactive enumeration" attack), but the marginal security win is small relative to Priority A.

- **Drop credential from daemon memory immediately after MCP delivery** — no caching unless explicitly configured per-service. *Demoted from Priority A in the Stage 4 review:* this only defends against daemon compromise + retroactive enumeration, not against the dominant agent-side exposure window.
- `**setrlimit(RLIMIT_CORE, 0)`** at startup (belt-and-suspenders against `prctl(PR_SET_DUMPABLE, 0)`).
- `pkey_alloc` + `pkey_mprotect` per-credential page protection (Linux 4.9+, x86 only).
- Secure-scrubbing global allocator (`mimalloc` secure mode or `scudo`).
- `ptrace_scope` runtime check at startup — refuse to launch if `< 1`.
- CI binary-hardening verification (`checksec` for PIE, RELRO, stack canaries, NX).
- Anti-debugger check via `TracerPid` in `/proc/self/status` at startup.

#### Daemon Priority C (broader runtime cooperation, v0.2+)

- **Extend `memfd_secret`-via-SCM_RIGHTS delivery to non-agentkeys-managed agent runtimes.** Most upstream LLM frameworks expect a `String` env var, not an fd. Generalizing the Priority A protection to arbitrary runtimes requires upstream changes.
- **Daemon-mediated `cmd_run` for arbitrary parent processes.** Priority A covers paths we control (`agentkeys run`, `agentkeys.run` MCP tool). Generalizing to arbitrary parents that want fork-and-drop semantics is a v0.2+ item.

#### CLI deliverables

- `**agentkeys whoami`** — print non-sensitive session metadata (wallet, scope, expiry). Never prints `session.token`. Replaces `ak-keychain-show | jq` in the manual test.
- **Idempotent `agentkeys init`** — short-circuit when a valid session exists, `--force` overrides. Matches `git init`, `gh auth login`, `kubectl config`. Eliminates the find-then-update double-prompt path on macOS for repeated `init` calls.
- `**zeroize` wrapping** for credential strings in `cmd_read` and `cmd_run`. Cheap, consistent with daemon-side work.
- `**prctl(PR_SET_DUMPABLE, 0)` + `setrlimit(RLIMIT_CORE, 0)`** on CLI startup (Linux only).
- **Wire CLI `read` to honor `AuthRequestType::HighValueRelease`** — sensitive credentials require `agentkeys approve` before release.

#### Optional storage hardening

- **Touch-ID gate the master session on macOS** via `kSecAttrAccessControl = kSecAccessControlUserPresence`. Master session only — child sessions stay silent. macOS only.
- **DEK + encrypted file pattern** — keyring holds an immutable 32-byte data encryption key, session JSON lives encrypted at `~/.agentkeys/session.enc` (XChaCha20-Poly1305). Cross-platform. Makes `security find-generic-password -w` return useless random bytes.
Sketch:
  ```rust
  fn get_or_create_master_key() -> Result<[u8; 32]> {
      let entry = keyring::Entry::new("agentkeys", "master-key")?;
      match entry.get_password() {
          Ok(hex_str) => hex::decode(hex_str)?.try_into()
              .map_err(|_| anyhow!("master key wrong length")),
          Err(keyring::Error::NoEntry) => {
              let mut key = [0u8; 32];
              OsRng.fill_bytes(&mut key);
              entry.set_password(&hex::encode(key))?;
              Ok(key)
          }
          Err(e) => Err(e.into()),
      }
  }
  ```

### Stage 8 contract summary

- **Inputs:** Stages 0-7 complete
- **Outputs:** Hardened daemon and CLI; optional Touch-ID / DEK storage
- **Done when:** All Priority A daemon items implemented, all CLI items implemented, all 15 unit tests pass, manual review confirms credential bytes do not survive in daemon memory beyond the configured eviction window. Priority B may slip to Stage 9 if needed; Priority C is explicitly v0.2+.
- **Estimated effort:** 4-6 days
- **Position in critical path:** Off the critical path. Stage 8 ships after the v0 demo (Stage 7) and does not block any earlier stage. Recommended sequencing: ship v0 from Stage 7, then immediately roll into Stage 8 before broad deployment.

See `docs/archived/development-stages-v2-2026-04.md` Stage 8 section for the full deliverable list, unit test matrix, and reviewer E2E checklist.

---

## 10. Server-side trust anchors and URL-hijack defense

This doc focuses on **client-side** credential storage: keychain vs file, memory hygiene, the daemon's credential lifecycle. It does not cover the **server-side** trust anchors our architecture introduced for Stage 6/7 (OIDC federation, DKIM, per-user PrincipalTag). Those are documented authoritatively in [Blockchain TEE Architecture §7 — Security model: assumptions and attacker surface](blockchain-tee-architecture#7-security-model-assumptions-and-attacker-surface).

### What's covered there that matters to a client-security reader

- **Four architectural rules** and what each rule actually defends against (bearer theft, TEE compromise, chain attack, OIDC URL hijack, etc.).
- **Attacker-surface matrix by attack class** — columns for what the attacker needs to achieve, net capability without mitigation, and the mitigation we ship.
- **The "total compromise" disaster-recovery case** for TEE-extraction scenarios.
- **Routine key-rotation procedures** for the three rotation paths (OIDC-issuer, session-JWT, MRSIGNER) — all kept cheap under HDKD (gap §2) + the two new pallets (gap §8, §9).

### New threat class introduced by Stage 7 OIDC federation

**OIDC URL hijack.** `https://oidc.agentkeys.dev` is a public HTTPS endpoint serving our JWKS. Stage 7's cryptographic trust anchor is URL + TLS + JWKS signature. Attackers who compromise DNS / CA / hosting / deploy pipeline can replace the JWKS and mint JWTs that downstream clouds (AWS / GCP / Ali) accept.

- **Baseline hardening in Stage 7 (no blockchain):** AWS thumbprint pinning, CAA DNS records, DNSSEC where supported, 5-min JWT TTL, short `Cache-Control` on JWKS. These reduce the attack surface but don't close it.
- **Chain-anchored defense in Stage 7b:** `pallet-oidc-pubkeys` + off-chain watchdog + daemon-side dual-verify for AgentKeys-owned accounts. Detection + auto-revocation in 30–60 s. Full spec in [`docs/spec/heima-gaps-vs-desired-architecture.md`](../spec/heima-gaps-vs-desired-architecture.md) §8.
- **TEE-hosted OIDC endpoint (future work):** defers past v0.1; closes the hole on foreign clouds too. Tracked in [`docs/spec/post-v0.1-future-work.md`](../spec/post-v0.1-future-work.md) §2.1.

### How this doc's client-side model interacts with the server-side model

Client-side (what this doc covers) and server-side (blockchain-tee-architecture §7) defenses are additive; neither replaces the other:

- Client-side keychain / memory hygiene defends bearer-token leakage on a user's machine.
- Server-side OIDC / PrincipalTag defends against a compromised client failing into another user's data or privilege.
- **If both hold**, user-A compromise bounds to user-A's 30-day blast radius, and even then only against operations user-A was grant-authorized for.
- **If client-side breaks** (bearer stolen), server-side still enforces per-user isolation at the cloud layer.
- **If server-side breaks** (TEE compromise), client-side keychain is irrelevant — the attacker has signing authority.

The two models are designed against **different adversaries** — client-side against local malware and opportunistic attackers on the user's device; server-side against infrastructure attackers with PKI / cloud / deploy-pipeline reach. Shipping both is the whole story.

---

## 11. What was broken in the manual-test doc

Two bugs in `docs/manual-test-stage4.md` found during this investigation:

1. **Wrong jq field name.** Lines 108, 112, 294, 352, 358, 440 all query `.wallet_address` on the session JSON. The `Session` struct in `crates/agentkeys-types/src/lib.rs:7-13` serializes the wallet under the key `wallet`, not `wallet_address`. The correct query is `.wallet` (or `.wallet.0` if `WalletAddress` serializes as a tuple-struct). The existing queries silently return `null`, and downstream `WALLET=$(...)` lines feed a literal `null` into `agentkeys usage`.
2. **Pass criterion requires triggering the double-prompt.** Line 121 asserts "`ak-keychain-show` returns valid JSON containing `wallet_address` + `token`". This assertion:
  - Unavoidably triggers the two keychain prompts
  - Uses the wrong field name (see #1)
  - Duplicates the check at line 113-114 (second `agentkeys` process reads the session), which is the real round-trip proof

Both should be fixed together. The right fix is to add `agentkeys whoami` (see hardening option D above) and replace the `ak-keychain-show | jq` block with `agentkeys whoami`. Until that lands, the doc can at least be corrected to use `.wallet` and to warn that `ak-keychain-show` will prompt twice by design.

---

## 12. References

### Spec documents

- `docs/spec/tech-brief.md` — storage tiering, TEE shielding key model, `tech-brief.md:80` and `tech-brief.md:127`
- `docs/spec/1-step-analysis.md` — "structurally different from 1Password" framing, session-tier table at `1-step-analysis.md:105`
- `docs/spec/credential-backend-interface.md` — `CredentialBackend` trait definition, `AuthRequestType` enum including `HighValueRelease`
- `docs/arch.md` — Rust-first rationale for security-critical paths (`architecture.md:43`)

### Source

- `crates/agentkeys-cli/src/session_store.rs` — `keyring-rs` wiring, fallback file path, 2s timeout
- `crates/agentkeys-cli/src/lib.rs` — `cmd_init`, `cmd_read`, `cmd_store`, `cmd_run`, `cmd_revoke`, `cmd_usage`
- `crates/agentkeys-cli/src/main.rs:30-132` — the complete subcommand list
- `crates/agentkeys-types/src/lib.rs:7-13` — `Session` struct field names
- `crates/agentkeys-mock-server/src/handlers/credential.rs` — `audit_log` insert sites
- `crates/agentkeys-mock-server/src/handlers/session.rs:29-89` — session creation, `generate_wallet_address()` vs `generate_token()`
- `crates/agentkeys-mock-server/src/auth.rs:76-88` — wallet and token byte layouts (20 bytes vs 32 bytes)

### Test docs

- `docs/manual-test-stage4.md` — Test 0 (Keychain Round-Trip) and the `ak-keychain-`* shell helpers

### External

- `keyring` crate v2.3.3 — [https://docs.rs/keyring/2.3.3/](https://docs.rs/keyring/2.3.3/)
- `security-framework::passwords::set_generic_password` — the source of the find-then-update double-prompt on macOS
- Apple `security(1)` man page — the CLI `ak-keychain-show` shells out to

