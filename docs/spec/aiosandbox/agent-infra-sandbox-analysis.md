# agent-infra/sandbox — kernel & integration prerequisites for AgentKeys §3.3a

> **ARCHIVED** — Round 12 source-only analysis. THREE findings were reversed by the Round 13 runtime probe ([`agent-infra-sandbox-runtime-probe.md`](agent-infra-sandbox-runtime-probe.md)): **memfd_secret WORKS** (was PROBABLE FAIL), **Landlock FAILS** (was PASS), **supervisord IS PID 1** (was "no init system"). Read the runtime probe document for current findings.

Source-only analysis of the open-source repository at https://github.com/agent-infra/sandbox (clone at `/tmp/agent-infra-sandbox`, default branch `main`, surveyed against `1-step-analysis.md` §3.3a "S1 at-rest design — Linux kernel hardening").

## TL;DR

The open-source `agent-infra/sandbox` repo is **only an SDK + docs surface**. The actual container image is built and published externally (the `docker/` directory in the repo is empty — `/tmp/agent-infra-sandbox/docker/.gitkeep` is the only file), so almost every Round-6 kernel-capability question (A1–A6) **cannot be answered from source alone**. What we *can* prove from the repo is uncomfortable for §3.3a:

1. The official Quick Start mandates `--security-opt seccomp=unconfined` (`README.md:35`, `docker-compose.yaml:5-6`, `website/docs/en/guide/start/quick-start.mdx:18`). Seccomp is **off by default**, meaning the syscall-denial filter §3.3a Layer 2 step 7 wants to *add* is the only thing standing between a tenant and `ptrace`/`process_vm_readv` — but there is no host-imposed deny-list to layer on top of.
2. The default user inside the sandbox **has passwordless sudo** (`website/docs/en/guide/basic/sandbox.mdx:140` "User: e3f8da5a6253, with sudo privileges"; `sudo` is a first-class boolean parameter on every file-mutation API in `website/docs/public/v1/openapi.json:5191, 5226, 5265, 5358`). That collapses §3.3a's "dedicated `agentkeys` UID, not the agent's UID" assumption — any compromised agent can `sudo cat /var/lib/agentkeys/session`.
3. Kernel is recent enough on the demo image: `Linux 6.10.14-linuxkit (x86_64)` per `website/docs/en/guide/basic/sandbox.mdx:140`. That clears the `memfd_secret` (≥5.14) and Landlock (≥5.13) version gates — but only on the *demo* image's host. Production hosts are unspecified.
4. A single sandbox container is multi-tenant by design (Browser + VSCode + Jupyter + Shell + MCP + VNC all share one PID/UID/mount namespace, see architecture diagram `README.md:255-265` and "Unified File System" claim `README.md:70`). §3.3a's "daemon in its own PID namespace inside the sandbox" requires the daemon to set up nested namespaces itself — no help from the sandbox image.

**Verdict:** Of the six §3.3a kernel prerequisites, **only one (kernel version) is verifiable as PASS from source.** Three are PROBABLE FAIL (A2 secretmem, A4 dedicated UID, A5 ptrace), one is INDETERMINATE (A3 LSM passthrough), and one is HARD FAIL (the seccomp baseline that A6 depends on is `unconfined`). The §3.3a Round-6 design as written is **not buildable on a stock `agent-infra/sandbox` image** without either (a) a custom fork of the image, (b) the daemon installing all of the hardening itself from inside an unprivileged sudo-equipped container, or (c) accepting that S1 is only meaningful against in-container userspace adversaries, not against the agent process itself once it has sudo.

---

## Repo overview

Inventory of `/tmp/agent-infra-sandbox` (cloned 2026-04-08):

| Path | Contents | Relevance |
|---|---|---|
| `README.md` | Marketing + Quick Start + Architecture diagram | Confirms `seccomp=unconfined` requirement (line 35) |
| `docker-compose.yaml` | 50-line compose file | Confirms `seccomp=unconfined` (line 6), env-var inventory, no security_opt beyond that |
| `docker/` | **Empty** (just `.gitkeep`) | **The Dockerfile is not open source.** Image is built and published externally to `ghcr.io/agent-infra/sandbox` and `enterprise-public-cn-beijing.cr.volces.com/vefaas-public/all-in-one-sandbox` |
| `cli/` | **Empty** | No CLI source either |
| `sdk/python/agent_sandbox/` | Generated Python SDK (Fern-based) | API surface only |
| `sdk/js/src/api/resources/` | Generated TS SDK | API surface only |
| `sdk/go/` | Generated Go SDK | API surface only |
| `sdk/fern/` | Fern API definitions | Source of truth for the HTTP API |
| `website/docs/public/v1/openapi.json` | 9000+-line OpenAPI spec | The closest thing to authoritative behavior docs |
| `website/docs/en/guide/basic/sandbox.mdx` | Sandbox info doc with example `SystemEnv` payload | Lines 138-160 — reveals kernel version, user, sudo, home dir |
| `website/docs/en/guide/basic/authentication.md` | JWT auth doc | All ingress is JWT-bearer or short-lived ticket |
| `website/docs/en/blog/announcing-0.mdx` | Architecture blog | Line 269: code execution uses ByteDance **Sandbox Fusion** as the inner secure-isolation layer |
| `examples/` | 12 integration examples | Userland only |

**The repo is essentially a client SDK + docs + examples.** All claims about kernel posture must therefore be inferred from (1) what the documented `docker run` command requires and (2) what the example `SystemEnv` payload reveals about the running container.

---

## A. Kernel-capability prerequisites (A1–A6)

These are the six items in `1-step-analysis.md:273-279` that §3.3a says must be verified before the Round-6 design is buildable.

### A1 — Host kernel version ≥ 5.14 (`memfd_secret`) and ≥ 5.13 (Landlock)

**Status: PASS on the demo image, UNVERIFIABLE for production hosts.**

Evidence: `website/docs/en/guide/basic/sandbox.mdx:140` shows the example sandbox-context payload reporting `Linux 6.10.14-linuxkit (x86_64), with internet access`. 6.10 is well past both thresholds (Landlock ≥5.13, `memfd_secret` ≥5.14, also ≥5.13 for `clone3` improvements and ≥5.4 for `pidfd_open`).

Caveats:
- `linuxkit` indicates this was captured from a Docker-Desktop-on-Mac development VM, not the production fleet that customers will actually run on. There is no statement in the repo about minimum supported host kernel.
- Container kernel = host kernel. AgentKeys cannot influence this; it's whatever the customer's Docker host happens to be.

**For AgentKeys:** add a startup self-check in `agentkeys-daemon` that calls `uname -r`, `memfd_secret(0)` and `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`, and aborts with a clear error on hosts < 5.14. Document the minimum kernel in our README. Do not silently downgrade.

### A2 — `CONFIG_SECRETMEM=y` in the host kernel

❌ **REVERSED by Round 13 runtime probe:** `memfd_secret()` returned `fd=3` on the live image. The source-only inference below was wrong — linuxkit's current build DOES enable `CONFIG_SECRETMEM`.

**Original source-only status: PROBABLE FAIL / UNVERIFIABLE.**

Evidence: nothing in the repo. `CONFIG_SECRETMEM` is a build-time kernel option (default `n` in mainline; Debian/Ubuntu enable it on x86_64 ≥5.14, but RHEL/CentOS Stream and many cloud-vendor kernels do not). The repo's example image runs on `linuxkit`, whose default config does **not** enable `CONFIG_SECRETMEM` historically. Even where the symbol exists, `memfd_secret()` can be runtime-disabled via the `secretmem.enable=0` boot parameter.

**For AgentKeys:** the daemon must `memfd_secret(0)` at startup and fall back to a degraded mode (mlock'd anonymous mapping, accept that `process_vm_readv` from another in-container process with `CAP_SYS_PTRACE` can read it). Explicitly log the degradation. Do not silently fall back.

### A3 — Host AppArmor/SELinux passthrough vs in-container LSM

**Status: INDETERMINATE / PROBABLE FAIL for AppArmor.**

❌ **PARTIALLY REVERSED by Round 13 runtime probe (Landlock sub-finding):** Landlock returns `ENOSYS` on the live image despite kernel 6.10, because `CONFIG_SECURITY_LANDLOCK=n` in the linuxkit build. Source analysis incorrectly assumed Landlock would work if kernel version was sufficient. The AppArmor assessment remains unchanged.

Evidence: nothing in the repo. The Quick Start docker-run command does not pass `--security-opt apparmor=...` (`README.md:35`, `quick-start.mdx:18`), so the container inherits Docker's default AppArmor profile (`docker-default`), not a custom one. AgentKeys cannot install its own AppArmor profile from inside the container — AppArmor profiles are loaded at the host level via `apparmor_parser`, which requires `CAP_MAC_ADMIN` on the host. Same for SELinux types (`semanage fcontext`).

**For AgentKeys:** §3.3a Layer 1 line "AppArmor profile labels the file so only `/usr/bin/agentkeys-daemon` can read it" is **not implementable inside a stock `agent-infra/sandbox` container.** Drop it from v0; rely on DAC + the dedicated-UID story (which itself depends on A4). Document the LSM gap explicitly in the threat model.

### A4 — Sandbox runs as root w/ user namespaces, or non-root UID? Can we create an `agentkeys` UID?

**Status: PROBABLE FAIL on the dedicated-UID assumption.**

Evidence:
- `website/docs/en/guide/basic/sandbox.mdx:140-141` shows `User: e3f8da5a6253, with sudo privileges` and `Home directory: /home/gem`. The username is a random hex (per-instance) but the home dir is hardcoded `/home/gem`, suggesting the container has a long-lived `gem` UID and the random hex is a per-session display name.
- `website/docs/en/guide/basic/code-server.md:46` confirms `/home/gem/` as the workspace root.
- **The default user has passwordless sudo.** This is confirmed three ways: (1) explicit text "with sudo privileges" in the SystemEnv example, (2) `sudo` is a first-class boolean parameter on `FileReadRequest`, `FileWriteRequest`, `FileReplaceRequest`, and `StrReplaceEditorRequest` in `website/docs/public/v1/openapi.json:5191, 5226, 5265, 5358`, and (3) the `SystemEnv` schema has a `user` field (line 8943) but no separate `effective_uid` — i.e. the API exposes one user, who has sudo.

Implications for §3.3a:
- We *can* `useradd agentkeys` from inside the container (the default user has sudo), which gives us a dedicated UID at runtime. But:
- That UID has no protection against the agent's UID, which has sudo, and `sudo cat /var/lib/agentkeys/session` will succeed regardless of `chmod 0600 root:agentkeys`.
- The only way to make the dedicated-UID story meaningful is to **revoke sudo from the agent's UID** before handing the container to user code. That requires either (a) a custom image fork or (b) an `agentkeys init-container` step that runs first, edits `/etc/sudoers.d/`, and then drops to a non-sudo UID before `exec`'ing the agent. (b) is doable but requires the orchestrator (not the sandbox) to coordinate the handoff.
- User namespaces: the repo is silent. `linuxkit` Docker Desktop typically does not enable userns-remap. We cannot tell from source.

**For AgentKeys:** the dedicated-UID design only buys anything if we control the entry sequence. Adopt an `agentkeys-init` model where the init binary creates the `agentkeys` UID + session file + daemon, then `exec`s the agent under a stripped-sudo UID. **This is a significant scope addition not in the current §3.3a writeup.**

### A5 — Does `agent-infra/sandbox` block `CAP_SYS_PTRACE` by default?

**Status: PROBABLE FAIL.**

Evidence: nothing direct in the repo, but two strong indirect signals:
- The container needs to run Chromium with VNC and CDP, plus Jupyter, plus VSCode-server, plus shell — this is a "full Linux distro in a container" pattern, not a hardened-cap one. The compose file (`docker-compose.yaml:5-6`) only specifies `seccomp:unconfined` and **no `cap_drop`**, which means Docker's default capability set is in effect. Docker's default set **does not** include `CAP_SYS_PTRACE`, so cross-process ptrace within the container is blocked at the kernel level *unless* the user is root. But:
- The user *has sudo*, so the user can `sudo strace -p <agentkeys-daemon-pid>` and read `memfd_secret` pages from `/proc/<pid>/mem` — `CAP_SYS_PTRACE` is granted to UID 0, which sudo gives you.

**For AgentKeys:** the §3.3a `prctl(PR_SET_DUMPABLE, 0)` defense protects against same-UID ptrace, **not against root.** Combined with A4, this means the entire ptrace defense rests on actually stripping sudo from the agent UID. There is no other layer.

### A6 — Does it expose `/dev/mem`, `/proc/kcore`, allow `ptrace_attach` across PID namespaces?

**Status: PARTIAL PASS / unverifiable.**

Evidence: nothing direct. Inferences:
- Docker default does not bind-mount `/dev/mem` or `/dev/kmem` from the host into the container, so these files inside the container reflect container-level access only and are owned by `root` with mode `0640`. The user can still `sudo cat /dev/mem` but inside a container it returns I/O errors on most setups.
- `/proc/kcore` similarly only reveals the container's view.
- Cross-PID-namespace ptrace is normally blocked by namespace boundaries; nothing in the repo suggests this is relaxed.
- **However:** because seccomp is `unconfined` (line 35 of README), the sandbox image *cannot* be relying on seccomp to deny `process_vm_readv`. This is the main syscall §3.3a wants blocked, and it is wide open.

**For AgentKeys:** the daemon must install its own seccomp-bpf filter (which `agent-infra/sandbox` permits because seccomp is unconfined — paradoxically, the lax baseline is what *enables* us to install a strict one). Confirm this is reachable from a non-root process via `prctl(PR_SET_NO_NEW_PRIVS, 1)` + `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)`, which it should be on any kernel ≥3.5.

---

## B. AgentKeys integration prerequisites (B7–B10)

These are the four practical questions about how AgentKeys plugs into the sandbox's API surface, not the kernel.

### B7 — Persistent storage location for the session file

**Status: ATTENTION REQUIRED.**

Evidence: the `SystemEnv` schema (`openapi.json:8938-8966`) has `home_dir` and an optional `workspace`, but no notion of a "system data dir" or "secrets dir." The Quick Start (`README.md:300`) shows volume mounts target only `/home/gem/...`. There is no documented persistent path outside the user's home.

§3.3a wants `/var/lib/agentkeys/session`, owned `agentkeys:agentkeys` mode `0700`. **`/var/lib/` is inside the container's writable layer**, which means:
- It survives across `docker exec` but **does not** survive across `docker run --rm` (the documented invocation).
- If the operator does not bind-mount `/var/lib/agentkeys/` into the host, the session is destroyed on every container restart.
- If they *do* bind-mount it, the file is then visible from the host filesystem, and the §3.3a "host root can already read it" caveat becomes much sharper because the path is directly accessible without docker-cp.

**For AgentKeys:** spec must say the session lives at `${WORKSPACE:-/home/gem}/.agentkeys/session` so it sits in the documented persistence path, *or* require a named docker volume mounted at `/var/lib/agentkeys/`. Either way the threat model paragraph needs an explicit "if you bind-mount, host root reads the ciphertext."

### B8 — Authentication boundary between AgentKeys and the sandbox HTTP API

**Status: COMPATIBLE.**

Evidence: `website/docs/en/guide/basic/authentication.md` documents JWT bearer auth via `JWT_PUBLIC_KEY` env var, plus short-lived tickets for browser-style URLs (`/tickets` endpoint). All sandbox API calls go through `:8080` and are gateable on a JWT signed by a keypair the operator controls.

**For AgentKeys:** the master CLI on the user's Mac can mint a sandbox-scoped JWT for the spawning provisioner and pass it to the sandbox at boot via `JWT_PUBLIC_KEY`. The agent inside the sandbox does *not* need the JWT private key — it talks to the local `agentkeys-daemon` over the Unix socket, which talks to Heima directly. The sandbox's HTTP-API auth and AgentKeys' Heima session-key auth are orthogonal and compose cleanly.

### B9 — Per-tenant network egress control

**Status: PARTIAL.**

Evidence: the sandbox runs `TinyProxy` as a forward proxy (`announcing-0.mdx:299`, env var `PROXY_SERVER` in `docker-compose.yaml:16`) and supports `DNS_OVER_HTTPS_TEMPLATES` for DNS hardening (`docker-compose.yaml:18`). There is no per-process egress allow-list.

**For AgentKeys:** the daemon needs to talk to (1) Heima RPC and (2) nothing else. We can pin DNS via `DNS_OVER_HTTPS_TEMPLATES` and route the daemon's HTTP through TinyProxy with an allow-list of `heima-rpc.example.com`. The agent's egress to third-party services (OpenRouter, etc.) is *separately* gated by whether AgentKeys hands it the credential, not by network ACL — which matches the §3.3a / §3.4 architecture.

### B10 — Lifecycle: how long does the daemon run, and who restarts it?

❌ **REVERSED by Round 13 runtime probe:** The image ships a Python **supervisord** at PID 1 (`/opt/gem/supervisord.conf`). AgentKeys can register as a supervisord program. The source-only analysis below incorrectly concluded there was no init system.

**Original source-only status: ATTENTION REQUIRED.**

Evidence: the sandbox is a single-container, single-process-tree environment. There is no `systemd`, no documented init system, no `restart_policy` for in-container services other than what `docker run --restart` provides at the container level. The compose file uses `restart: "unless-stopped"` (`docker-compose.yaml:9`) at the **container** granularity.

**For AgentKeys:** the daemon must be started by an entrypoint script (or `agentkeys init`) that runs before the agent and is responsible for:
1. Creating the `agentkeys` UID + session file (per A4 strategy).
2. Spawning the daemon detached.
3. Health-checking the daemon's Unix socket before handing control to the agent.
4. Handling daemon crash-restart from inside the container — there's no host supervisor to lean on.

A small Go/Rust supervisor that double-forks the daemon and exposes a `/healthz` socket is the minimum viable shape. **This is not in §3.3a today** and should be added.

---

## C. Items that can't be determined from source alone

The repo is a docs+SDK shell. The image-build recipe, the inner Sandbox Fusion config, the entrypoint scripts, the actual `useradd` lines, the seccomp profile (or absence thereof), and the host kernel config are all opaque. Specifically:

1. **Whether `gem` UID is fixed across versions** — `home_dir` is hardcoded but the displayed username is randomized per session. We can't tell if it's a stable UID without `cat /etc/passwd`.
2. **Whether `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN` are dropped in the entrypoint** — Docker default drops them, but the entrypoint may add them back via `setcap` for browser/VNC/proxy functionality.
3. **Whether `/proc/sys/kernel/yama/ptrace_scope` is set** — would harden A5.
4. **Whether the inner Sandbox Fusion (ByteDance's `bytedance/SandboxFusion`, `announcing-0.mdx:269`) uses bubblewrap, nsjail, gVisor, or a homegrown isolation layer for code execution** — relevant because if it's gVisor, the kernel ABI under code-exec is *not* the host kernel and `memfd_secret` will silently no-op there. Only relevant if `agentkeys-daemon` itself runs under Sandbox Fusion (which it shouldn't — it should run alongside, not under, the code-exec subsystem).
5. **Whether the published image enables user namespaces** — the compose file doesn't set `userns_mode`, so it inherits Docker daemon settings. Unknown.
6. **The actual sudoers config** — does the default user have *full* `NOPASSWD: ALL` sudo, or scoped sudo to specific binaries? The OpenAPI `sudo: bool` flag suggests the former.

To resolve C1–C6, run `docker run --rm ghcr.io/agent-infra/sandbox:latest sh -c 'id; cat /etc/passwd | grep -E "gem|agent"; cat /etc/sudoers.d/* 2>/dev/null; capsh --print; cat /proc/self/status | grep -E "Cap|Seccomp"; uname -r; ls /dev/mem /proc/kcore 2>&1'` and capture the output. This is the single most useful empirical follow-up and replaces about half this report.

---

## D. Recommended changes to AgentKeys §3.3a design

Concrete edits to `1-step-analysis.md` §3.3a, in priority order:

1. **Drop the AppArmor/SELinux line from Layer 1.** The container has no host LSM control. Replace with: "DAC + sudo-revocation provide the entirety of v0's filesystem isolation." (Addresses A3.)

❌ **REVERSED (partially) by Round 13 runtime probe:** The init-container approach described in item 2 below is blocked because revoking sudo from `gem` deadlocks the sandbox's own HTTP API (`gem-server` uses `sudo tee` internally). See the runtime probe for the revised strategy (revocation-latency-only isolation on stock image).

2. **Add an `agentkeys init-container` step before §3.3a Layer 1.** This step runs as the default sudo-equipped user, performs `useradd -r agentkeys`, writes `/etc/sudoers.d/agentkeys-deny` to revoke sudo from the agent UID, creates `${WORKSPACE}/.agentkeys/` (or `/var/lib/agentkeys/`) with the right perms, spawns the daemon, then `exec`s the agent under a non-sudo UID. **Without this, A4 + A5 collapse the entire defense.** (Addresses A4, A5.)

3. **Reframe the storage path.** Use `${WORKSPACE}/.agentkeys/session` so it lands inside the documented persistence boundary, *or* require a named volume mounted at `/var/lib/agentkeys/`. Add an explicit threat-model line: "If the operator bind-mounts the session directory to the host filesystem for persistence, host-side adversaries gain ciphertext access without needing `docker cp` or namespace entry. This does not change the on-chain revocation guarantee but does make the 4-hour TTL more important." (Addresses B7.)

4. **Add a kernel self-check at daemon startup** that probes `memfd_secret(0)`, `landlock_create_ruleset`, and `prctl(PR_SET_NO_NEW_PRIVS)`. On any failure, refuse to start with a clear `AGENTKEYS_FATAL_KERNEL_INSUFFICIENT` error. Document the minimum kernel as 5.14. (Addresses A1, A2.)

❌ **REVERSED by Round 13 runtime probe:** supervisord IS PID 1. A custom Rust supervisor is unnecessary — register the daemon as a supervisord program instead.

5. **Add a daemon supervisor.** A 200-line Rust supervisor that double-forks the daemon, exposes `/var/run/agentkeys.sock.health`, and logs to a ring buffer in `memfd_create("agentkeys-log", MFD_CLOEXEC)`. The init-container `exec`s the supervisor, the supervisor `exec`s the daemon. Without this there is no in-container restart story. (Addresses B10.)

6. **Acknowledge that S1 is degraded relative to the Round-6 writeup.** The honest claim becomes: *"The session key gets every protection a non-HW-TEE container with sudo-stripped agent UID can offer. In the worst case — host root or sandbox-image vendor compromise — the attacker gets the scoped subset of credentials for this one agent for ≤ 4 hours, audited on Heima. We are explicitly **not** protected against an in-container adversary that retains sudo, because the upstream sandbox grants sudo by default and we have to actively revoke it."* This is roughly the existing claim with the sudo caveat made explicit.

7. **Add a "production hardening" follow-up to §6 open questions**: "Is there a maintained fork of `agent-infra/sandbox` (or an upstream PR) that ships seccomp-on, sudo-off, and no `JUPYTER`/`CODE_SERVER` for the AgentKeys provisioner use case? If not, build one." This is the long-term durable answer, vs. trying to harden the daemon from inside an unhardened image.

---

## E. Open questions for the agent-infra/sandbox maintainers

1. **Why is `--security-opt seccomp=unconfined` mandatory?** What syscall is the default Docker seccomp profile blocking that the sandbox legitimately needs? (Likely candidates: `clone3` for newer glibc, `userfaultfd` for some browser features, `unshare` for nested namespacing.) Knowing this lets us write a *minimal* profile that re-enables everything except the syscalls §3.3a wants blocked.

2. **What is the canonical username and UID inside the container?** The displayed username is randomized but `/home/gem` is fixed. Is the UID stable across image versions?

3. **What's the sudo policy?** Full `NOPASSWD: ALL`, or scoped? Is there a documented way to launch the container with sudo *disabled* for the default user? (e.g., an env var like `DISABLE_SUDO=true`.)

4. **Is the Dockerfile open source?** The `docker/` directory is empty and the README points only to the published image. Is there a plan to publish the build recipe?

5. **What inner isolation primitive does Sandbox Fusion use?** The blog says "integrated secure isolation environment for code execution" but doesn't specify (bubblewrap? nsjail? gVisor? Firejail? a homegrown ptrace jail?). Relevant because Jupyter/code-exec may run under a *second* sandbox layer that affects what syscalls work.

6. **Is there a recommended way to mount persistent secret material?** The compose example mounts `/tmp/gem/vite-project:/home/gem/vite-project` for code, but no documented pattern for "I have a secret file that should survive restarts and be readable only by a specific UID inside the container."

7. **Does the maintained image enable user namespaces?** Specifically, is the default user UID 1000-on-host or remapped to a high-range UID via `userns-remap`?

8. **Is there a hardened build target?** A "headless, no-VNC, no-VSCode, no-Jupyter, no-sudo, seccomp-on" variant intended for production agent runtimes (vs. the dev-experience-optimized default).

These are all things to bring to the next conversation with `agent-infra/sandbox` maintainers (Kai's network if there's overlap, or directly via GitHub Discussions: https://github.com/agent-infra/sandbox/discussions).

---

## F. References

All paths absolute, line numbers cited where load-bearing.

- `/tmp/agent-infra-sandbox/README.md:35` — `docker run --security-opt seccomp=unconfined ...` (Quick Start, mandatory flag)
- `/tmp/agent-infra-sandbox/README.md:255-265` — Architecture diagram (single-container, multi-component)
- `/tmp/agent-infra-sandbox/README.md:300-318` — Docker-compose example with full env-var inventory
- `/tmp/agent-infra-sandbox/docker-compose.yaml:5-6` — `security_opt: - seccomp:unconfined`
- `/tmp/agent-infra-sandbox/docker-compose.yaml:9` — `restart: "unless-stopped"` (container-level only)
- `/tmp/agent-infra-sandbox/docker-compose.yaml:11-12` — `mem_limit: "8g"`, `cpus: "4"`
- `/tmp/agent-infra-sandbox/docker-compose.yaml:18` — `DNS_OVER_HTTPS_TEMPLATES` env var
- `/tmp/agent-infra-sandbox/docker/.gitkeep` — **The only file in `docker/`. Dockerfile is not in source.**
- `/tmp/agent-infra-sandbox/cli/` — empty directory
- `/tmp/agent-infra-sandbox/website/docs/en/guide/start/quick-start.mdx:18` — same `seccomp=unconfined` requirement, doc-side
- `/tmp/agent-infra-sandbox/website/docs/en/guide/basic/sandbox.mdx:138-160` — example `SystemEnv` payload showing `Linux 6.10.14-linuxkit (x86_64)`, `User: e3f8da5a6253, with sudo privileges`, `Home directory: /home/gem`
- `/tmp/agent-infra-sandbox/website/docs/en/guide/basic/code-server.md:46` — `/home/gem/` workspace layout confirms stable home dir
- `/tmp/agent-infra-sandbox/website/docs/en/guide/basic/authentication.md` — JWT bearer auth via `JWT_PUBLIC_KEY` + `/tickets` short-lived tickets
- `/tmp/agent-infra-sandbox/website/docs/en/blog/announcing-0.mdx:269` — "Code Execution ... using Python 3.10/3.11/3.12 and Node.js 22 runtimes from Sandbox Fusion, providing an integrated secure isolation environment for code execution" — links to https://bytedance.github.io/SandboxFusion/
- `/tmp/agent-infra-sandbox/website/docs/en/blog/announcing-0.mdx:299-306` — TinyProxy forward-proxy explanation
- `/tmp/agent-infra-sandbox/website/docs/public/v1/openapi.json:5191-5196` — `FileReadRequest.sudo: bool` field
- `/tmp/agent-infra-sandbox/website/docs/public/v1/openapi.json:5226-5231` — `FileWriteRequest.sudo`
- `/tmp/agent-infra-sandbox/website/docs/public/v1/openapi.json:5265, 5358` — `FileReplaceRequest.sudo`, `StrReplaceEditorRequest.sudo`
- `/tmp/agent-infra-sandbox/website/docs/public/v1/openapi.json:8425-8484` — `ShellExecRequest` schema (note: no `sudo` field on shell — but the agent can simply prefix `sudo` to the `command` string)
- `/tmp/agent-infra-sandbox/website/docs/public/v1/openapi.json:8938-8966` — `SystemEnv` schema with `user`, `home_dir`, `workspace` fields (no `effective_uid`, no `capabilities`)

§3.3a context being analyzed:
- `/Users/hanwencheng/Projects/project-life/projects/idea/agentkeys/1-step-analysis.md:228-281` — Round 6 §3.3a Linux kernel hardening design
- `/Users/hanwencheng/Projects/project-life/projects/idea/agentkeys/1-step-analysis.md:273-279` — the six prerequisites enumerated as A1–A6 in this report
- `/Users/hanwencheng/Projects/project-life/projects/idea/agentkeys/1-step-analysis.md:589-596` — Round-7 ambiguity-tracker note that §3.3a's six kernel prerequisites are the main remaining blocker
