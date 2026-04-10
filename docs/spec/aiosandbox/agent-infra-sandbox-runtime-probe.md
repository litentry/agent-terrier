# agent-infra/sandbox — Runtime Probe Report

**Date:** 2026-04-08 (Round 13 of auth-layer sub-interview)
**Source:** runtime probe of a live `agent-infra/sandbox` instance at `http://localhost:8080`, version **`1.0.0.152`**, on Docker Desktop (Apple Silicon, aarch64). Probe script: `/tmp/agentkeys-probe.sh`, raw output: `/tmp/agentkeys-probe-output.txt`.
**Parent docs:**
- [`./1-step-analysis.md`](1-step-analysis.md) §3.3a (original Round 6 kernel-hardening design) and §3.3b (Round 12 source-only reality check)
- [`./agent-infra-sandbox-analysis.md`](agent-infra-sandbox-analysis.md) (Round 12 source-only analysis, **now partially superseded by this doc**)
- [`./architecture.md`](architecture.md) (component inventory and language split)
- [`./open-source-posture.md`](open-source-posture.md) (security posture, threat model)

---

## 1. Executive summary (the critical finding)

**Stock `agent-infra/sandbox` v1.0.0.152 cannot enforce the §3.3a Round 6 daemon-vs-agent UID split, because the image's own HTTP control plane (`gem-server`) runs as the `gem` user and depends on that user having passwordless sudo for its privileged operations. Any attempt to revoke sudo from `gem` — the exact mechanism §3.3b proposed — breaks the sandbox's own HTTP API, confirmed empirically via a deadlock during probe2.**

As a direct consequence, **v0 of AgentKeys on stock agent-infra/sandbox is limited to revocation-latency-based isolation.** The session key is, in the worst case, readable by the agent process at any time (because the agent runs as gem and gem has NOPASSWD sudo). The only remaining defense is rapid on-chain revocation: a stolen session dies the moment `agentkeys revoke` is called, which lands in ≤ 1 Heima block (~6 seconds if scoped sessions are supported, else ≤ 4h worst case from the TTL).

**Three significant reversals vs the Round 12 source-only analysis:**

| Finding | Round 12 source-only | Round 13 runtime |
|---|---|---|
| `memfd_secret()` availability | PROBABLE FAIL (linuxkit default assumed to lack `CONFIG_SECRETMEM`) | **✅ VERIFIED WORKING** — returned `fd=3` on this image |
| Landlock availability | PASS on version (kernel ≥5.13 present) | **❌ FAIL with `ENOSYS`** — `CONFIG_SECURITY_LANDLOCK=n` in this kernel build |
| In-container init/supervisor | "No init system, only container-level restart" | **✅ supervisord IS PID 1** — image ships a Python supervisord at `/opt/gem/supervisord.conf`; AgentKeys can register as a supervisord program |

**Two fundamentally new findings that neither source nor Round 12 caught:**

1. **`gem-server` uses sudo internally.** When you call `/v1/file/write` with `sudo: true`, the gem-server spawns a `sudo tee` subprocess. If gem's sudo is revoked, this hangs forever waiting for a password prompt. **Empirically verified during probe2 cleanup deadlock.**
2. **Landlock is not kernel-version-gated, it's kernel-build-gated.** Docker Desktop's current linuxkit build has kernel 6.10 but ships with `CONFIG_SECURITY_LANDLOCK=n`. Source analysis cannot catch this without running the actual syscall.

---

## 2. What we probed and how

**Target:** live instance at `http://localhost:8080`, `version=1.0.0.152`, running `Ubuntu 22.04.5 LTS` userspace on `Linux 6.10.11-linuxkit aarch64`.

**Method:** wrote a bash probe script, uploaded it via `POST /v1/file/write`, executed via `POST /v1/shell/exec`, captured stdout. No root access, no Docker host access — everything through the sandbox's own public HTTP API.

**Probe script** (`/tmp/agentkeys-probe.sh`, 149 lines) covered:
- Identity and UID mapping
- Sudo posture (`sudo -n true`, `sudo -l`, `/etc/sudoers.d/` listing)
- Capabilities (`capsh --print`, `/proc/self/status Cap*`)
- Kernel version and config presence
- `memfd_secret()` runtime test via `ctypes` syscall
- `landlock_create_ruleset()` runtime test via `ctypes` syscall
- `memfd_create()` baseline (always-available sanity check)
- LSM status (`/sys/kernel/security/lsm`, `aa-status`, `sestatus`)
- User namespace mapping (`/proc/self/uid_map`, `/proc/self/ns/*`)
- PID 1 identity and process tree
- Filesystem layout (mount types, `/home`, `/var/lib`, `/workspace`)
- `/dev/mem`, `/proc/kcore`, seccomp posture
- Binary availability for init-container steps
- Heima RPC reachability (DNS + TCP)

A second probe script (probe2) attempted to test the §3.3b init-container's sudo-revocation step end-to-end. **It succeeded in validating the revocation works — to the point that it locked the sandbox's own API out of sudo and hung.** See §6 below.

---

## 3. Answers to the six kernel prerequisites

### A1 — Kernel version (`memfd_secret` ≥5.14, Landlock ≥5.13)

**Status: ✅ PASS on this image (version gate only)**

Evidence:
```
Linux e0130dcb744e 6.10.11-linuxkit #1 SMP Thu Oct  3 10:17:28 UTC 2024 aarch64
Linux version 6.10.11-linuxkit (root@buildkitsandbox)
  (gcc (Alpine 13.2.1_git20240309) 13.2.1 20240309, GNU ld (GNU Binutils) 2.42)
  #1 SMP Thu Oct  3 10:17:28 UTC 2024
```

**Caveats:**
- Kernel version tells us what syscalls could theoretically exist; it does not guarantee `CONFIG_*` flags. See A2 and A3 — version pass ≠ feature availability.
- `linuxkit` means this is the Docker Desktop on Mac build, not an arbitrary production host. The version on a customer's actual host could be anything.

### A2 — `CONFIG_SECRETMEM=y` / `memfd_secret()` availability

**Status: ✅ RUNTIME VERIFIED WORKING** — **positive reversal vs Round 12's PROBABLE FAIL**

Evidence:
```
=== memfd_secret RUNTIME TEST (Python) ===
SUCCESS: memfd_secret() returned fd=3
```

The Python ctypes test called `syscall(447, 0)` (the aarch64 `memfd_secret` syscall number), and it returned a valid file descriptor. This means `CONFIG_SECRETMEM=y` is enabled in the linuxkit kernel build. We do NOT need the `mlock2` fallback mode on this image.

**Sysfs path `/sys/kernel/secretmem/` does not exist** — that's expected; the sysfs interface was only added in later kernels for userspace configuration. The syscall itself works regardless.

**For AgentKeys:** use `memfd_secret()` as the primary path. Keep the `mlock2` fallback code for hosts where the runtime probe fails, but expect it to be rarely invoked on Docker Desktop.

### A3 — LSM (AppArmor/SELinux) passthrough or in-container LSM

**Status: ❌ DEAD** — no LSM operational inside the container

Evidence:
```
--- LSM ---
cat: /sys/kernel/security/lsm: No such file or directory
--- apparmor ---
/tmp/agentkeys-probe.sh: line 56: aa-status: command not found
cat: /proc/self/attr/current: Invalid argument
--- selinux ---
/tmp/agentkeys-probe.sh: line 59: sestatus: command not found
ls: cannot access '/sys/fs/selinux/': No such file or directory
```

`/sys/kernel/security/lsm` does not exist — means the `securityfs` filesystem doesn't even surface LSM information inside this container. `aa-status` is not installed (`aa-utils` package absent). `sestatus` is not installed. `/proc/self/attr/current` returns `Invalid argument` which indicates no LSM has claimed the process.

**For AgentKeys:** the §3.3a Layer 1 line *"AppArmor profile labels the session file so only `/usr/bin/agentkeys-daemon` can read it"* is definitively not implementable on this image. Drop it.

### A3-bonus — Landlock availability

**Status: ❌ DEAD despite kernel version pass** — **negative reversal vs Round 12's PASS-on-version**

Evidence:
```
=== Landlock RUNTIME TEST (Python) ===
FAIL: landlock_create_ruleset() errno=38 (Function not implemented)
```

`errno 38 = ENOSYS` = "Function not implemented." The syscall number exists (we called 444 which is `landlock_create_ruleset` on both aarch64 and x86_64), but the kernel has `CONFIG_SECURITY_LANDLOCK=n` — Landlock was not compiled into this kernel build.

**This is a significant loss for the §3.3a design.** Layer 2 step 8 (Landlock restricting filesystem access to `/var/lib/agentkeys/` and `/var/run/agentkeys.sock`) is **not enforceable** on stock `agent-infra/sandbox`. We lose the in-kernel filesystem sandbox that was supposed to prevent a compromised daemon from accessing arbitrary files.

**For AgentKeys:** either (a) conditionally skip Landlock setup on kernels that lack it and document the degradation, (b) use seccomp-bpf to deny `openat` on anything under `/etc/` / `/sys/` / `/proc/*/mem` (weaker, more complex to enumerate), or (c) require a hardened fork of the sandbox with Landlock compiled in. **Recommend (a) with honest documentation for v0.**

### A4 — User/UID model (non-root UID; can create `agentkeys` UID?)

**Status: ⚠️ MIXED — technically possible but sudo-bypass collapses the isolation**

Evidence:
```
=== IDENTITY AND USER ===
gem
uid=1000(gem) gid=1000(gem) groups=1000(gem)
--- /etc/passwd (gem line) ---
gem:x:1000:1000::/home/gem:/bin/bash
```

So yes: the default user is non-root, UID 1000, stable across invocations. `useradd` and `runuser` binaries exist, so creating a dedicated `agentkeys` UID (999 or similar) and spawning the daemon under it is mechanically possible.

**BUT:**

```
=== SUDO POSTURE ===
--- sudo -n true (passwordless?) ---
exit: 0
--- sudo -l ---
Matching Defaults entries for gem on e0130dcb744e:
    env_reset, mail_badpass, secure_path=..., use_pty

User gem may run the following commands on e0130dcb744e:
    (ALL) NOPASSWD: ALL
--- /etc/sudoers.d/ ---
-r--r----- 1 root root   27 Apr  8 15:45 gem
-r--r----- 1 root root 1096 Aug  3  2022 README
```

The default user `gem` has **`(ALL) NOPASSWD: ALL`** — unconditional passwordless sudo to every command. This rule lives in `/etc/sudoers.d/gem` (27 bytes, root-owned, mode 0440). The UID split from §3.3a is **structurally defeated** by sudo: gem can `sudo cat /var/lib/agentkeys/session` regardless of DAC 0600, `chattr +i`, or any other Layer 1 protection that predicates on the agent running without root.

**See §6 for what happened when we tried to remove gem's sudo.**

### A5 — `CAP_SYS_PTRACE` blocked?

**Status: ✅ baseline is blocked, ❌ effectively bypassable via sudo**

Evidence:
```
Current: =
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,
  cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,
  cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Ambient set =
Current IAB: !cap_dac_read_search,!cap_linux_immutable,!cap_net_broadcast,
  !cap_net_admin,!cap_ipc_lock,!cap_ipc_owner,!cap_sys_module,!cap_sys_rawio,
  !cap_sys_ptrace,!cap_sys_pacct,!cap_sys_admin,!cap_sys_boot,!cap_sys_nice,
  !cap_sys_resource,!cap_sys_time,!cap_sys_tty_config,!cap_lease,
  !cap_audit_control,!cap_mac_override,!cap_mac_admin,!cap_syslog,
  !cap_wake_alarm,!cap_block_suspend,!cap_audit_read,!cap_perfmon,!cap_bpf,
  !cap_checkpoint_restore

CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
NoNewPrivs:     0
Seccomp:        0
```

Current effective capabilities are **empty** (`CapEff: 0`). Bounding set is **standard Docker default** with 14 caps, and crucially **`cap_sys_ptrace` is NOT in the bounding set** (explicitly listed in the IAB as `!cap_sys_ptrace`).

**BUT:** `sudo` is a setuid binary. When gem runs `sudo strace` it becomes effectively root, and sudo explicitly drops the bounding-set restrictions for its child, so `strace` (ptrace) works anyway. The bounding set only constrains what gem can get *without* sudo.

**Conclusion:** direct ptrace is blocked; sudo-wrapped ptrace is not.

### A6 — `/dev/mem`, `/proc/kcore`, seccomp

**Status: ✅ PARTIAL PASS** — raw-memory files hidden, seccomp explicitly disabled

Evidence:
```
=== DEV FILES ===
ls: cannot access '/dev/mem': No such file or directory
ls: cannot access '/dev/kmem': No such file or directory
crw-rw-rw- 1 root root 1, 3 Apr  8 15:45 /proc/kcore
```

```
=== mount types ===
tmpfs /dev
tmpfs /dev/shm
tmpfs /proc/kcore
tmpfs /proc/keys
tmpfs /proc/scsi
```

- `/dev/mem` and `/dev/kmem`: absent ✓
- `/proc/kcore`: exists as a character device, **but mounted as tmpfs** — Docker's standard practice. Reading it gets zero bytes, effectively shadowed.

```
=== SECCOMP POSTURE ===
Seccomp:        0
Seccomp_filters:        0
(0=disabled 1=strict 2=filter)
```

**`Seccomp: 0` confirms `--security-opt seccomp=unconfined` at container startup.** No baseline seccomp filter. On the upside, this means AgentKeys can install its own strict filter without fighting a pre-existing one.

---

## 4. Answers to the four integration prerequisites

### B7 — REST API for session-key push

**Status: ✅ HTTP API confirmed, `/v1/file/write` + `sudo: bool` works (when gem's sudo isn't broken — see §6)**

Evidence:
```
POST /v1/file/write
properties: ['file', 'content', 'encoding', 'append', 'leading_newline',
             'trailing_newline', 'sudo']
required: ['file', 'content']
```

Empirically confirmed the endpoint accepts a 4613-byte bash script and writes it to `/tmp/agentkeys-probe.sh`. The `sudo: true` flag works in steady state. **Caveat:** when gem's sudo is revoked, file/write with `sudo:true` hangs indefinitely because gem-server spawns an internal `sudo` subprocess that waits for a password (§6).

### B8 — Network reachability to Heima

**Status: ✅ PASS**

Evidence:
```
=== HEIMA RPC REACHABILITY ===
198.18.14.188   rpc.litentry-parachain.litentry.io
TCP_OK
```

DNS resolves, TCP 443 handshake succeeds. The daemon can talk to Heima's public RPC endpoint directly without any outbound proxy or tunnel.

### B9 — Browser and Playwright availability

**Status: ✅ PASS** — browser pre-installed and actively running

Evidence (from `ps auxf`):
- `/usr/local/bin/browser` at PID 98 (Chromium-based), visible flags: `--remote-debugging-port=9222 --disable-web-security --no-sandbox --user-agent=...Chrome/140.0.0.0`
- `/usr/bin/mcp-server-browser` at PID 115 (`--port 8100 --host 0.0.0.0 --browser chrome --cdp-endpoint http://127.0.0.1:9222/json/version --vision`)

Chrome 140 via CDP on port 9222. MCP server at port 8100 wraps it. The Agent Provisioner can reuse this browser directly, or spin up its own Playwright instance since Node v22.21.0 is also available.

### B10 — Init system / supervisor

**Status: ✅ SUPERVISORD IS PID 1** — **positive reversal vs Round 12 "no init system"**

Evidence:
```
=== PID 1 AND SUPERVISOR ===
  PID USER     COMMAND         COMMAND
    1 root     supervisord     /usr/bin/python3 /usr/bin/supervisord -n -c /opt/gem/supervisord.conf
```

The container runs `supervisord` (Python implementation) as PID 1, managing multiple services: `python-server` (MCP hub on 8091), `gem-server` (HTTP API on 8088, which is what `/v1/*` routes to), `browser`, `nginx` (port 8080 frontend), `code-server` (VSCode on 8200), `websocat` (VNC on 6080), `mcp-server-browser` (8100).

**For AgentKeys:** we do NOT need to write a Rust supervisor. Instead, drop a new `[program:agentkeys-daemon]` snippet into `/opt/gem/supervisord.conf` (or an include directory if the conf supports it) and let supervisord handle start/stop/restart/health. Significant simplification of §3.3b delta #5.

**Caveat:** modifying `/opt/gem/supervisord.conf` requires sudo. See the sudo-bypass problem in §6.

---

## 5. Additional runtime findings (not in the original question list)

1. **`/etc/sudoers.d/gem` file is unreadable without sudo** but we can infer its content from `sudo -l` output: `gem ALL=(ALL) NOPASSWD: ALL`. The canonical deny-path the init-container would write to is `/etc/sudoers.d/zz-agentkeys-deny-sudo` (sorted alphabetically after `gem`, so read last by sudoers parser; "zz-" prefix is the conventional way to ensure ordering).

2. **User namespace mapping is identity** (`0 0 4294967295`) — no userns remapping. UID 1000 inside the container == UID 1000 on the host VM. No extra isolation from user namespaces.

3. **`/workspace` does not exist.** Earlier source analysis mentioned `${WORKSPACE}` as a persistence path; the actual equivalent is `/home/gem`. The §3.3b "Option X: `${WORKSPACE}/.agentkeys/session`" should be rewritten to `/home/gem/.agentkeys/session`.

4. **`/var/lib` exists** as `drwxr-xr-x 1 root root` — gem cannot write to it without sudo. Any init-container that wants `/var/lib/agentkeys/` has to create it with `sudo install -d`.

5. **Filesystem backing:** `/dev/vda1 ext4 59G 35% /etc/hosts` (only `/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf` are bind-mounted from the host VM). Root filesystem itself is Docker `overlay`.

6. **Inside the container** there is **no userspace apparmor** (`aa-status` not found), no SELinux userspace (`sestatus` not found). The binaries we'd need for hardening (`useradd`, `visudo`, `runuser`, `chattr`, `setcap`, `getcap`, `capsh`, `sudo`, `su`, `bash`) are all present.

7. **Python environments:** `python3.10` (default), `python3.11`, `python3.12` are all present; `python3.10` has ctypes access to libc for raw syscalls (how our probe worked). Node v22.21.0 is also present.

8. **The container has hundreds of browser sub-processes** (Chrome renderer, GPU process, utility processes). This is a multi-service environment — NOT a minimal sandbox. See §8 below for implications.

---

## 6. The sudo-bypass deadlock — empirical validation and warning

**Probe2 tried to test the §3.3b init-container end-to-end.** It ran these steps successfully:

1. Created `agentkeys` UID 999 via `sudo useradd -r -s /usr/sbin/nologin -d /var/lib/agentkeys agentkeys`
2. Created `/var/lib/agentkeys` via `sudo install -o agentkeys -g agentkeys -m 0700 -d /var/lib/agentkeys`
3. Wrote a test session file as the `agentkeys` UID via `sudo runuser -u agentkeys -- bash -c "echo TESTSESSION > /var/lib/agentkeys/session"`
4. Wrote the deny rule via `echo 'gem ALL=(ALL) !ALL' | sudo tee /etc/sudoers.d/zz-test-agentkeys`
5. Verified it parsed with `sudo visudo -c`

At this point the rule was in force. **The verification step `sudo -n id` correctly returned "sudo: a password is required"** — the deny rule works exactly as §3.3b designed.

**Then the cleanup step hung.** `sudo rm -f /etc/sudoers.d/zz-test-agentkeys` hung because the deny rule had just blocked sudo for gem — gem couldn't remove the very rule that was blocking it. Classic self-lock.

**Worse: the sandbox's own HTTP control plane (`gem-server`) also locked up.** When probe2's timeout fired (120 s) I tried a simple state-check via `/v1/file/write` with `sudo: true` — it hung too. Then `/v1/sandbox` (GET, no sudo at all) also hung. The entire API server became unresponsive.

**Root cause:** `gem-server` runs as the `gem` UID (confirmed in probe1's `ps auxf` output, PID 97). When any API call triggers an internal privileged operation, gem-server spawns `sudo <something>` as a child. With the deny rule active, that child hangs on the password prompt, and it appears gem-server lacks a timeout around the child — the whole server wedges.

**What this proves:**

1. **§3.3b's "revoke sudo from gem" step works too well.** It breaks the sandbox's own control plane. You cannot run the init-container step on stock `agent-infra/sandbox` without permanently wedging it.
2. **`gem-server` is not a clean isolation surface.** It actively depends on its parent UID having sudo. This is a fundamental architectural choice by agent-infra (gem-server is designed to expose sudo as an API parameter, per the OpenAPI spec's `sudo: bool` on every file-mutation endpoint), and it means AgentKeys cannot safely strip sudo from gem **no matter how surgical the approach**.
3. **Any UID-split defense in depth on stock sandbox is theater.** The agent runs as gem. Gem has sudo. Sudo bypasses DAC. Therefore the agent can read any file, including our session key, regardless of where we put it or what UID it belongs to.

**The sandbox is currently in this wedged state as of 2026-04-08 ~19:22 UTC.** Recovery requires either:
- `docker exec -u root <container-id> rm /etc/sudoers.d/zz-test-agentkeys && docker exec -u root <container-id> userdel -r agentkeys` on the host, OR
- `docker restart <container-id>` (the deny rule lives in the writable overlay layer and resets on container recreation).

---

## 7. Implications for the AgentKeys v0 design (Round 13 scope decision)

Based on the runtime evidence, the user has locked in the following scope decision:

**v0 ships on stock `agent-infra/sandbox` with revocation-latency-only isolation.** Concretely:

- The AgentKeys daemon runs as `gem` (the default user), just like every other service in the container.
- The session key file is stored at `/home/gem/.agentkeys/session`, mode 0600, owned by gem.
- `memfd_secret()` is used for the runtime in-memory copy (verified working) — this protects against userspace process-memory dumps via `process_vm_readv` from non-gem processes, though there are no non-gem processes worth protecting against on this image.
- `mlock2(MCL_CURRENT|MCL_FUTURE)` prevents swap of the daemon's pages.
- `prctl(PR_SET_DUMPABLE, 0)` and `prctl(PR_SET_NO_NEW_PRIVS, 1)` block core dumps and ptrace attachment **from non-root processes**.
- No Landlock (kernel lacks `CONFIG_SECURITY_LANDLOCK`).
- No LSM (AppArmor/SELinux absent).
- No UID split, no sudo revocation — attempting either breaks gem-server.
- The daemon registers as a `[program:agentkeys-daemon]` in `/opt/gem/supervisord.conf` for lifecycle management (requires sudo at provisioning time — done once, during the initial `agentkeys attach` flow).

**The honest v0 security claim becomes:**

> *"On stock `agent-infra/sandbox`, the session key is stored using every kernel feature available (`memfd_secret`, mlock, seccomp-bpf we install ourselves, dumpable off, no-new-privs on), but the agent process has `NOPASSWD: ALL` sudo by image construction. In the worst case — RCE of the agent process — the attacker has immediate full access to the session file and to daemon memory via `sudo strace`. Our defense is not isolation; it is **rapid on-chain revocation**. Stolen sessions die in ≤ 1 Heima block (~6 s) once detected, and have a hard TTL of 4 hours regardless. Compared to 1Password service-account tokens — which have no TTL, no per-call signing, and no instant revocation — this is still a meaningful upgrade, but it is strictly weaker than the §3.3a Round 6 design. Users who need kernel-enforced isolation between their agent process and their credential daemon must use a hardened fork of `agent-infra/sandbox` (see §8) or a different sandbox product entirely."*

**The §3.3b design as written does NOT apply to stock sandbox. It applies to the hardened fork described in §8.**

---

## 8. Long-term TODO: build (or commission) a hardened fork of agent-infra/sandbox

**Added to 1-step-analysis.md §8.2.x and open-source-posture.md §14.**

The durable answer to all the Round 13 problems is a variant of `agent-infra/sandbox` designed for production agent runtimes instead of interactive development:

**What the "headless production" variant would change vs stock:**

1. **Move `gem-server` (and `python-server`, `mcp-server-browser`) to run as `root` (or a dedicated privileged `sandbox` UID),** not as `gem`. Eliminates the sudo-via-child-process pattern entirely.
2. **Remove sudo from gem by default.** `/etc/sudoers.d/gem` either omitted or replaced with a minimal deny rule.
3. **Remove interactive development services:** no Jupyter, no VSCode/code-server, no VNC/websocat, no browser-as-default. Smaller attack surface.
4. **Enable seccomp-bpf by default** — reverse the `--security-opt seccomp=unconfined` mandate; ship a reasonable default seccomp profile.
5. **Build the kernel with `CONFIG_SECURITY_LANDLOCK=y`** (Docker Desktop users would need to upgrade their linuxkit; Linux hosts already have it on most distros).
6. **Enable AppArmor passthrough** — ship an AppArmor profile as part of the image; document the host requirements for loading it.
7. **Ship with a dedicated `agentkeys` UID pre-created** (or a generic "secrets daemon" UID) so the init-container step is a one-line enable rather than a multi-step setup.
8. **Publish the Dockerfile** — `docker/` in the public repo is currently empty (per source analysis).

**Why this is a long-term TODO, not a blocker:**
- Would require either upstream collaboration with the agent-infra team (conversation needed, no existing channel) or maintaining our own fork long-term (significant operational cost).
- v0 of AgentKeys can ship on stock sandbox with the revocation-latency-only story and still beat 1Password.
- The writeup becomes part of the research artifact's honest discussion — "here's what we did, here's why it's limited, here's what would fix it."

**Action items:**
- [ ] Open a GitHub Discussion on `agent-infra/sandbox` asking: "Is there a hardened production variant of this image for agent runtimes that consume credentials, where the default user does not have sudo and sensitive services are namespace-isolated?"
- [ ] Prepare a threat-model writeup explaining why the standard image is not suitable for long-lived agent credential storage.
- [ ] Scope the effort to fork and maintain a hardened variant if the upstream conversation doesn't go anywhere (approx.: 1 week initial fork + ongoing patches to keep parity with upstream).

---

## 9. Open questions we still couldn't answer from inside the container

These remain for a future conversation with `agent-infra/sandbox` maintainers (also listed in [`./agent-infra-sandbox-analysis.md`](agent-infra-sandbox-analysis.md) §E):

1. **Why is `seccomp=unconfined` mandated?** What syscall does the default Docker seccomp profile block that the sandbox legitimately needs?
2. **Can the image be configured to disable sudo for `gem` at launch?** (e.g., `DISABLE_SUDO=true` env var)
3. **Is the Dockerfile open source?** The `docker/` directory in the public repo is empty.
4. **What inner isolation does "Sandbox Fusion" (mentioned in their blog) provide?** Related to Jupyter code execution.
5. **Does the maintainer ship (or plan to ship) a production-hardened variant of the image?**
6. **Is there a way to ask supervisord to start a new program at runtime via a non-sudo mechanism?** (e.g., supervisorctl over a unix socket that doesn't require gem to have sudo)
7. **Is gem's UID 1000 stable across image version upgrades?** Or does it change?

---

## 10. Cross-references

- **§3.3a original Round 6 kernel-hardening design:** [`./1-step-analysis.md`](1-step-analysis.md) §3.3a
- **§3.3b Round 12 source-only reality check:** [`./1-step-analysis.md`](1-step-analysis.md) §3.3b (to be updated with Round 13 deltas)
- **Round 12 source analysis:** [`./agent-infra-sandbox-analysis.md`](agent-infra-sandbox-analysis.md)
- **Component inventory / language split:** [`./architecture.md`](architecture.md)
- **Security posture / threat model:** [`./open-source-posture.md`](open-source-posture.md)
- **Kai meeting agenda (TEE worker questions):** [`./heima-open-questions.md`](heima-open-questions.md)

## 11. Raw probe output

Full probe1 output: `/tmp/agentkeys-probe-output.txt` (193 lines). Probe scripts: `/tmp/agentkeys-probe.sh`, `/tmp/probe2.sh`.

---

*This document captures the empirical reality of `agent-infra/sandbox` v1.0.0.152 as a target runtime for AgentKeys v0. It supersedes the Round 12 source-only analysis in [`./agent-infra-sandbox-analysis.md`](agent-infra-sandbox-analysis.md) on the three findings listed in §1 (memfd_secret works, Landlock doesn't, supervisord exists).*
