# Agent background-job harness

A portable contract for **running, streaming, and controlling background work** on a device-hosted
agent — independent of which LLM/agent runtime powers it. It exists because a voice/device agent's
reply is **one-shot** (it only talks when spoken to), so anything ongoing ("report the time every
10 s", "watch this") has to run as a real OS process and be delivered + controlled out-of-band.

The defining property: **the control plane sits BELOW the agent.** Listing and killing a task never
go through the agent's API or the LLM — they read `/proc` and signal process groups directly. So the
harness works for Hermes, an OpenClaw/Claude-style runtime, or a hand-rolled script, unchanged; only
a thin per-agent seam differs (see [Per-agent seams](#per-agent-seams)).

Reference implementation in this repo: the hermes-sandbox bridge `/v1/jobs` API
([`docker/hermes-sandbox/hermes_bridge.py`](../../docker/hermes-sandbox/hermes_bridge.py)), the
device probe's jobs panel (the operator-internal front-end client), and
the agent knowledge page ([`docs/wiki/on-device-agent-and-agentkeys.md`](../wiki/on-device-agent-and-agentkeys.md)).
Tracked under issue #340 item 2.

## The model: a task is a process group

The owner cares about **one logical activity**; the OS implements it as **several processes**. The
harness must collapse to the former.

| Term | What it is | In a `while … sleep` timer | Per task | Surface to owner? | Control unit? |
|---|---|---|---|---|---|
| **Task** | one background activity the owner asked for | "报时 every 10 s" | it *is* the unit | ✅ one row | ✅ |
| **Process group** (`pgid`) | the OS handle bundling a task's processes | the session the runtime opens for the loop | 1 : 1 with the task | ❌ internal | ✅ the kill anchor |
| **Process / "thread"** | an individual OS process | `bash` (loop) · `sleep` · `date` | 2–3 | ❌ detail | ❌ killing one lets the loop respawn |

Why a loop shows as several processes: the agent backgrounds e.g.
`bash -c 'while true; do echo $(date); sleep 10; done >> …/stream.log'`. The `>>` redirect makes
**bash** hold the output file open, and the `sleep`/`date` children **inherit that file descriptor**.
A naive "every process holding the file" view therefore returns 2–3 rows for one task. **Group by
`pgid`** to get one row per task, and **kill the whole group** (`killpg`) so the loop *and* its
children stop together.

## The agent's contract

To be visible + controllable, an agent (any runtime) must:

1. **Run ongoing work as a real OS process** — background it (the runtime's own backgrounding
   mechanism), never loop inside a single reply.
2. **Append output to the jobs dir** — `…/jobs/stream.log` (append mode). That file is the *only*
   channel by which recurring output reaches the device; holding it open is also what makes the task
   discoverable (the FD is the hook).
3. **Never promise async delivery it can't make** — no "I'll tell you when it's done"; the reply is
   one-shot. Say it's running and how to stop it.
4. **Stop via the host kill API, not its own process tool** — the runtime's kill often can't reach a
   detached, PTY-less loop (e.g. Hermes errors `tcsetattr: Inappropriate ioctl for device`). Call the
   host's group-kill instead.
5. **Answer "what's running" from the host list, not its own tools** — a runtime usually has several
   disjoint notions of background work (delegated tasks / processes / cron) and the LLM maps the
   question to the wrong one. The host `/v1/jobs` list is the single deterministic truth.

## The host control plane (reusable, deterministic)

The host process runs **inside** the sandbox/instance, so it reads `/proc` directly — no `docker
exec`, no TTY, no LLM.

- **`GET /v1/jobs`** → `{"jobs": [{"pgid", "pid", "cmd", "procs"}]}`. Walk `/proc/<pid>/fd`, keep the
  PIDs with a symlink into the jobs dir, drop the device's own `tail` follower, then **group by
  `pgid`** (one row per task; `cmd` = the most descriptive member, i.e. the loop, not a transient
  `sleep`). Deterministic: same kernel state → same output, every time.
- **`POST /v1/jobs/kill`** `{"pgid": N}` | `{"pid": N}` | `{"all": true}` → `killpg(pgid, SIGKILL)`
  for each target; returns `{killed, failed, remaining}`. Group-level, so the task actually stops.
- **Auth + logging** — gate both like the chat surface (bearer); log every list + kill (pids/pgids)
  so a stuck task is debuggable from the device's log view.
- **Streaming** — the device tails the jobs dir (`tail -F …/stream.log`) and surfaces / speaks each
  new line live. This is the out-of-band delivery the one-shot reply can't provide.
- **UI** — any front-end (TUI panel, web UI) consumes the same HTTP surface: list → select → kill.
  Because it's plain HTTP against the in-sandbox host, it works identically for a **local** sandbox
  and a **remote** instance (route by gateway + instance headers).

## Per-agent seams

Everything above is agent-agnostic. Only two pieces are runtime-specific:

| Piece | Reusable? | Adapt for a new runtime by… |
|---|---|---|
| `/v1/jobs` list + kill (`/proc`, `pgid`) | ✅ unchanged | nothing |
| jobs-dir convention + tail → device stream | ✅ unchanged | nothing |
| front-end panel (HTTP) | ✅ unchanged | nothing |
| **chat adapter** (e.g. `/v1/chat` ↔ Hermes ACP) | ❌ | implement the new runtime's transport |
| **convention injection** (the agent knowledge text) | ❌ (thin) | give the new agent the same 5-point contract |

### Adapting to another agent (checklist)

1. Mount the same jobs dir; run the same host control plane (`/v1/jobs` GET/kill + the tail stream).
2. Implement a chat adapter for the new runtime (or reuse it as-is if it already speaks the same
   HTTP/SSE shape).
3. Inject the [agent contract](#the-agents-contract) into the new agent's system prompt / knowledge.
4. Point the existing front-end at it. No job-machinery changes.

If the agent simply *can't* be taught the convention, it's still partly covered: any process it
backgrounds that writes into the jobs dir is listed + killable regardless — the harness observes the
kernel, not the agent.
