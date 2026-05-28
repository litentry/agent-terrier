# Issue #103 — aiosandbox + Hermes agent + AgentKeys demo on ESP32-S3

**Status:** DRAFT — sections C4, C5, C6 SUPERSEDED 2026-05-24, see banner below.
**Tracking issue:** [#103](https://github.com/litentry/agentKeys/issues/103)
**Branch:** `claude/hopeful-mccarthy-15e5ba`

> ## ⚠ DECISION 2026-05-28 — Option B with hooks-first architecture
>
> The integration architecture is **Option B** (vendor surface → Task Host runtime → both MCPs: aiosandbox loopback + AgentKeys over network), with **hooks as the primary IAM-guarantee mechanism** and the OpenAI-compatible proxy as a **lower-priority fallback** for hosts without a hook surface.
>
> Full reasoning and the IAM-tool-vs-IAM-guarantee distinction live in [`docs/wiki/agent-iam-guarantee-glossary.md`](../../wiki/agent-iam-guarantee-glossary.md); strategic anchor in [`docs/agent-iam-strategy.md`](../../agent-iam-strategy.md) §3.6 + §3.7; execution plan in [`docs/spec/plans/phase-1-fresh-user-wire-onboarding.md`](phase-1-fresh-user-wire-onboarding.md). The previous Rust-runtime runbook + verification + setup script were archived 2026-05-28 under `docs/archived/*-rust-runtime-2026-05*`.
>
> Phase split:
> - **Phase 1** (this PR + immediate follow-up): AgentKeys MCP server (7 tools per strategy §4.2), Hermes MCP registration inside aiosandbox.
> - **Phase 3** ([issue #133](https://github.com/litentry/agentKeys/issues/133)): reference hook configs for Tier-1 hosts (Claude Code, Codex, Hermes, OpenClaw), `agentkeys hook check` CLI helper, cap-mint pre-warming.
> - **Phase 3b** (after #133 ships): proxy fallback for Tier-2 hosts (xiaozhi-server, vendor mobile SDKs, plain `openai.ChatCompletion` scripts).
>
> ## ⚠ PIVOT 2026-05-24 (multiple rounds) — read strategic anchor FIRST: [`docs/agent-iam-strategy.md`](../../agent-iam-strategy.md)
>
> **Strategic frame**: AgentKeys is the **Agent IAM and memory control plane** for the AI device era. This issue ships Phase 1 from the strategy doc — a three-act demo that proves AgentKeys is Agent IAM, not chatbot infrastructure.
>
> **Hardware** (verified): MagicLick 2.5 (ESP32-S3 + ES8311 + 128×128 LCD + WiFi/4G) running xiaozhi-esp32 v1.9.4. See [`docs/research/xiaozhi-esp32-magiclink.md`](../../research/xiaozhi-esp32-magiclink.md).
>
> **Architecture** (MCP-direct, NOT Hermes-bridge): xiaozhi-server has first-class MCP support (`core/providers/tools/server_mcp/`). We register the AgentKeys MCP server in `mcp_server_settings.json`; the LLM (Qwen/Kimi/Doubao/Claude) calls our tools directly. No fork, no Hermes middleman. Hermes joins Phase 3 as a callable MCP tool (`hermes.execute_task`) the LLM can invoke for complex agentic work — not as the LLM-caller replacement. See [`docs/research/xiaozhi-hermes-architecture.md`](../../research/xiaozhi-hermes-architecture.md).
>
> **Phase 1 demo (three acts)** — replaces the single-act memory injection demo described below. Goal: <5-minute vendor pitch that reads as Agent IAM, not chatbot.
> - **Act 1 — Permissioned Memory**: device reads ONLY the memory namespace it's allowed to read (not "the device knows you" — "the device knows what it's allowed to know about you")
> - **Act 2 — Deterministic Denial**: user asks for a spend over the daily cap; `agentkeys.permission.check` returns `denied: daily_spend_cap_exceeded`; device refuses. No LLM in the decision.
> - **Act 3 — Online Revocation**: parent opens AgentKeys web UI, revokes payment scope; next device attempt fails immediately on online cap-token check.
>
> **Four architecture commitments** (corrected from earlier loose framing):
> 1. **Revocation**: *immediate online, bounded TTL/cache offline*. Not "no propagation delay." High-risk actions always online; low-risk reads use short-lived cached caps; offline mode denies sensitive actions by default.
> 2. **Audit (two-tier)**: real-time off-chain feed in parent-control UI + **2-min batched Merkle root anchored on-chain** (chain choice is deployment config; the strategy stays chain-agnostic per [`agent-iam-strategy.md`](../../agent-iam-strategy.md) §3.2). NOT real-time on-chain. The chain explorer is tamper-evidence proof, not the UX surface.
> 3. **Delegation**: `agentkeys.delegation.grant` is **schema-documented but not active** in v1. Returns `not_implemented_in_v1`. Active delegation lands in Phase 4.
> 4. **Zero orchestration in v1** — hard line. If a vendor needs orchestration, they pick a runtime (Hermes/OpenClaw/their own) via Phase 3 MCP tools.
>
> **What's NEW vs what's shipped**: cap-token machinery (broker, signer, K3/K10 HDKD, memory/cred/audit workers, per-actor isolation per issue #90) is already shipped via Stage 7+. New work for Phase 1: MCP server wrapper around existing backend RPCs (~1 week), parent-control web UI (mobile-responsive, ~3-4 days), two-tier audit wiring (~1 day), demo runbook (~half day). Total ~2 weeks.
>
> **Sections below**: §C3 (mock memory + daemon endpoint) still useful as backend context. §C4 (custom Hermes runtime as Rust crate) is **SUPERSEDED** — use the AgentKeys MCP server pattern from [`docs/research/volcano-ark-mcp-integration.md`](../../research/volcano-ark-mcp-integration.md). §C5 (Dockerfile with hermes-runtime) is **SUPERSEDED**. §C6 (custom ESP32 firmware) **SUPERSEDED for MagicLick demo** — firmware is unchanged. §C7 (deploy script) needs rework to provision the MCP server + xiaozhi-server stock + parent web UI instead of the bridge. The "Implementation order" and "Effort estimate" sections below reflect the older bridge-fork plan and should be read as historical context, not current spec.
>
> **What this means for the original plan sections:**
> - §C3 (mock memory + daemon endpoint) — **STILL VALID**, no changes
> - §C4 (custom Hermes runtime as a Rust crate) — **SUPERSEDED**. Use NousResearch Hermes-agent installed via official installer; no Rust crate to build
> - §C5 (sandbox Dockerfile with hermes-runtime program) — **SUPERSEDED**. Install Hermes-agent inside aiosandbox via the official script; add `xiaozhi-hermes-bridge` as a separate component  
> - §C6 (ESP32-S3 firmware from scratch) — **SUPERSEDED for the MagicLick demo**. Keep `firmware/esp32s3-agentkeys/` as a reference scaffolding for future custom hardware projects, but the MagicLick demo uses the unmodified xiaozhi firmware. Configure the device's server URL via its built-in WiFi captive portal (Path C in the research doc) to point at our `xiaozhi-hermes-bridge`.
> - §C7 (deploy script) — **PARTIALLY VALID**. Update to provision the bridge instead of a custom hermes-runtime.
> - §Implementation order — **SUPERSEDED** by the 6-step "Specific next steps" list in the research doc.
>
> Full rationale, hardware specs, communication protocols, four candidate reference server implementations, and hardware verification procedures live in [`docs/research/xiaozhi-esp32-magiclink.md`](../../research/xiaozhi-esp32-magiclink.md). A follow-up commit will rewrite the C-sections below to match the pivoted direction. Until then, read the research doc as the source of truth.
**Related research:**
- [`docs/research/aiosandbox/agent-infra-sandbox-analysis.md`](../../research/aiosandbox/agent-infra-sandbox-analysis.md)
- [`docs/research/aiosandbox/agent-infra-sandbox-runtime-probe.md`](../../research/aiosandbox/agent-infra-sandbox-runtime-probe.md)
- [`docs/research/ai-hardware-companion-office-hours.md`](../../research/ai-hardware-companion-office-hours.md) (Approach D)
- [`docs/arch.md`](../../arch.md) (agent-infra/sandbox is the canonical agent runtime; memory-service at `bots/<actor_omni_hex>/memory/*`)

## Goal

Ship a working end-to-end demo for the AgentKeys hardware-vendor wedge:

> An ESP32 hardware device, configured with one URL and one actor token, talks to a cloud-hosted `agent-infra/sandbox` running a Hermes agent runtime + `agentkeys-daemon`. The agent auto-injects a mock user-memory MD file from S3 at boot, so the device sounds personalized from the very first conversation.

This is the v0 buyer-pitch demo that the [office-hours design doc §9.6 Storyboard](../../research/ai-hardware-companion-office-hours.md) calls for, scoped down to **single device, single sandbox, single mock memory blob**. Cross-vendor portability, cap-token enforcement, multi-tenant orchestration, payment rails, and the parent-control app are out of scope for v0 demo.

## Why now

The office-hours diagnostic surfaced that the next critical step is a working demo a vendor can SEE — not more architecture docs. Approach D (AgentKeys-native sandbox) was chosen specifically because vendor integration friction collapses from "embed SDK in firmware" (2 months) to "point your device at a URL" (1 day). This issue ships that 1-day vendor onboarding story end-to-end.

## Scope

**IN scope:**

- One ESP32 device speaking to one cloud-hosted sandbox
- Mock memory injected from one S3 MD file at agent boot
- Single hardcoded actor (`O_demo_001`) for the demo
- Text-mode interaction (button press → text payload → agent → text response → serial-print or BLE-companion-app display); voice mode deferred to a follow-up issue
- Subsidized LLM (Qwen-class via DashScope or OpenRouter) for the agent
- Public-facing demo URL (`https://demo.aiosandbox.litentry.org` or similar)
- One-command setup script (idempotent per [CLAUDE.md "Idempotent remote-setup rule"](../../../CLAUDE.md))
- Demo runbook for live walk-throughs

**NOT in scope (deferred to follow-ups):**

- Voice STT/TTS pipeline (text-only v0 demo)
- Real `agentkeys-worker-memory` integration (demo uses mock S3 blob with direct `s3:GetObject`, bypasses cap-token verification)
- Cross-vendor memory portability (single-vendor v0)
- Multi-tenant sandbox orchestration (one sandbox per active demo; multi-tenancy follows in production phase)
- Pricing / billing / activation flow (no Stripe ACP / Alipay+ AMP)
- Cap-token enforcement on the memory read path (mock memory is read with a static signed URL for v0)
- Parent-control / consumer mobile app
- On-chain audit anchoring (off-chain audit only for v0; on-chain batch in Phase 2+)
- Real-time revocation UI

## Architecture

```
┌─────────────────────┐
│ ESP32 (~$5 board)   │
│ - WiFi config       │
│ - Hardcoded:        │
│   • sandbox URL     │
│   • actor_token     │
│ - Button → POST     │
│ - Response → serial │
└──────────┬──────────┘
           │ HTTPS POST /v1/chat
           │ Authorization: Bearer <actor_token>
           v
┌──────────────────────────────────────────────────────────┐
│ agent-infra/sandbox @ ghcr.io/agent-infra/sandbox        │
│ (cloud-hosted, supervisord PID 1)                        │
│                                                          │
│  [supervisord programs]                                  │
│   ├── gem-server (default, port 8088)  ← stock           │
│   ├── nginx (port 8080 frontend)       ← stock           │
│   ├── agentkeys-daemon (port 8089)     ← NEW            │
│   ├── hermes-runtime (port 8090)       ← NEW            │
│   └── (browser/code-server/jupyter — stock, unused for demo) │
│                                                          │
│  [boot sequence]                                         │
│   1. agentkeys-daemon starts; reads $ACTOR_OMNI from env │
│   2. agentkeys-daemon caches mock memory from S3         │
│      → GET s3://agentkeys-demo-memory/bots/<actor>/memory/profile.md │
│   3. hermes-runtime starts; queries daemon's            │
│      /v1/memory/<actor>/profile.md endpoint              │
│   4. hermes-runtime injects profile.md into system prompt│
│   5. /v1/chat is ready                                   │
│                                                          │
│  [request flow]                                          │
│   ESP32 → nginx → agentkeys-broker-server (forward)      │
│                → hermes-runtime /v1/chat                 │
│                → LLM (DashScope Qwen-Plus or OpenRouter) │
│                → response → ESP32                        │
└──────────────────────────────────────────────────────────┘
           │
           v
┌────────────────────────────────────────────┐
│ S3: agentkeys-demo-memory (us-east-1)      │
│   bots/O_demo_001/memory/profile.md        │ ← mock blob (versioned)
└────────────────────────────────────────────┘
```

Reuse of canonical AgentKeys primitives ([`docs/arch.md`](../../arch.md)):

- **Sandbox**: `agent-infra/sandbox` is already arch.md's chosen agent runtime substrate (§3.3a, §10.4)
- **Actor model**: `O_demo_001` is a fixed HDKD-derived actor omni for v0 demo (single actor; production binds per device)
- **Memory bucket layout**: `bots/<actor_omni_hex>/memory/<path>` matches arch.md §15.2 — we use the same layout with a demo prefix so the path stays canonical
- **Daemon**: `agentkeys-daemon` extends with one new GET endpoint `/v1/memory/<actor>/profile.md`; no new K-key infra needed
- **supervisord**: stock sandbox ships supervisord at PID 1 (per [runtime probe finding 3 in §1](../../research/aiosandbox/agent-infra-sandbox-runtime-probe.md)) — we register `agentkeys-daemon` + `hermes-runtime` as new programs in `/opt/gem/supervisord.conf`

## Components

### C1 — Mock memory MD blob (S3)

Path: `s3://agentkeys-demo-memory/bots/O_demo_001/memory/profile.md`

Content (sample fixture; team can iterate before demo day):

```markdown
---
actor_omni: O_demo_001
user_display_name: Kevin Cheng
timezone: Asia/Shanghai
last_updated: 2026-05-23T10:00:00Z
---

# User profile (demo fixture)

## Personal
- Lives in Shanghai
- Travels frequently between SH ↔ Chengdu for work
- Currently planning Chengdu trip 2026-05-25 → 2026-05-29
- Outstanding question: customs clearance for personal electronics (raised yesterday)

## Diet
- Loves spicy Sichuan food (especially mapo tofu, hotpot)
- 2 days of Fujian food in Singapore last week — would prefer Sichuan today
- Allergic to peanuts

## Family
- Wife Lin works remotely in Hangzhou
- 2 kids (Mia 8, Leo 5); Mia is into dinosaurs; Leo is into space

## Recent context
- Yesterday's chat: customs clearance question (no resolution)
- 3 days ago: discussed booking dinner via Meituan
- Default budget cap for autonomous purchases: ¥500/day
```

### C2 — `agentkeys-demo-memory` S3 bucket

- Region: `us-east-1` (matches `agentkeys-admin` operational region; PIPL note in office-hours doc §Constraints — for production we'll need a CN-cloud replica, but demo can run on AWS)
- Lifecycle: versioned, 30-day expiration for non-current versions
- Access: read-only signed URL for v0 demo (skip cap-token verification per Scope NOT-in-scope item)
- Provision via `scripts/setup-demo-aiosandbox.sh` step 1 (idempotent — skip if bucket exists, upload only if content drift)

### C3 — `agentkeys-daemon` new endpoint

Add handler to [`crates/agentkeys-daemon/src/handlers/`](../../../crates/agentkeys-daemon):

```rust
// GET /v1/memory/{actor_omni}/profile.md
// Demo-only endpoint — returns mock memory content from S3 bucket
// without cap-token verification. Production path goes through
// agentkeys-worker-memory + cap-token check.
async fn get_demo_memory_profile(
    Path(actor_omni): Path<String>,
    State(state): State<AppState>,
) -> Result<String, AppError> {
    if !state.config.demo_mode {
        return Err(AppError::DemoEndpointDisabled);
    }
    let s3_key = format!("bots/{}/memory/profile.md", actor_omni);
    let content = state
        .s3_client
        .get_object()
        .bucket(&state.config.demo_memory_bucket)
        .key(&s3_key)
        .send()
        .await?
        .body
        .collect()
        .await?;
    Ok(String::from_utf8(content.to_vec())?)
}
```

- Demo endpoint is gated behind `AGENTKEYS_DEMO_MODE=1` env var; off by default
- Reuses existing S3 client + IAM role wiring in the daemon
- No cap-token verification in v0 — the memory blob is "public" for the demo
- Logs every read for audit-trail (off-chain, append to local journal)

### C4 — Hermes agent runtime (`agentkeys-hermes-runtime`)

NEW crate at `crates/agentkeys-hermes-runtime/`:

- Single binary that serves `POST /v1/chat`
- At startup: HTTP GET `http://localhost:8089/v1/memory/{actor_omni}/profile.md` (calls the daemon on the loopback)
- Inject profile.md content as the system prompt prefix:
  ```
  You are a helpful AI companion. Below is the user's profile and recent context.
  Respond conversationally, referencing relevant context when natural.

  ---
  {profile_md}
  ---
  ```
- LLM backend: configurable via env var
  - `AGENTKEYS_LLM_PROVIDER=dashscope|openrouter|claude|openai`
  - `AGENTKEYS_LLM_MODEL=qwen-plus|claude-haiku|gpt-4o-mini|...`
  - `AGENTKEYS_LLM_API_KEY=...`
- Default: DashScope Qwen-Plus (cheap, low-latency for China, ~$0.001/1K tokens)
- Chat endpoint:
  ```
  POST /v1/chat
  Authorization: Bearer <actor_token>
  Body: {"query": "string"}
  Response: {"response": "string", "memory_loaded": true, "tokens_used": N}
  ```

**Naming note**: "Hermes" in this issue refers to the lightweight AgentKeys-native runtime we're shipping for this demo, NOT NousResearch's Hermes LLM and NOT an existing third-party project. We picked the name in [office-hours §Approach D](../../research/ai-hardware-companion-office-hours.md). A 1-week research spike (open question §1 below) should confirm whether a public OSS project named "Hermes" already occupies this namespace and we need to rename — best candidates if rename needed: `agentkeys-companion`, `agentkeys-runtime`, `agentkeys-shell`.

### C5 — Extended sandbox image

NEW Dockerfile at `docker/aiosandbox-demo/Dockerfile`:

```dockerfile
FROM ghcr.io/agent-infra/sandbox:latest

# Install agentkeys binaries
COPY --from=builder /target/release/agentkeys-daemon /usr/local/bin/
COPY --from=builder /target/release/agentkeys-hermes-runtime /usr/local/bin/

# Register as supervisord programs
COPY supervisord.d/agentkeys-daemon.conf /opt/gem/supervisord.d/
COPY supervisord.d/hermes-runtime.conf /opt/gem/supervisord.d/

# Pre-create memory cache dir (writable by gem)
RUN mkdir -p /home/gem/.agentkeys && chown gem:gem /home/gem/.agentkeys

# Expose ports
EXPOSE 8080 8089 8090
```

Supervisord programs (per [runtime probe §4 B10](../../research/aiosandbox/agent-infra-sandbox-runtime-probe.md)):

```ini
# /opt/gem/supervisord.d/agentkeys-daemon.conf
[program:agentkeys-daemon]
command=/usr/local/bin/agentkeys-daemon serve --port 8089
user=gem
environment=AGENTKEYS_DEMO_MODE=1,ACTOR_OMNI=O_demo_001,DEMO_MEMORY_BUCKET=agentkeys-demo-memory
autostart=true
autorestart=true
stdout_logfile=/var/log/agentkeys-daemon.log

# /opt/gem/supervisord.d/hermes-runtime.conf
[program:hermes-runtime]
command=/usr/local/bin/agentkeys-hermes-runtime serve --port 8090 --daemon-url http://localhost:8089
user=gem
environment=AGENTKEYS_LLM_PROVIDER=dashscope,AGENTKEYS_LLM_MODEL=qwen-plus
autostart=true
autorestart=true
stdout_logfile=/var/log/hermes-runtime.log
```

### C6 — ESP32-S3 firmware (text mode v0)

Path: `firmware/esp32s3-agentkeys/`

**Hardware target:** ESP32-S3-DevKitC-1 (or compatible ESP32-S3-WROOM-1 board). Rationale:

- Native USB-OTG → flash + console via single USB-C cable, no separate UART chip
- PSRAM-capable (8MB external) → audio buffers fit for the voice-mode follow-up
- Xtensa LX7 with AI vector instructions → on-device wake-word feasible in v1
- BLE 5 + WiFi 802.11 b/g/n
- ~$10-15 dev board; underlying ESP32-S3 chip is <$5 in BOM volume
- Matches MCU-class authenticity (FoloToy / Ropet / BubblePal ship MCU-class chips)

**Stack:** PlatformIO + ESP-IDF (not Arduino). Rationale:

- ESP-IDF exposes S3-specific features (native USB CDC, PSRAM, ESP-DSP, secure boot, OTA) that Arduino abstracts away
- PlatformIO wraps it with VSCode integration + reproducible builds + dependency lock
- Production AI-toy vendors use ESP-IDF — the demo code can become a reference integration rather than throwaway

**Module structure:**

```
firmware/esp32s3-agentkeys/
├── platformio.ini          # board=esp32-s3-devkitc-1, framework=espidf
├── README.md               # flash + WiFi config quickstart
├── sdkconfig.defaults      # USB CDC console, PSRAM, mbedTLS, partition table
├── partitions.csv          # NVS + factory + OTA partition layout
├── CMakeLists.txt          # ESP-IDF project root
├── .gitignore              # build/, .pio/, secrets.h
└── main/
    ├── CMakeLists.txt      # component registration
    ├── main.c              # app_main entrypoint + FreeRTOS task spawn
    ├── config.h            # SANDBOX_URL, ACTOR_TOKEN, GPIO pin assignments
    ├── secrets.h.example   # WiFi SSID/PASSWORD template (copy → secrets.h, gitignored)
    ├── wifi_sta.h/.c       # WiFi STA mode + reconnect loop
    ├── https_chat.h/.c     # POST /v1/chat with Bearer auth + JSON parse
    ├── button.h/.c         # GPIO interrupt → FreeRTOS queue event
    └── led_status.h/.c     # RGB status LED state machine (idle/processing/error)
```

**FreeRTOS task layout:**

| Task | Priority | Purpose |
|---|---|---|
| `wifi_task` | 5 | Connect WiFi STA, reconnect on disconnect, signal `WIFI_READY` event |
| `button_task` | 4 | Debounce GPIO interrupt, emit `BUTTON_PRESSED` event |
| `chat_task` | 3 | Wait for button event → read user input from USB CDC → POST → parse JSON → print response to USB CDC + LED status update |
| `led_task` | 2 | Drive on-board RGB LED based on state machine (boot=red, idle=blue dim, processing=blue pulsing, error=red flashing) |

Tasks communicate via FreeRTOS queues + event groups; no shared globals.

**Behavior (v0):**

1. On boot: connect to WiFi (config from NVS or `secrets.h` fallback), print `[agentkeys] ready` to USB CDC
2. On button press (GPIO 0, the boot button on DevKitC-1): prompt for user input over USB CDC (`> `)
3. User types message + ENTER over USB CDC; firmware POSTs `https://demo.aiosandbox.litentry.org/v1/chat` with `Authorization: Bearer <ACTOR_TOKEN>` and body `{"query": "<text>"}`
4. Parse JSON response, print `agent: <text>` to USB CDC; flash LED on success
5. On error (WiFi loss, TLS fail, HTTP non-2xx, JSON parse fail): LED flashes red, print `[error] <reason>` to USB CDC

**Config sources (priority order):**

1. NVS-stored config (set via serial command `agentkeys config set sandbox_url ...`) — production path
2. `secrets.h` compile-time defines (gitignored, copy from `secrets.h.example`) — dev path
3. Hardcoded fallback in `config.h` — last-resort default

**Hardcoded fallback for v0 demo:**

```c
#define DEFAULT_SANDBOX_URL "https://demo.aiosandbox.litentry.org/v1/chat"
#define DEFAULT_ACTOR_TOKEN "demo_token_O_demo_001_changeme"
```

Token is validated by hermes-runtime against `AGENTKEYS_DEMO_ACTOR_TOKEN` env var on the sandbox side.

**Voice mode follow-up (NOT in v0 scope, but architecture-friendly):** I2S mic (INMP441) + I2S DAC (MAX98357A) + PSRAM-backed ring buffers + WebSocket streaming to sandbox `/v1/audio` endpoint. ESP-IDF's `esp_codec_dev` component + ESP-DSP wake-word are the building blocks. Tracked as separate follow-up issue (TBD).

### C7 — Demo deploy script

NEW: `scripts/setup-demo-aiosandbox.sh`

Idempotent per [CLAUDE.md "Idempotent remote-setup rule"](../../../CLAUDE.md) — every step pre-checks state and short-circuits if already done.

Step inventory:

| Step | Action | Idempotency check |
|---|---|---|
| 1 | Build agentkeys-daemon + agentkeys-hermes-runtime binaries (cargo) | `[ -x target/release/agentkeys-hermes-runtime ]` |
| 2 | Build demo sandbox image (`docker build docker/aiosandbox-demo/`) | `docker image inspect agentkeys/aiosandbox-demo:latest` |
| 3 | Provision `agentkeys-demo-memory` S3 bucket | `aws s3api head-bucket --bucket agentkeys-demo-memory --region us-east-1` |
| 4 | Upload mock memory MD to S3 | content hash diff vs S3 ETag |
| 5 | Deploy sandbox container to demo host (single VM behind nginx + TLS) | `systemctl is-active aiosandbox-demo.service` |
| 6 | Health-check `https://demo.aiosandbox.litentry.org/v1/chat` returns 200 | curl + jq check |
| 7 | Print ESP32 config: sandbox URL + actor token | always print (informational) |

Output convention per CLAUDE.md: `ok proceeding` / `skip <reason>` / `fail <reason>` per step.

### C8 — Demo runbook

NEW: `docs/demo-aiosandbox-runbook.md`

Operator-facing 1-pager:
- One-command setup
- ESP32 flashing instructions
- Live demo script (what to say into the serial, what the audience sees)
- Troubleshooting (firmware → WiFi → sandbox → LLM, each layer's failure signature)
- How to swap the mock memory blob mid-demo (change S3 file + restart agent)

## Implementation order

Sequenced for incremental verifiability — each step lands a testable artifact:

| # | Deliverable | Verify by |
|---|---|---|
| 1 | Mock memory MD fixture in `tests/fixtures/demo-profile.md` | File exists; passes markdown lint |
| 2 | New crate `agentkeys-hermes-runtime` with `/v1/chat` stub (no LLM yet) | `cargo test -p agentkeys-hermes-runtime` |
| 3 | Hook hermes-runtime to DashScope Qwen-Plus; chat returns LLM response (no memory yet) | `curl localhost:8090/v1/chat -d '{"query":"hi"}'` returns response |
| 4 | Add `/v1/memory/{actor}/profile.md` endpoint to agentkeys-daemon (returns hardcoded test fixture, no S3 yet) | `curl localhost:8089/v1/memory/O_demo_001/profile.md` returns fixture |
| 5 | Hermes-runtime fetches memory from daemon at startup; system prompt includes profile | Chat response references profile facts (e.g., "Kevin", "Chengdu", "spicy") |
| 6 | Provision S3 bucket + upload fixture via `setup-demo-aiosandbox.sh` step 3-4 | `aws s3 ls s3://agentkeys-demo-memory/bots/O_demo_001/memory/` |
| 7 | agentkeys-daemon reads from S3 (not hardcoded fixture) | Change S3 file, restart daemon, chat reflects new profile |
| 8 | Build extended sandbox Dockerfile with supervisord configs | `docker run agentkeys/aiosandbox-demo:latest` boots clean |
| 9 | Deploy sandbox to demo host with TLS + public URL | `curl https://demo.aiosandbox.litentry.org/v1/chat` succeeds |
| 10 | Write ESP32 firmware, flash to board | Button press → text query → response on serial |
| 11 | End-to-end: ESP32 → sandbox → LLM → response on serial, reflecting memory | Live demo |
| 12 | Write `docs/demo-aiosandbox-runbook.md` + commit + push | Operator can re-run from doc alone |

## Acceptance criteria

A reviewer takes the demo runbook, runs `bash scripts/setup-demo-aiosandbox.sh` on a fresh demo host, flashes the ESP32 firmware to a fresh board, and within **15 minutes** is able to:

- Send a text query from the ESP32 via serial-input
- Receive a response that demonstrably reflects the mock memory content (e.g., calls user by name "Kevin", references the Chengdu trip, knows the spicy food preference)
- Swap the S3 memory blob and see the next response reflect the new content (after agent restart)
- Read the demo runbook to understand every command they ran

## Open questions for kickoff (resolve before step 3)

1. **"Hermes" naming**: confirm internal name vs. potential OSS conflict. If OSS Hermes exists in this space, rename to `agentkeys-companion-runtime` or `agentkeys-shell`.
2. **LLM provider for demo**: DashScope (China-friendly, cheap, low-latency) vs. OpenRouter (global, more model choice) vs. direct Claude/OpenAI (premium, expensive). Default DashScope unless team has DashScope-access friction.
3. **Demo host**: reuse Heima broker host (per `scripts/setup-broker-host.sh`) or spin up a separate dedicated VM? Recommend separate to avoid blast radius on the broker.
4. **Voice mode timeline**: defer to a follow-up issue, or stretch goal for this issue? Recommend defer — text-mode demo is enough to validate the pitch with vendors.
5. **ESP32 board choice**: ~~ESP32-WROOM-32 vs ESP32-S3~~ **CONFIRMED: ESP32-S3** (ESP32-S3-DevKitC-1 dev board). Native USB-OTG + PSRAM + AI vector instructions all matter — PSRAM for the voice follow-up, native USB for faster iteration, AI instructions for on-device wake-word in v1. Same MCU-class authenticity as WROOM-32, ~$10-15 dev board.
6. **Auth**: skip JWT for v0 demo or use simple bearer token? Recommend simple static bearer token tied to actor_omni — easy to demo, easy to revoke (just restart the sandbox with a new token).

## Dependencies

- **agent-infra/sandbox**: stock image, no fork needed for v0
- **AgentKeys Stage 7+ stack**: agentkeys-daemon exists, extend with one new GET handler
- **agentkeys-worker-memory**: NOT used in v0 demo (mock bypasses it); production path uses it
- **AWS S3**: existing `agentkeys-admin` profile, `us-east-1`
- **LLM provider account**: DashScope or OpenRouter, ~$10/month credit is more than enough for demos
- **ESP32 hardware**: $5-15 board, off-the-shelf
- **Demo host**: small VM (1 vCPU / 2GB RAM is plenty for stock sandbox per `docker-compose.yaml mem_limit: 8g` — overprovision to 2 vCPU / 4GB to be safe)
- **TLS cert**: Let's Encrypt via certbot, same pattern as `setup-broker-host.sh`

## Effort estimate

- Steps 1-7 (Rust + S3 + memory injection): **~1.5 weeks**
- Steps 8-9 (Dockerfile + deploy): **~3 days**
- Steps 10-11 (ESP32 + end-to-end): **~1 week**
- Step 12 (runbook): **~2 days**
- **Total: ~1-2 weeks for a working v0 demo** (revised 2026-05-24 from original ~3 week estimate)

**The revision happened because** the [risk-verification research](../../research/xiaozhi-hermes-risks.md) showed all three identified risks were either built-in-mitigated (R1: Hermes session headers, 2-4 hrs), mostly-not-real (R2: learning loop is background-off-turn-path), or fine-for-v0 (R3: gateway is multi-tenant by design). A newly discovered fourth risk (R4: cold agent construction per request adds 50-300ms) needs 1 day of fork-local pooling work. Net effect: bridge work ~3-4 days, parallel tracks (AgentKeys daemon endpoint, S3 mock, device config, runbook) ~3-4 days. Calendar time ~1-2 weeks depending on engineer concurrency.

This fits the office-hours §9.7 next-moves timeline: demo ready in 1-2 weeks, vendor outreach happens in parallel (the assignment from §The Assignment).

## What landed (to fill at PR time)

*To be completed by the implementing engineer at PR time per [CLAUDE.md plan-completion policy](../../../CLAUDE.md).*

## What did NOT land (to fill at PR time)

*To be completed by the implementing engineer at PR time per [CLAUDE.md plan-completion policy](../../../CLAUDE.md). If empty, state "All plan steps shipped."*
