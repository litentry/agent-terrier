# VE delegate-sandbox image pipeline — build, push, precache (#568)

**Status:** IMPLEMENTED + verified live on the VE stack (2026-07-26). **Scope:** how the `hermes-sandbox` image that VE delegate sandboxes run gets built, pushed to the Volcano Container Registry, and made *actually live* in veFaaS. **Related:** [`ve-broker-runtime-port.md`](ve-broker-runtime-port.md) (the VE stack's port seams), [`aws-sandbox-spawn.md`](aws-sandbox-spawn.md) (the AWS twin of the spawn path), and the operator rules in `AGENTS.ops.md` "Delegate sandbox image (VE)".

![VE sandbox image pipeline](../assets/ve-sandbox-image-pipeline.svg)

## The one command

```bash
bash scripts/operator/build-image-hybrid.sh
```

That is the whole cycle for a normal code change — also the fleet console's **"build+push+preheat VE sandbox image · HYBRID"** item. It ends with the new image *preheated in veFaaS*, not merely pushed to a registry. Bringing live delegates onto the new image is then **one parent-control "update runtime" click per delegate (#577, Phase 4 below)** — an in-place kill + re-create with the same identity, grants and chat channel. No archive ceremony: archive remains only for actually *removing* a delegate.

For a **Hermes version bump** (the pin moves — #483), the multi-phase routine around this pipeline — drift → bump PR → the human merge gate → CR base re-seed → image cycle → in-image verify — is driven end-to-end by one ceremony driver (#578), re-run after every stop:

```bash
bash scripts/operator/ship-hermes.sh          # status (default) · ship · verify
```

It delegates every mutation to the scripts on this page and gates on observables (PR state, the `base/hermes:<pin>-<sha8>` tag in the CR, precache status, `hermes --version` inside the image); merging the bump PR stays a human step, and `--kill-pinners` is the explicit consent for the #577 kill-only unpin. Also the fleet console's **"ship Hermes bump · CEREMONY"** item — the bump counterpart of the HYBRID row above.

## Why the work is split across two machines

The pipeline looks over-engineered until you know that **two directions do not work**, both measured:

| Direction | What happens |
|---|---|
| **CN broker → GitHub / PyPI** | The Hermes installer's `git clone` runs ~20 min and dies `GnuTLS recv error (-54) … bytes of body are still expected` — **including with `--network host`**, so it is the transfer truncating, not container NAT. `pip install` from PyPI is the same link. |
| **Laptop → CN Container Registry (BULK)** | 39 retries could not land ~660 MB of genuinely-new layers into an empty repo: `toomanyrequests`, `short read … unexpected EOF`, and intermittent **DNS failure** for the CR host. The qualifier matters: that is the **no-mount-candidates** regime. An *incremental* push whose base layers already live in the CR **cross-repo-mounts** them (~18 real blob ops) and landed **first try** (measured 2026-07-28) — see the CR-tier section below. |

So neither machine can do the whole BULK job, and the CR refuses many-OPERATION pushes from anywhere (the frequency refusal below bit the broker's intra-region push hardest). The split follows: **the Mac compiles and seeds the foreign layers once; the routine push runs from whichever machine holds the seeded base locally** — normally the Mac, whose incremental push cross-mounts everything but the changed ~50 MB — **with the broker as the fallback builder/pusher and always the boot-gate + precache-refresh host.** Crucially, *at image-build time nothing crosses the border at all* on either path — the foreign layers ride the seeded base.

This is also why the daemon travels as a **~50 MB artifact** (a layer upload on the laptop path, an scp on the broker path) instead of a ~17 GB image over the registry protocol.

## Phase 1 — seed the base (RARE)

```bash
bash scripts/operator/seed-base-images.sh    # from a machine with good international network
```

Builds the Dockerfile's **stage 1 (`foreign`)** — the only steps that reach the public internet (Hermes clone + `pip install openviking`) — and publishes it to the CR, recording:

| Env key | What it is |
|---|---|
| `VE_BASE_HERMES` | the published `foreign` stage — Hermes + openviking preinstalled |
| `VE_BASE_AIO` / `VE_BASE_RUST` | CR mirrors of the Docker-Hub/ghcr build bases |

Run this **only on a deliberate Hermes/openviking bump**. The published tag encodes the Hermes pin, so a bump cannot silently reuse the old base, and the Dockerfile's **final stage re-asserts `hermes --version`** so a stale or wrong base fails the build loudly instead of shipping the wrong agent.

> **Current state (2026-07-27):** `VE_BASE_HERMES` is the **purpose-built base** — `base/hermes:0.19.0-3ef6bbd2`, published by `seed-base-images.sh` for the Hermes 0.19.0 bump (#576). It briefly ran on a *bootstrap pin* instead (a digest of the pre-split `hermes-sandbox` image, reused because a first attempt to push a clean base lost ~660 MB across 39 retries to the international CR link); the 0.19.0 push landed first try, so that workaround is retired. Expect the push to be the flaky part of any future bump and simply retry it — `docker push` resumes.

## Phase 2 — the hybrid (EVERY code push)

| Step | Where | What |
|---|---|---|
| 1 | Mac | cross-compile `agentkeys-daemon` for `linux/amd64` — **natively via `cargo-zigbuild` when installed** (#597: 2m56s full build measured 2026-08-10, glibc floor 2.35 = the hermes base's, vendored OpenSSL feature; `SBX_CROSS=qemu` forces the container path), else the QEMU builder |
| 2 | Mac | **push-path pick from observable state** (`--push-path` / `VE_PUSH_PATH`, default `auto`, printed loud): seeded `VE_BASE_HERMES` present in the local docker → **LAPTOP**, else **BROKER** |
| 3-L | Mac (LAPTOP path) | **BuildKit assembly `FROM $VE_BASE_HERMES`** (stage 1 skipped — the base layers stay **byte-identical** to the CR's, so they mount/exist on push, ~18 real blob ops: the only regime measured to clear the frequency refusal). The classic-builder+cache mode is a buildx-broken fallback only: a cold cache re-runs the foreign stage (~30 min, measured 2026-08-10) and its rebuilt NEW-digest layers 429 on push |
| 3-B | Mac → broker (BROKER path) | `scp` the ~50 MB binary; `setup-image.sh --from-binary`: `docker build` **FROM `$VE_BASE_HERMES`** — BuildKit **skips stage 1 entirely**, zero foreign egress, daemon `COPY` as the **last layer** — then `docker push` → CR, **intra-region** |
| 4 | broker | **veFaaS-faithful boot gate** (pod-env boot of the registry-live digest — Phase 3 below) |
| 5 | broker | `agentkeys-broker-server precache-refresh` → poll until 已预热 — the LAPTOP path reaches 4-5 via `setup-image.sh --refresh-only`, after which the broker's local image copy is **STALE**: never `--push-only` there until it rebuilds (the #578 footgun) |

Two design details that are load-bearing rather than cosmetic:

- **`FOREIGN_BASE` must be a global `ARG`** (declared before the *first* `FROM`). An `ARG` written inside a stage body is stage-scoped and invisible to a later `FROM`, which fails with `base name (${FOREIGN_BASE}) should not be blank`.
- **BuildKit is required on the broker** when `FOREIGN_BASE` is set — only BuildKit prunes an unreferenced stage. The classic builder walks every stage and would run the Hermes clone anyway, so `build.sh` hard-errors on that combination.

### Versioned tags — blue-green precache (#598, the DEFAULT)

Every cycle mints an immutable tag — `hermes-sandbox:v<utc-stamp>-g<sha8>` (`build-push-ve.sh`; the hybrid mints once and passes it to every leg) — instead of mutating `:latest`. This inverts the production-hostile ordering the mutable tag forced: a **new** URL has no existing precache registration, so `refresh_precache()` takes its **fresh-registration path — no delete, no pinner pre-flight** — and **live delegates keep serving the old version for the entire ~30 min preheat**. Nothing is killed or archived up front.

The cycle then has a gated second half, run after the preheat reports 已预热:

```bash
# 1. commit + push the env file's CR_IMAGE change (the flip gates on origin carrying it)
# 2. point SPAWNS at the new version (unit converge, step 5, on the VE host):
bash scripts/operator/build-image-hybrid.sh --flip
```

After the flip, new spawns and the #577 **"update runtime"** clicks use the new version — delegates migrate one at a time, each with only its own in-place restart. Old versions stay servable throughout; VE documents **100 image versions/repo** on 小微版 (the tier table above), so retention is not a near-term constraint. Opt-outs: `VE_CR_TAG=<tag>` pins an explicit tag (`VE_CR_TAG=latest` restores the mutable-tag semantics below), `VE_IMAGE_VERSIONING=0` disables the mint. **Mutable-tag mode keeps the old rules**: a same-tag re-push is invisible until a delete+re-add refresh, and a live delegate PINS that registration (`--kill-pinners` / archive). Follow-ups tracked on #598: a `precache-refresh --prune-stale` GC for old unpinned registrations + CR tag retention. The registration quota IS documented in the console (沙箱镜像 banner, read 2026-08-11): the preheat feature is in free public beta with a **default cap of 20 preheated images** and a **default 15-day retention (默认保留 15 天)** — whether the 15 days expires the warmed cache or the registration row is unverified; treat registrations older than ~2 weeks as suspect and re-preheat at the next flip.

### Layer budget — the push-op ceiling is structural (2026-08-10)

The refusal counts **every blob operation, existence checks included**: an 84-layer image (63 base + 21 final-stage) was 429'd from the Mac with *zero* bytes pending upload. Two structural changes keep every push deterministically under the measured-safe ~18 ops:

1. **Assembly-stage fold** (Dockerfile): all final-stage work runs in a build-local `assembly` stage; the shipped stage adds **5 `COPY --from` layers** instead of 21 (verified: 68 total). New files go into `assembly` and ride one of the five COPYs — never a sixth layer without re-checking the budget.
2. **Flat base** — `setup-image.sh --flatten-base` on the **broker**: re-publishes `VE_BASE_HERMES` as a **single-layer** image (`…/base/hermes-flat:<same suffix>`, config metadata re-applied, env-key parity asserted — the `function_exited` class), recorded as `VE_BASE_HERMES_FLAT` and preferred by every build once set → the final image is **~6 layers ≈ ~12 push ops**, and BOTH push hosts drop under the ceiling. Idempotent; re-run after every base re-seed. Its own push is few-op/many-byte (~13 GB single blob, intra-region, ~35 min at the 50 Mbps cap) — the one combination not yet measured; `docker push` resumes per-LAYER, so a truncated blob restarts that blob.

### The CR tier is a real ceiling on step 4 — know it before blaming the pipeline

`agent-terrier-1` is a **小微版 / Micro** instance (`ve cr ListRegistries` → `Type`). Per VE's [使用限制](https://www.volcengine.com/docs/6420/78488), that tier gets:

| | 小微版 | 标准版 |
|---|---|---|
| 公网带宽上限 | **50 Mbps** | 200 Mbps |
| VPC 接入配额 | **不支持** | 5 |
| 命名空间存储容量 | 500 GiB | 无限制 |
| 镜像版本数量 / repo | 100 | 5000 |

Two consequences worth stating plainly, because both contradict things this doc used to imply:

1. **The broker's push is NOT a privileged private path.** 小微版 has no VPC access, so it pushes over the *public* endpoint at 50 Mbps like any other client — a full ~15 GB image is ≥40 min at the cap. Its advantage over the laptop is proximity and reliability, not a special link. The pipeline is designed so this rarely matters: the daemon `COPY` is the last layer, so a normal code push moves ~50 MB.
2. **A `request frequency is too high, try later` refusal is UNDOCUMENTED — and retry-futile.** VE publishes no push QPS/frequency limit for any tier, and the [push-failure FAQ](https://www.volcengine.com/docs/6420/78516) covers only `unauthorized`. Measured 2026-07-27: a 3-layer push succeeded while an 81-layer push was refused **both** with ~15 GB of new layers and with ~50 MB into a repo already holding them; `max-concurrent-uploads=1` changed nothing; reads were fine throughout. So it is neither bytes, storage, nor concurrency — and there is **no documented reset window to wait for** (11–39 consecutive 60s-spaced retries all refused, measured 2026-07-28 and 2026-08-09). Two consequences in the tooling: the hybrid's `auto` push-path pick avoids entering this regime whenever the seeded base is local (the LAPTOP path's cross-mount push is the one measured escape), and `push_with_retry` (build.sh) **fails fast** — after `PUSH_FREQ_MAX_RETRIES` (default 3) consecutive frequency refusals it stops with rc 75 and prints that escape instead of grinding the 40-attempt transient budget. Past the tooling, escalate to VE support (提升实例配额 is their documented channel for limits). Because the refusal is undocumented, **no tier or config change is a verified fix**: 标准版's documented gains (bandwidth, VPC quota) are not the failing dimension, and whether it alters this refusal has never been measured — do not plan a migration around that assumption. A bump run is where this bites, because re-seeding the base pushes a fresh multi-GB image right before the hybrid does.

## Phase 3 — precache refresh: why a push is not enough

**veFaaS spawns the image it has PRECACHED, not what the registry currently serves.** A same-tag re-push is invisible to it. This produced a silent-chat incident (2026-07-23) where the CR held the new image while every sandbox kept booting the previous one.

### The boot gate runs first: a veFaaS pod's env is NOT docker's env (2026-07-30)

**A pod gets ONLY the function's env template + the per-instance `Envs` — the image's baked `ENV`s are NOT merged.** Plain `docker run` *does* merge them, so an image can boot green in every docker check on this page and still exit in every pod. Measured 2026-07-30: the re-seeded AIO base's entrypoint (`/opt/gem/entrypoint.sh`) had grown `mkdir -p "$LOG_DIR" "$XDG_RUNTIME_DIR"`, the function template — captured for `all-in-one-sandbox:1.10.0` — lacked `XDG_RUNTIME_DIR`, so every `CreateSandbox` died `mkdir: cannot create directory ''` → exit 1 → 403 `function_exited`. First symptom: a freshly-spawned delegate's chat silently never answered (the message sat in the channel feed; nginx showed no sandbox ever polling). The pod's own stdout lives in the function's **TLS log topic** (`GetFunction → TlsConfig`) — that is where the `mkdir` line was finally read; `GetFunctionInstanceLogs` 404s once the failed instance is GC'd (minutes).

`setup-image.sh` therefore runs a **boot gate before every precache refresh** (`run_vefaas_boot_gate`, also under `--refresh-only`):

1. resolve the **registry-live digest** of `CR_IMAGE` (never the local tag — the two diverged 2026-07-28 when a laptop escape-hatch push put `c8a98106…` in the CR while the broker's local build was `35e32195…`; the precache serves the CR one) and pull it;
2. fetch the **live** function env template — `GetFunction` via the operator-side `scripts/operator/lib/ve-api.py` (a stdlib port of `agentkeys-core::ve_sign`), creds from the broker unit's env family, needing the read-only `vefaas:GetFunction` grant ([`ve-broker-vefaas.json`](../../scripts/operator/policies/ve-broker-vefaas.json) Sid `FunctionReadForBootGate`; a 403 here means the cloud policies predate it — converge with `setup-cloud.sh --cloud ve`);
3. boot the digest with **`env -i` + exactly that template + the function's own `Command`** — pod semantics, image `ENV`s dropped — and require PID 1 alive after `AGENTKEYS_VEFAAS_GATE_SECS` (default 25 s).

A failing gate **blocks the refresh** and prints the container log (byte-for-byte what the pod would log) plus the baked-vs-template key diff with the exact console/`UpdateFunction` remediation. Both directions are measured on the live stack: the broken template reproduces the incident through the gate, and adding the missing keys (`XDG_RUNTIME_DIR=/tmp/runtime-gem`, `GEM_SERVER_PORT=8088`, `MCP_SERVER_PORT=8089`, `MCP_HUB_PORT=8079`) turns it green. Emergency opt-out: `AGENTKEYS_SKIP_VEFAAS_BOOT_GATE=1` — loud, because it re-opens exactly this class.

The same drift is caught **at its source** by `seed-base-images.sh`: on every run it diffs the AIO base's baked env keys against the live function template and fails listing the missing keys + values (opt-out `AGENTKEYS_SKIP_VEFAAS_ENV_CHECK=1`) — a base bump is the deliberate moment the template must be re-synced, the ship-time boot gate is the behavioral backstop.

`ve_faas.rs::refresh_precache()` therefore does: **List → Delete → verify GONE → Precache → poll until `success`**. Each part exists because of a measured failure mode:

| Fact | Consequence |
|---|---|
| `PrecacheSandboxImages` answers `already exists` for a registered URL without re-pulling | re-adding alone can never refresh a moved tag |
| `ListSandboxImages` exposes **no digest** | staleness is undetectable from the API — so refresh deletes unconditionally rather than comparing |
| `DeleteSandboxImage` answers **200 with `Result.Status:"failed"`** while a live instance runs the image | a bare 200 proves nothing; the pin is the live instance (`DescribeSandbox.ImageInfo.Id`) |
| `DeleteSandboxImage` answers 200 deleting **nothing** without body `Region` | the delete must be *observed* (entry absent from List) before re-adding |
| `ImageType` on List is required and **lowercase** (`private` / `public`) | `Private` → 400 `type is invalid` |

**A preheat takes ~30 minutes and a timeout is not a failure.** The verb waits up to 1 h by default; if it does time out the push already succeeded and the entry keeps preheating server-side. Re-running is safe and cheap: `refresh_precache()` **resumes** an in-flight (`caching`) entry instead of deleting it, so a retry never restarts the clock. Only a `success` entry takes the delete + re-add path.

**If a delegate is live it pins the registration** — the refresh stops and names the exact instance, delegate hash, and expiry. Two remedies (#577): re-run with **`--kill-pinners`** (`VE_REFRESH_KILL_PINNERS=1` through `setup-image.sh`) — a kill-ONLY unpin: the on-chain bindings stay active and each delegate returns on the new image via the update click once the preheat completes — or archive the delegate (Touch ID) if you actually want it gone. Instances also expire on their own within the veFaaS lifetime (default 1440 min), so an overnight cycle usually finds the registration unpinned.

### Spawn readiness: the pod is Ready when PORT 8090 listens — and the boot must fit ~29s (#589)

`CreateSandbox` is synchronous with a hard server-side **~29s cold-start budget**, and veFaaS readiness is *the configured port (8090, the hermes bridge) accepting connections*. Preheat makes the image itself instant — measured 2026-08-01, the container executed `/opt/gem/run.sh` **0.6s** after the CreateSandbox call — so the entire budget is spent on whatever sits in front of the bridge's `bind()`. The incident: the bridge ran the blocking ACP handshake (`hermes acp` spawn + `initialize`) *before* binding, 16–29s+ on 1 vCPU, so every cold spawn 408'd `function_cold_start_timeout` **while the pod kept booting** — and each blind retry created a duplicate instance (a booting instance is invisible to the reuse pre-check; 3 creates → 3 Ready instances → 3 chat loops on one channel).

Two layers fix it (#589): the bridge now **binds :8090 first and initializes ACP in the background** (gated endpoints answer 503 `acp_starting`; context files applied pre-init land in the first session), and the broker treats a cold-start 408 as **in-progress, not failure** — it parses the instance name out of the 408 and adopts it once `Ready` (`AGENTKEYS_VEFAAS_COLDSTART_WAIT_SECS`, default 120, 0 disables). Keep new boot-time work *behind* the bind, never in front of it. Related measured fact: `SetSandboxTimeout` can never extend past `create_time + <create-time Timeout>`, so with the full 1440-min lease at create the keep-alive is a designed no-op and expiry-re-create (#546) is the real path.

## Phase 4 — bringing delegates onto the new image (#577)

A sandbox **freezes its image at spawn**, so a completed preheat changes only what *future* creates boot. The user-facing half is the #577 update surface:

- **Staleness is visible, not shell-probed.** An instance freezes the pre-cache **registration id** it spawned from (`DescribeSandbox.ImageInfo.Id`) while the refresh mints a NEW registration id for the same tag — `frozen ≠ current` is exactly "running old bits". `POST /v1/agent/image-status` (J1_master; proxied by the daemon for parent-control) reports it per delegate; the Delegates page renders an **"update available"** chip and an **"update N stale agents"** batch button. The same response carries the instance's lease deadline plus the **live agent identity from the bridge's `/healthz`** (ACP-reported engine + version + LLM endpoint — the running truth, not the tag's claim), rendered as the card's **runtime**/**sandbox** rows, so "did the bump actually take" is answerable from the app instead of the `hermes --version` container probe below.
- **`POST /v1/agent/update`** (J1_master, chain-verified ownership, TIER_AGENT only) performs the in-place cycle: job-guard + Hermes-home export from the old instance → `KillSandbox` → re-create through the SAME #546 spawn-context ensure path a veFaaS-expiry re-create uses (fresh #552 J1, lazily re-provisioned metered gate key) → import + agent re-source in the replacement. No chain write, no Touch ID, no slot movement; audit emits `SandboxTeardown(reason="update")` + the usual `SandboxSpawn`.
- **What the hand-off preserves — and what it cannot.** The bridge's bearer-gated `/v1/sandbox/mgmt/*` surface (armed per delegate via the broker-derived `AGENTKEYS_SANDBOX_MGMT_TOKEN`) exports **on-disk `$HERMES_HOME` state** (SOUL.md, skills, backups — the image-owned `config*.yaml` chain is excluded both ways). The live **conversation is the hermes bridge's in-RAM ACP session** ("the session IS the memory") and restarts with the instance — exactly as it already does at every veFaaS expiry. Making transcripts durable is a Hermes-persistence follow-up, not something the relay can conjure.
- **Background jobs (#340) refuse the update** (409 `jobs_running`) unless forced — their output stream dies with the instance; the UI turns the button into "update anyway".
- A **pre-#577 instance** has no mgmt surface: the update still lands, with `session_migrated:false` and the reason surfaced; the capability heals once the new image runs.

## Entry points

| Command | Use |
|---|---|
| `scripts/operator/build-image-hybrid.sh` | **the normal path** — laptop-driven, ends with the new version preheated (#598: alongside the old) |
| `scripts/operator/build-image-hybrid.sh --flip` | the #598 second half — after 已预热 + the env commit, point spawns at the new version (unit converge) |
| `scripts/operator/seed-base-images.sh` | rare — only on a Hermes/openviking bump |
| `scripts/operator/setup-image.sh --from-binary` | the broker-side half the hybrid invokes (run directly if the binary is already staged) |
| `scripts/operator/setup-image.sh --push-only` | re-push + refresh with no rebuild — the usual "unpin, then re-run" follow-up (`VE_REFRESH_KILL_PINNERS=1` opts into the kill-only unpin) |
| `agentkeys-broker-server precache-refresh [--timeout-secs N] [--kill-pinners]` | refresh alone, on the broker, under the unit's env |
| `docker/hermes-sandbox/build-push-ve.sh` | **laptop fallback** — broker unreachable, or building outside CN. Split halves `--build-only` / `--push-only` exist here for a throttled push (docker push resumes, so each retry makes progress); they are script flags rather than fleet menu rows, because the hybrid retired the problem they solved. |

## Verifying a spawn really runs the new bits

**`/usr/local/bin/agentkeys-daemon` is a layer of the IMAGE — it exists on neither the broker host nor the operator laptop.** Every check below runs *inside a container*, either locally against the image copy or remotely inside a live sandbox. Running the commands in a broker or laptop shell just yields `No such file` and a misleading `0`.

**Check the image first — no spawn, no gateway, no Touch ID.** The laptop keeps the copy it pushed, so after any hybrid run you can interrogate the exact pushed bits offline (the digest match to `CR_IMAGE_DIGEST` is what makes this equivalent to asking the registry):

```bash
docker image inspect "$CR_IMAGE" --format '{{index .RepoDigests 0}}'   # must equal CR_IMAGE_DIGEST
docker run --rm --entrypoint sh "$CR_IMAGE" -c '
  hermes --version
  strings /usr/local/bin/agentkeys-daemon | grep -c AGENTKEYS_SESSION_JWT'   # 0 = STALE daemon layer
```

Pick the check that matches what you changed: **`hermes --version`** proves a Hermes bump landed, the **`strings` count** proves the daemon layer is post-#552. On an arm64 Mac Docker warns about the platform mismatch and still runs the amd64 image under emulation — the warning is expected, not a failure.

That covers "are the right bits in the registry". It cannot tell you what a *running* delegate booted, since a sandbox freezes its image at spawn — for that, go through the gateway.

**Then check a live sandbox.** This failure class is invisible from outside — the broker reports `Ready` and the gateway answers 200. Reach any sandbox port through the veFaaS gateway with `-H "x-faas-instance-name: <SandboxId>" -H "x-faas-proxy-port: N"` (8090 = hermes bridge, **3114 = the agentkeys-daemon ui-bridge**), then ask the agent to run:

```bash
strings /usr/local/bin/agentkeys-daemon | grep -c AGENTKEYS_SESSION_JWT   # 0 = STALE image
env | grep -c AGENTKEYS_SESSION_JWT                                      # 1 = broker injected fine
tail -6 /var/log/agentkeys-daemon.log                                    # the chat loop's own verdict
```

Cheap first pass without touching the sandbox: on the broker, `channel/poll` in the nginx access log coming only from the operator's laptop IP (never a VE address) proves no sandbox ever subscribed.

## Layer ordering — keep the daemon last

The daemon `COPY` is deliberately the **final** layer: it is the only thing that changes on a normal code push, so a rebuild invalidates exactly one ~50 MB layer and a re-push uploads only that. **Anything added below it re-inflates every incremental push** — put new steps above it.
