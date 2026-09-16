# VE delegate-sandbox image pipeline — build, push, precache (#568/#621)

**Status:** IMPLEMENTED + verified live on the VE stack (first dsh cycle 2026-08-24; pipeline machinery live since 2026-07-26). **Scope:** how the `dsh-sandbox` image that VE delegate sandboxes run gets built, pushed to the Volcano Container Registry, and made *actually live* in veFaaS. Since **#621** there is ONE runtime (DeepSeek Harness, `dsh` — [`delegate-runtime-dsh.md`](delegate-runtime-dsh.md)) and ONE image family; the hermes-era pipeline this machinery was built on is deleted, and its incident history is kept below where it still teaches the contract. **Related:** [`ve-broker-runtime-port.md`](ve-broker-runtime-port.md) (the VE stack's port seams), [`aws-sandbox-spawn.md`](aws-sandbox-spawn.md) (the AWS twin of the spawn path), and the operator rules in `AGENTS.ops.md` "Delegate sandbox image (VE)".

![VE sandbox image pipeline](../assets/ve-sandbox-image-pipeline.svg)

## The one command

```bash
bash scripts/operator/build-image-dsh.sh
```

That is the whole cycle for a normal code change — also the fleet console's **"build+push+preheat VE DSH sandbox image · HYBRID"** item. It ends with the new image *preheated in veFaaS*, not merely pushed to a registry. Bringing live delegates onto the new image is then **one parent-control "update runtime" click per delegate (#577, Phase 4 below)** — an in-place kill + re-create with the same identity, grants and chat channel — or simply their next **#594 lease rotation**, which performs the same cycle automatically. No archive ceremony: archive remains only for actually *removing* a delegate.

For a **dsh version bump** (the pin moves — #619), the multi-phase routine around this pipeline — drift + the permission-contract diff → bump PR → the human merge gate (G1) → CR base re-seed → image cycle → the env commit (G2) → flip → live verify — is driven end-to-end by one ceremony driver, re-run after every stop:

```bash
bash scripts/operator/ship-dsh.sh          # status (default) · ship · verify
```

It delegates every mutation to the scripts on this page and gates on observables (PR state, the pin-encoded `base/dsh:<pins>` tag in the CR, precache status, the live unit's `CR_IMAGE`); merging the bump PR stays a human step — a moved `ApprovalOutcome`/`ApprovalPolicy`/`ToolGuard` contract STOPS the bump outright (#619). Also the fleet console's **"ship dsh bump · CEREMONY"** item.

## Why the work is split across two machines

The pipeline looks over-engineered until you know that **two directions do not work**, both measured (hermes era, 2026-07 — the constraints are properties of the network and the CR, not the runtime):

| Direction | What happens |
|---|---|
| **CN broker → GitHub / npm / PyPI** | A foreign fetch runs ~20 min and dies `GnuTLS recv error (-54) … bytes of body are still expected` — **including with `--network host`**, so it is the transfer truncating, not container NAT. |
| **Laptop → CN Container Registry (BULK)** | 39 retries could not land ~660 MB of genuinely-new layers into an empty repo: `toomanyrequests`, `short read … unexpected EOF`, and intermittent **DNS failure** for the CR host. The qualifier matters: that is the **no-mount-candidates** regime. An *incremental* push whose base layers already live in the CR **cross-repo-mounts** them (~18 real blob ops) and landed **first try** (measured 2026-07-28) — see the CR-tier section below. |

So neither machine can do the whole BULK job, and the CR refuses many-OPERATION pushes from anywhere. The split follows: **the Mac compiles and seeds the foreign layers once; the routine push runs from the Mac, whose incremental push cross-mounts everything but the changed ~50 MB** — with the broker as the boot-gate + precache-refresh host. Crucially, *at image-build time nothing crosses the border at all* — the foreign layers ride the seeded base.

This is also why the daemon travels as a **~50 MB layer** instead of a ~17 GB image over the registry protocol.

## Phase 1 — seed the base (RARE)

```bash
bash scripts/operator/seed-dsh-base.sh    # from a machine with good international network
```

Builds the Dockerfile's **stage 1 (`foreign`)** — the only steps that reach the public internet: Node from nodejs.org (exact-pinned, checksum-verified against SHASUMS256.txt), `npm install -g` of the exact-pinned `@deepseek-ai/dsh`, the `@openviking/dsh-memory-plugin` profile dep, and pip `openviking` (0.4.16+, the `viking://~` requirement measured on #610) — and publishes it to the CR, recording:

| Env key | What it is |
|---|---|
| `VE_BASE_DSH` | the published `foreign` stage — Node + dsh + OV plugin + openviking preinstalled |
| `VE_BASE_DSH_FLAT` | the #598 ONE-layer republication (`setup-image.sh --flatten-base --family dsh`, on the broker) — builds prefer it once set |
| `VE_BASE_AIO` | CR mirror of the AIO sandbox base the Dockerfile builds FROM |

Run this **only on a deliberate pin bump** (the #619 gate files the PR). The published tag ENCODES all three pins (`<dsh>-ovp<plugin>-ov<pip>`), so a bump cannot silently reuse the old base, and the final stage re-asserts the installed dsh version so a stale or wrong base fails the build loudly.

## Phase 2 — the cycle (EVERY code push)

| Step | Where | What |
|---|---|---|
| 1 | Mac | cross-compile `agentkeys-daemon` for `linux/amd64` — **natively via `cargo-zigbuild`** (#597: 2m56s full build measured 2026-08-10, glibc floor 2.35 = the base's, vendored OpenSSL; `SBX_CROSS=qemu` forces the container path) |
| 2 | Mac | **push-path pick from observable state** (`VE_PUSH_PATH`, default `auto`, printed loud): seeded `VE_BASE_DSH` present in the local docker → **LAPTOP** (the only measured regime that clears the frequency refusal), else the honest fallback advice |
| 3 | Mac | **BuildKit assembly `FROM $VE_BASE_DSH`** (stage 1 skipped — the base layers stay **byte-identical** to the CR's, so they mount on push, ~18 real blob ops), suite tarball packed from `packages/agentkeys-dsh`, daemon `COPY` last; local boot smoke (`:8090/healthz` from an env-clean container); push the versioned tag |
| 4 | broker | **veFaaS-faithful boot gate** (pod-env boot of the registry-live digest — Phase 3 below) |
| 5 | broker | `agentkeys-broker-server precache-refresh` → poll until 已预热 — reached via `setup-image.sh --refresh-only` over ssh (the ONE owner of the refresh invocation) |

Two design details that are load-bearing rather than cosmetic:

- **`FOREIGN_BASE` must be a global `ARG`** (declared before the *first* `FROM`). An `ARG` written inside a stage body is stage-scoped and invisible to a later `FROM`, which fails with `base name (${FOREIGN_BASE}) should not be blank`.
- **BuildKit is required** when `FOREIGN_BASE` is set — only BuildKit prunes an unreferenced stage. The classic builder walks every stage and would run the foreign fetches anyway, so `build.sh` hard-errors on that combination.

### Versioned tags — blue-green precache (#598, the DEFAULT)

Every cycle mints an immutable tag — `dsh-sandbox:v<utc-stamp>-g<sha8>` — instead of mutating `:latest`. This inverts the production-hostile ordering a mutable tag forces: a **new** URL has no existing precache registration, so `refresh_precache()` takes its **fresh-registration path — no delete, no pinner pre-flight** — and **live delegates keep serving the old version for the entire preheat**. Nothing is killed or archived up front.

The cycle then has a gated second half, run after the preheat reports 已预热:

```bash
# 1. commit + push the env file's CR_IMAGE change (the flip gates on origin carrying it)
# 2. point SPAWNS at the new version (unit converge, step 5, on the VE host):
bash scripts/operator/build-image-dsh.sh --flip
```

After the flip, new spawns, the #577 **"update runtime"** clicks and the #594 lease rotations use the new version — delegates migrate one at a time, each with only its own in-place restart. Old versions stay servable throughout. **Tag reuse:** a re-run for the same commit reuses its versioned tag, so a timed-out preheat RESUMES on the same URL instead of orphaning it. Opt-outs: `VE_CR_TAG=<tag>` pins an explicit tag (`VE_CR_TAG=latest` restores mutable-tag semantics: a same-tag re-push is invisible until a delete+re-add refresh, and a live delegate PINS that registration — `--kill-pinners`). The registration quota IS documented in the console (沙箱镜像 banner, read 2026-08-11): the preheat feature is in free public beta with a **default cap of 20 preheated images** and a **default 15-day retention (默认保留 15 天)** — whether the 15 days expires the warmed cache or the registration row is unverified; treat registrations older than ~2 weeks as suspect and re-preheat at the next flip.

### Layer budget — the push-op ceiling is structural (2026-08-10)

The refusal counts **every blob operation, existence checks included**: an 84-layer image was 429'd from the Mac with *zero* bytes pending upload. Two structural rules keep every push deterministically under the measured-safe ~18 ops:

1. **Thin final stage** (Dockerfile): the shipped stage adds a handful of `COPY` layers over the base — new files ride an existing COPY, never a new layer without re-checking the budget.
2. **Flat base** — `setup-image.sh --flatten-base --family dsh` on the **broker**: re-publishes `VE_BASE_DSH` as a **single-layer** image (config metadata re-applied, env-key parity asserted — the `function_exited` class), recorded as `VE_BASE_DSH_FLAT` and preferred by every build once set. Idempotent; re-run after every base re-seed. Its own push is few-op/many-byte (single blob, intra-region; `docker push` resumes per-LAYER).

### The CR tier is a real ceiling — know it before blaming the pipeline

`agent-terrier-1` is a **小微版 / Micro** instance (`ve cr ListRegistries` → `Type`). Per VE's [使用限制](https://www.volcengine.com/docs/6420/78488), that tier gets:

| | 小微版 | 标准版 |
|---|---|---|
| 公网带宽上限 | **50 Mbps** | 200 Mbps |
| VPC 接入配额 | **不支持** | 5 |
| 命名空间存储容量 | 500 GiB | 无限制 |
| 镜像版本数量 / repo | 100 | 5000 |

Two consequences worth stating plainly:

1. **The broker's push is NOT a privileged private path.** 小微版 has no VPC access, so it pushes over the *public* endpoint at 50 Mbps like any other client. The pipeline is designed so this rarely matters: the daemon `COPY` is the last layer, so a normal code push moves ~50 MB.
2. **A `request frequency is too high, try later` refusal is UNDOCUMENTED — and retry-futile.** VE publishes no push QPS/frequency limit for any tier, and the [push-failure FAQ](https://www.volcengine.com/docs/6420/78516) covers only `unauthorized`. Measured 2026-07-27/28: a 3-layer push succeeded while an 81-layer push was refused both with ~15 GB of new layers and with ~50 MB into a repo already holding them; `max-concurrent-uploads=1` changed nothing; 11–39 consecutive spaced retries all refused. So the push fail-fasts — after 3 consecutive frequency refusals it stops with **rc 75** and prints the two real remedies (flatten the base; push from the laptop with the base local) instead of grinding. Past the tooling, escalate to VE support (提升实例配额). Because the refusal is undocumented, **no tier or config change is a verified fix** — do not plan a migration around that assumption.

## Phase 3 — precache refresh: why a push is not enough

**veFaaS spawns the image it has PRECACHED, not what the registry currently serves.** A same-tag re-push is invisible to it. This produced a silent-chat incident (2026-07-23, hermes era) where the CR held the new image while every sandbox kept booting the previous one.

### The boot gate runs first: a veFaaS pod's env is NOT docker's env (2026-07-30)

**A pod gets ONLY the function's env template + the per-instance `Envs` — the image's baked `ENV`s are NOT merged.** Plain `docker run` *does* merge them, so an image can boot green in every docker check on this page and still exit in every pod. Measured 2026-07-30: a re-seeded AIO base's entrypoint had grown `mkdir -p "$LOG_DIR" "$XDG_RUNTIME_DIR"`, the function template lacked `XDG_RUNTIME_DIR`, so every `CreateSandbox` died `mkdir: cannot create directory ''` → exit 1 → 403 `function_exited`. First symptom: a freshly-spawned delegate's chat silently never answered. The pod's own stdout lives in the function's **TLS log topic** (`GetFunction → TlsConfig`); `GetFunctionInstanceLogs` 404s once the failed instance is GC'd (minutes).

`setup-image.sh` therefore runs a **boot gate before every precache refresh** (`run_vefaas_boot_gate`, under `--refresh-only`):

1. resolve the **registry-live digest** of `CR_IMAGE` (never the local tag — the two diverged once when an escape-hatch push put different bits in the CR; the precache serves the CR ones) and pull it;
2. fetch the **live** function env template — `GetFunction` via `scripts/operator/lib/ve-api.py` (a stdlib port of `agentkeys-core::ve_sign`), creds from the broker unit's env family, needing the read-only `vefaas:GetFunction` grant ([`ve-broker-vefaas.json`](../../scripts/operator/policies/ve-broker-vefaas.json) Sid `FunctionReadForBootGate`);
3. boot the digest with **`env -i` + exactly that template + the function's own `Command`** — pod semantics, image `ENV`s dropped — and require PID 1 alive after `AGENTKEYS_VEFAAS_GATE_SECS` (default 25 s).

A failing gate **blocks the refresh** and prints the container log plus the baked-vs-template key diff with the exact console/`UpdateFunction` remediation. Emergency opt-out: `AGENTKEYS_SKIP_VEFAAS_BOOT_GATE=1` — loud, because it re-opens exactly this class. The dsh image needs NO template additions by design: its only baked ENV (`DSH_HOME`) is set by its own supervisord unit (measured at the first dsh cycle, 2026-08-24 — the gate passed against the unmodified template). `seed-dsh-base.sh` reminds at every seed that the template contract is re-checked at the first spawn.

`ve_faas.rs::refresh_precache()` therefore does: **List → Delete → verify GONE → Precache → poll until `success`**. Each part exists because of a measured failure mode:

| Fact | Consequence |
|---|---|
| `PrecacheSandboxImages` answers `already exists` for a registered URL without re-pulling | re-adding alone can never refresh a moved tag |
| `ListSandboxImages` exposes **no digest** | staleness is undetectable from the API — so refresh deletes unconditionally rather than comparing |
| `DeleteSandboxImage` answers **200 with `Result.Status:"failed"`** while a live instance runs the image | a bare 200 proves nothing; the pin is the live instance (`DescribeSandbox.ImageInfo.Id`) |
| `DeleteSandboxImage` answers 200 deleting **nothing** without body `Region` | the delete must be *observed* (entry absent from List) before re-adding |
| `ImageType` on List is required and **lowercase** (`private` / `public`) | `Private` → 400 `type is invalid` |

**A fresh preheat can take ~30 minutes and a timeout is not a failure** (measured 2026-07-26; **~2-4 min when the CR is warm** from the just-landed push, measured 2026-08-24). The verb waits up to 1 h by default; if it does time out the push already succeeded and the entry keeps preheating server-side. Re-running is safe and cheap: `refresh_precache()` **resumes** an in-flight (`caching`) entry instead of deleting it. Only a `success` entry takes the delete + re-add path.

**If a delegate is live it pins the registration** (mutable-tag mode only — a versioned cycle registers a NEW url no instance pins) — the refresh stops and names the exact instance, delegate hash, and expiry. Remedies (#577): re-run with **`--kill-pinners`** (`VE_REFRESH_KILL_PINNERS=1` through `setup-image.sh`) — a kill-ONLY unpin — or archive the delegate (Touch ID) if you actually want it gone.

### Spawn readiness: the pod is Ready when PORT 8090 listens — and the boot must fit ~29s (#589)

`CreateSandbox` is synchronous with a hard server-side **~29s cold-start budget**, and veFaaS readiness is *the configured port (8090, the in-sandbox bridge) accepting connections*. Preheat makes the image itself instant — measured 2026-08-01, the container executed the function Command **0.6s** after the CreateSandbox call — so the entire budget is spent on whatever sits in front of the bridge's `bind()`. The hermes-era incident: the bridge ran a blocking agent handshake *before* binding, 16–29s+ on 1 vCPU, so every cold spawn 408'd `function_cold_start_timeout` **while the pod kept booting** — and each blind retry created a duplicate instance. Two layers fix it (#589): the bridge **binds :8090 first** and initializes the agent in the background (gated endpoints answer 503 while starting), and the broker treats a cold-start 408 as **in-progress, not failure** — it parses the instance name out of the 408 and adopts it once `Ready` (`AGENTKEYS_VEFAAS_COLDSTART_WAIT_SECS`, default 120). Keep new boot-time work *behind* the bind, never in front of it. The dsh bridge (`packages/agentkeys-dsh/src/bridge.ts`) is bind-first by construction; the first live dsh rotation measured **20.2 s wall for the whole kill + create + Ready cycle** (2026-08-26, #610 evidence). Related measured fact: `SetSandboxTimeout` can never extend past `create_time + <create-time Timeout>`, so with the full 1440-min lease at create the keep-alive is a designed no-op and expiry-rotation (#594) is the real path.

## Phase 4 — bringing delegates onto the new image (#577/#594)

A sandbox **freezes its image at spawn**, so a completed preheat changes only what *future* creates boot. Three paths converge on the SAME in-place cycle:

- **Staleness is visible, not shell-probed.** An instance freezes the pre-cache **registration id** it spawned from (`DescribeSandbox.ImageInfo.Id`) while the refresh mints a NEW registration id — `frozen ≠ current` is exactly "running old bits". `POST /v1/agent/image-status` (J1_master; proxied by the daemon for parent-control) reports it per delegate; the Delegates page renders an **"update available"** chip and a batch button. The same response carries the instance's lease deadline plus the **live agent identity from the bridge's `/healthz`** (engine + version + LLM endpoint — the running truth, not the tag's claim).
- **`POST /v1/agent/update`** (J1_master, chain-verified ownership, TIER_AGENT only) performs the in-place cycle: job-guard + runtime-home export from the old instance → `KillSandbox` → re-create through the SAME #546 spawn-context ensure path (fresh #552 J1, lazily re-provisioned metered gate key) → import + agent re-source in the replacement. No chain write, no Touch ID, no slot movement; audit emits `SandboxTeardown(reason="update")` + the usual `SandboxSpawn`.
- **The #594 lease sweeper** warm-rotates every expiring instance through the SAME core automatically (default ON), so a fleet migrates within one lease cycle even with zero clicks — measured live: the first dsh delegate in production arrived exactly this way (2026-08-25).
- **What the hand-off preserves — and what it cannot.** The bridge's bearer-gated `/v1/sandbox/mgmt/*` surface (armed per delegate via the broker-derived `AGENTKEYS_SANDBOX_MGMT_TOKEN`) exports **on-disk `DSH_HOME` state** (profile patch, durable session JSONL, skills — the image-owned profile config is excluded both ways; the wire doc's `hermes_home` field name is the frozen shape, predating #621). A **runtime-family switch skips the hand-off entirely** (#640 — a home snapshot is runtime-keyed; the replacement starts from canonical memory). Anything held only in process memory restarts with the instance.
- **Background jobs (#340) refuse the update** (409 `jobs_running`) unless forced — their output stream dies with the instance; the UI turns the button into "update anyway".
- The **crash path** is the #594 checkpoint: the in-sandbox daemon periodically persists the same exportable snapshot into its own `knowledge:<ns>` grant (keyed object `checkpoint/dsh-home`) and restores it at boot (newer-wins `snapshot_at` guard settles the race with a relay import).

## Entry points

| Command | Use |
|---|---|
| `scripts/operator/build-image-dsh.sh` | **the normal path** — laptop-driven, ends with the new version preheated (#598: alongside the old) |
| `scripts/operator/build-image-dsh.sh --flip` | the #598 second half — after 已预热 + the env commit, point spawns at the new version (unit converge) |
| `scripts/operator/seed-dsh-base.sh` | rare — only on a dsh/plugin/openviking pin bump (#619 gate) |
| `scripts/operator/setup-image.sh --refresh-only` | broker-side: boot gate + register/preheat `CR_IMAGE` (or `CR_IMAGE_OVERRIDE`) — the one owner of the refresh |
| `scripts/operator/setup-image.sh --flatten-base --family dsh` | broker-side, after every re-seed: publish the one-layer flat base |
| `agentkeys-broker-server precache-refresh [--timeout-secs N] [--kill-pinners]` | refresh alone, on the broker, under the unit's env |
| `scripts/operator/ship-dsh.sh` | the #619 bump ceremony over all of the above |

## Verifying a spawn really runs the new bits

**`/usr/local/bin/agentkeys-daemon` is a layer of the IMAGE — it exists on neither the broker host nor the operator laptop.** Every check below runs *inside a container* or a live sandbox.

**Check the image first — no spawn, no gateway, no Touch ID.** The laptop keeps the copy it pushed:

```bash
docker image inspect "$CR_IMAGE" --format '{{index .RepoDigests 0}}'   # must equal CR_IMAGE_DIGEST
docker run --rm --entrypoint bash "$CR_IMAGE" -c 'dsh --version'
```

**Then check a live sandbox.** Reach any sandbox port through the veFaaS gateway with `-H "x-faas-instance-name: <SandboxId>" -H "x-faas-proxy-port: N"` (8090 = the dsh bridge — its `/healthz` reports `{"engine":"dsh", …}`; **3114 = the agentkeys-daemon ui-bridge**), then ask the agent via `POST /v1/chat` to read `/var/log/agentkeys-daemon.log` (the chat loop's own verdict). The broker-side `DescribeSandbox.ImageInfo.Id` against the current registration id is the frozen-vs-current proof (the #602 machinery — the first dsh pod was proven exactly this way, `ImageInfo.Id = ybt857fxm9`).

Cheap first pass without touching the sandbox: on the broker, `channel/poll` in the nginx access log coming only from the operator's laptop IP (never a VE address) proves no sandbox ever subscribed.

## Layer ordering — keep the daemon last

The daemon `COPY` is deliberately the **final** layer: it is the only thing that changes on a normal code push, so a rebuild invalidates exactly one ~50 MB layer and a re-push uploads only that. **Anything added below it re-inflates every incremental push** — put new steps above it.

## The engine's embedder: gate relay (default) or a local model (opt-in, #694 step 5)

The sandbox's OpenViking engine embeds every mirrored knowledge line. By
default it does so through the model gate relay (`OPENVIKING_EMBED_PROVIDER=volcengine`,
the gate base + `gk_` key pair, metered as op 93 `GateEmbed`). The no-egress
alternative is the engine's own `local` provider — llama-cpp-python and a GGUF
(`bge-small-zh-v1.5-f16`, dimension 512, the engine's default) — which costs
image size + sandbox CPU instead of gate calls. It is a **two-part opt-in**,
default off on both parts:

1. **Bake it into the foreign base** (laptop-built; the CN broker never fetches):
   `local · main checkout` — `OV_LOCAL_EMBED=1 bash scripts/operator/seed-dsh-base.sh`.
   The base tag gains `-localembed`, so a base with the model is never mistaken
   for one without; the per-push cycle (`build-image-dsh.sh`) builds FROM it.
2. **Select it per pod** in the veFaaS function env template:
   `OPENVIKING_EMBED_PROVIDER=local` (optionally `OPENVIKING_EMBED_MODEL_PATH`).
   An image ENV is never merged into a pod (#587 class), so this is a template
   edit + the usual flip. A pod told `local` on an image built without the model
   refuses to start the engine (rc 78) instead of running without embeddings.

"Ship vectors from origin" is **not** an option with this engine: its write
API takes text only (`WriteContentRequest`, `extra="forbid"`, v0.4.16) and
vectorizes on write — see `docs/plan/knowledge-repository.md` §11.
