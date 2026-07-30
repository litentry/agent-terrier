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

It delegates every mutation to the scripts on this page and gates on observables (PR state, the `base/hermes:<pin>-<sha8>` tag in the CR, precache status, `hermes --version` inside the image); merging the bump PR stays a human step, and `--kill-pinners` is the explicit consent for the #577 kill-only unpin.

## Why the work is split across two machines

The pipeline looks over-engineered until you know that **two directions do not work**, both measured:

| Direction | What happens |
|---|---|
| **CN broker → GitHub / PyPI** | The Hermes installer's `git clone` runs ~20 min and dies `GnuTLS recv error (-54) … bytes of body are still expected` — **including with `--network host`**, so it is the transfer truncating, not container NAT. `pip install` from PyPI is the same link. |
| **Laptop → CN Container Registry** | 39 retries could not land ~660 MB: `toomanyrequests`, `short read … unexpected EOF`, and intermittent **DNS failure** for the CR host. |

So neither machine can do the whole job. The split follows directly: **the Mac compiles and seeds the foreign layers; the broker builds and pushes.** Crucially, *at image-build time nothing crosses the border at all* — that is what makes the cycle reliable rather than merely faster.

This is also why the daemon travels as a **~50 MB binary over scp** instead of a ~17 GB image over the registry protocol.

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
| 1 | Mac | cross-compile `agentkeys-daemon` for `linux/amd64` (fast cores; ~3 min incremental) |
| 2 | Mac → broker | `scp` the ~50 MB binary |
| 3 | broker | `setup-image.sh --from-binary`: `docker build` **FROM `$VE_BASE_HERMES`** — BuildKit **skips stage 1 entirely**, so zero foreign egress — with the daemon `COPY` as the **last layer** |
| 4 | broker | `docker push` → CR, **intra-region** (normally one ~50 MB layer — but see the CR-tier note below) |
| 5 | broker | `agentkeys-broker-server precache-refresh` → poll until 已预热 |

Two design details that are load-bearing rather than cosmetic:

- **`FOREIGN_BASE` must be a global `ARG`** (declared before the *first* `FROM`). An `ARG` written inside a stage body is stage-scoped and invisible to a later `FROM`, which fails with `base name (${FOREIGN_BASE}) should not be blank`.
- **BuildKit is required on the broker** when `FOREIGN_BASE` is set — only BuildKit prunes an unreferenced stage. The classic builder walks every stage and would run the Hermes clone anyway, so `build.sh` hard-errors on that combination.

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
2. **A `request frequency is too high, try later` refusal is UNDOCUMENTED.** VE publishes no push QPS/frequency limit for any tier, and the [push-failure FAQ](https://www.volcengine.com/docs/6420/78516) covers only `unauthorized`. Measured 2026-07-27: a 3-layer push succeeded while an 81-layer push was refused **both** with ~15 GB of new layers and with ~50 MB into a repo already holding them; `max-concurrent-uploads=1` changed nothing; reads were fine throughout. So it is neither bytes, storage, nor concurrency — and there is **no documented reset window to wait for**. Treat it as a support-ticket item (VE's own remedy for limits is 提升实例配额) or a reason to move to 标准版. A bump run is where this bites, because re-seeding the base pushes a fresh multi-GB image right before the hybrid does.

## Phase 3 — precache refresh: why a push is not enough

**veFaaS spawns the image it has PRECACHED, not what the registry currently serves.** A same-tag re-push is invisible to it. This produced a silent-chat incident (2026-07-23) where the CR held the new image while every sandbox kept booting the previous one.

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
| `scripts/operator/build-image-hybrid.sh` | **the normal path** — laptop-driven, ends preheated |
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
