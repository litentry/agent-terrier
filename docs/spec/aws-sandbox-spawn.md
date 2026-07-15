# AWS delegate-sandbox spawn — ECS/Fargate behind the `sandbox_backend` seam (#440)

**Status:** IMPLEMENTED (code + provisioning), live Fargate spawn pending the operator bring-up below. **Parent:** epic [#439](https://github.com/litentry/agentKeys/issues/439) (stack ② — the 备案-proof AWS product stack); the VE twin is #377 ([`ve-broker-runtime-port.md`](ve-broker-runtime-port.md) documents that stack's port seams).

## The seam

Delegate-sandbox spawn used to be VE-only (`ve_faas.rs`, #377). #440 extracts the broker-side interface into [`sandbox_backend.rs`](../../crates/agentkeys-broker-server/src/sandbox_backend.rs) — an enum over the per-cloud drivers, mirroring the ops-side #376 `--cloud` driver split:

| | VE (`ve_faas.rs`, #377) | AWS (`aws_ecs.rs`, #440) |
|---|---|---|
| Enabled by | `SANDBOX_FUNCTION_ID` | `AGENTKEYS_SANDBOX_ECS_CLUSTER` |
| Spawn / kill | veFaaS `CreateSandbox` / `KillSandbox` | `RunTask` (FARGATE, awsvpc) / `StopTask` |
| Quota key | `Metadata` labels | task **tags** (same label names — ONE definition in `ve_faas.rs`) + `startedBy=agentkeys-broker` |
| Lifetime | veFaaS timeout, extended per resolve | none (explicit stop; **idle teardown = follow-up**) |
| `agent_url` | ONE static gateway fronting all instances | **per-task** `http://<ENI private ip>:8090`, carried in the ensure outcome |
| Image | our `docker/hermes-sandbox` → Volcano CR (`CR_IMAGE`) | the SAME image → ECR (`ECR_IMAGE` leg of `build.sh`) |
| LLM env | #338 `ark` family (Ark) | #338 `ark` family — the family FILE carries this stack's OpenAI-compatible endpoint |

Both drivers configured = boot-time hard error (one backend per broker; no-silent-override). Handlers ([`handlers/sandbox.rs`](../../crates/agentkeys-broker-server/src/handlers/sandbox.rs) — the only call site) are cloud-blind: spawn-on-reason, kill-on-unpair, quota ≤1 live runtime per delegate, `SandboxSpawn`/`SandboxTeardown` audit emits (op_kinds 53/54; the audit body's `function_id` carries the veFaaS app id or `cluster/taskdef` — wire name unchanged, #203).

## Reachability (first ship = private IP)

A Fargate task's `agent_url` uses its **private** awsvpc ENI ip: in-VPC consumers (the broker, the gateway feed hop) reach it; the sandbox SG admits `:8090` from the **broker SG only**. The broker-mediated surfaces (#425 operator chat via opchat feeds, channel feeds) need nothing more. Public device→sandbox reachability (VE-gateway parity) is an explicit follow-up — NLB vs public-ENI lookup — tracked on #440, never silently assumed. Tasks still get a public IP by default (`AGENTKEYS_SANDBOX_ECS_ASSIGN_PUBLIC_IP=1`) because default-VPC subnets have no NAT and the ECR pull needs egress.

## Task security posture

The task runs with an **execution role only** (ECR pull + CloudWatch logs). **No task role, deliberately** (#90): the sandbox obtains per-actor short-TTL creds via cap-mint → STS relay — never ambient IAM.

## Operator bring-up (all CLI, idempotent)

```bash
# 1. provision (ECR repo · cluster · logs · exec role · SG · taskdef · broker-role policy
#    + env write-back) — wired as setup-cloud.sh step 18:
bash scripts/operator/setup-cloud.sh --only-step 18        # laptop, agentkeys-admin
# 2. build + push OUR image (linux/amd64):
PLATFORM=linux/amd64 ECR_IMAGE=$(grep ^SANDBOX_ECR_IMAGE= scripts/operator-workstation.env | cut -d= -f2) \
  bash docker/hermes-sandbox/build.sh
# 3. redeploy the broker host so the unit env carries AGENTKEYS_SANDBOX_ECS_*:
bash scripts/operator/setup-broker-host.sh --ref main      # on the broker host
```

Then a parent-control delegate spawn (#425/#427) boots a Fargate task from our image; archive stops it.

## Follow-ups (tracked on #440)

1. Live Fargate spawn verification on the prod stack (the bring-up above, then one spawn/archive cycle + a stage-3-style negative).
2. Idle-teardown reaper (VE parity — veFaaS expires idle instances; ECS needs an explicit stop policy).
3. Public device→sandbox reachability decision (NLB vs public-ENI lookup) for the direct `agent_url` path.
4. Own-base-image hardening: today's image extends the digest-pinned `ghcr.io/agent-infra/sandbox` (AIO) base; fully self-built base = separate decision.
