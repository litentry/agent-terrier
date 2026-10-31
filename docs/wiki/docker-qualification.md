These explicit qualifications exercise the real Docker adapter from a CLI. The small HTTP fixture checks lifecycle ownership and isolation. The managed-agent scenario also checks the actual daemon/agent image, service transport and saved conversations. Real models, application onboarding and contract-driven revocation are separate release gates.

## Prerequisites

Use a running local Docker engine with a Unix socket, the pinned Rust toolchain and the public checkout. The test accepts an explicit socket and never changes your active Docker context. A separate test engine is recommended when your normal engine contains unrelated work.

Local, from the public checkout, set `AGENT_TERRIER_TEST_DOCKER_SOCKET` to the engine's absolute socket path. Download the fixture base once:

```bash
export AGENT_TERRIER_TEST_DOCKER_SOCKET="${AGENT_TERRIER_TEST_DOCKER_SOCKET:?Set the local Docker socket path}"
export AGENT_TERRIER_TEST_BASE_IMAGE="${AGENT_TERRIER_TEST_BASE_IMAGE:-public.ecr.aws/docker/library/busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec}"
docker --host "unix://${AGENT_TERRIER_TEST_DOCKER_SOCKET}" pull "${AGENT_TERRIER_TEST_BASE_IMAGE}"
```

Local, from the same checkout and shell, run the qualification. It does not pull images and its temporary fixture build disables build networking:

```bash
cargo test -p agentkeys-runtime --test docker_local -- --ignored --nocapture
```

The explicit ignored-test invocation keeps ordinary unit tests independent of Docker availability. A missing socket, missing image or denied operation fails the qualification; it is never recorded as a pass or silently skipped. Compilation time and first image download are separate from the warm execution measurement.

## Managed agent qualification

Build the reviewed [public agent image](./local-agent-image.md) first. Local, from the public checkout and the same explicitly configured Docker socket:

```sh
export AGENT_TERRIER_TEST_AGENT_IMAGE="${AGENT_TERRIER_TEST_AGENT_IMAGE:?Set the preloaded public agent image}"
cargo test -p agentkeys-runtime --test docker_managed -- --ignored --nocapture
```

This uses `DockerRuntime::connect_managed`, the same lifecycle owner as the broker adapter, and the public `service-transport.mjs`; it adds no second Docker controller. The container has networking disabled, a read-only root, an unprivileged user and the existing owned state volume. The host supplies local service targets and the existing chain profile explicitly. After translated loopback listeners are ready, the host delivers the bounded bootstrap frame over the attached process stream. Credentials are absent from Docker environment metadata and command arguments. Reuse requires the current controller's active lease; another controller is refused before minting. Ordinary shutdown preserves state, while failed startup removes its owned container and preserves the volume for inspection/retry.

The scenario checks wrong chat proof with no model call, an authorized model reply, reuse without another mint, second-controller denial, restored conversation after container replacement, separate actor conversations, controller-loss shutdown and failed-transport cleanup. Its fixture deliberately denies chain/signer/channel requests: this proves process and transport integration, not real delegate authorization. It removes only its random namespace's containers and state volumes. A killed qualifier can leave a `terrier-managed-` namespace for inspection.

## What the check proves

- One create and one credential callback, followed by reuse without another mint.
- Immutable image selection, an unprivileged process, a read-only root, temporary scratch space and a private actor-owned state volume.
- Management HTTP reachable through an authenticated host-loopback stream; container ports are unpublished, with no host-directory or Docker-socket mounts.
- Foreign actor and namespace denial, with the authorized runtime preserved.
- Both HTTP targets work independently; direct cross-runtime network access fails without changing its target. Host forwarding refuses missing proof, another runtime's proof and an unauthenticated request from the other container.
- A stopped runtime is replaced with a new credential while saved bytes survive. Ordinary removal clears discovery and preserves both saved state and the other device.
- Another actor cannot adopt or reset saved state after removal, and denial mints no credential. The original actor can restore the same bytes. Reset refuses an active container; after removal, explicit reset is idempotent and a new runtime starts without the old data.

Each run uses a random ownership namespace. Cleanup removes only that run's containers, networks, state volumes and fixture image. It retains the downloaded base image for repeat runs. A failed assertion still attempts scoped cleanup; a killed test process can leave resources with its `terrier-check-` namespace for manual inspection.

Runtime images initialize the directory named by `agentkeys-protocol::runtime_layout::STATE_DIRECTORY` with its canonical user/group and mode 0700. The Docker owner mounts a named local volume there; it accepts no volume driver options, remote driver or host bind mount. It checks namespace/device/actor labels and mounted volume identity before reuse or removal. Ordinary `kill_for_device` retains state; the separate `reset_state_for_device` API checks actor ownership and refuses while any device container remains. This is host-controlled development storage, not a credential vault or production custody boundary.

The Docker host remains trusted. Its administrators can inspect container state. Generic fixture mode supplies an environment over stdin, which Docker retains; managed mode delivers credentials through the attached process stream instead. Neither puts credentials in command arguments or error output. The host client receives only `PATH`, `HOME`, `TMPDIR` and an explicitly supplied `DOCKER_CONFIG`, so inherited cloud settings and Docker context variables do not select another engine.

## Management transport

Runtime images must provide an `nc` executable supporting `nc 127.0.0.1 <port>` over stdin/stdout. The fixture uses BusyBox's implementation. The host opens a loopback listener and forwards an authorized connection through `docker exec --interactive`; it never publishes the container's management ports. Each endpoint has a fresh random forwarding token supplied through the existing runtime endpoint-header interface. The initial request's forwarding header is verified and stripped before starting the container stream. The application still verifies its own management bearer.

Connections have a five-second header deadline, a bounded header size, a one-hour maximum lifetime and at most 32 concurrent connections per endpoint. Missing or wrong forwarding proof returns HTTP 403 before any container stream starts. Endpoint teardown closes its listener and active host forwarding tasks; credentials and container environments are never printed in those errors. Existing containers with published ports are refused and require explicit operator inspection/removal before reuse.

The real qualifier reproduced cross-network access with the earlier published-port configuration on Docker Engine 29.5.3. The unpublished-port configuration passed both authorized HTTP controls and cross-network denial on that engine. Separate bridge networks alone are insufficient evidence for published-port isolation: Docker documents that publishing ports permits access across bridge networks. See the [Docker bridge networking documentation](https://docs.docker.com/engine/network/drivers/bridge/).
