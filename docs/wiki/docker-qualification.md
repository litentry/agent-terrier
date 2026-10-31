This qualification exercises the real Docker adapter from a CLI. It uses a small HTTP fixture, not the complete agent image. Local models, application onboarding and contract-driven revocation are separate release gates.

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
cargo test -p agentkeys-broker-server --test docker_local -- --ignored --nocapture
```

The explicit ignored-test invocation keeps ordinary unit tests independent of Docker availability. A missing socket, missing image or denied operation fails the qualification; it is never recorded as a pass or silently skipped. Compilation time and first image download are separate from the warm execution measurement.

## What the check proves

- One create and one credential callback, followed by reuse without another mint.
- Immutable image selection, an unprivileged process, a read-only root and temporary writable storage.
- Published HTTP reachable through host loopback; no host-directory or Docker-socket mounts.
- Foreign actor and namespace denial, with the authorized runtime preserved.
- Both HTTP targets work independently; a cross-runtime network request fails without changing its target.
- A stopped runtime is replaced with a new credential; removal clears discovery and preserves the other device.

Each run uses a random ownership namespace. Cleanup removes only that run's containers, networks and fixture image. It retains the downloaded base image for repeat runs. A failed assertion still attempts scoped cleanup; a killed test process can leave resources with its `terrier-check-` namespace for manual inspection.

The Docker host remains trusted. Its administrators can inspect container environments. The adapter sends values over stdin and does not put credentials in command arguments or error output. The host client receives only `PATH`, `HOME`, `TMPDIR` and an explicitly supplied `DOCKER_CONFIG`, so inherited cloud settings and Docker context variables do not select another engine.
