The public runtime composition and image are available for component development. They reuse the shared agent loop, authenticated bridge, grant guards and session persistence. The image starts and supervises the daemon and agent from explicit configuration. The Docker lifecycle connects it to selected local services. It is not yet the complete localhost deployment: complete application tool/channel workflows, browser acceptance and an independent clean install remain open in [epic #1](https://github.com/litentry/agent-terrier/issues/1).

## Build and test

Local, from the public checkout, install the single packages workspace lockfile and run its CLI lane:

```sh
npm ci --prefix packages --ignore-scripts
python3 terrier test focused --component dsh
python3 terrier test focused --component managed
```

The DSH lane builds shared plugins, checks types, runs their deterministic tests and starts real runtime processes for authentication, tool-denial and restart checks. The managed lane builds the native controller and daemon and checks their composition, controller loss, state locking, restart recovery and failure cleanup. Both use local fixture servers and load no models. Neither rebuilds the Docker image.

Local, from the public checkout with Docker running:

```sh
docker build --file packages/agent-terrier-runtime/Dockerfile \
  --tag agent-terrier-runtime:local .
docker build --file packages/agent-terrier-runtime/Dockerfile \
  --target qualification --tag agent-terrier-runtime:tests .
docker run --rm --pull=never --network=none --read-only \
  --cap-drop=ALL --security-opt=no-new-privileges --user=1000:1000 \
  --pids-limit=256 --memory=512m --cpus=1 \
  --tmpfs=/tmp:rw,nosuid,nodev,size=128m agent-terrier-runtime:tests
```

The Dockerfile pins its public Node and Rust base images by digest. Its adjacent context allowlist includes public Rust/runtime source, manifests, model/preset inputs and license notices; it excludes host build output, credential files and databases. npm installation scripts are disabled. The Rust stage reads the repository toolchain pin without updating the toolchain manager, builds the existing daemon with locked dependencies and bundled OpenSSL, remaps source paths and copies only its stripped executable into the final image. Build tools have explicit package versions. The final image contains the daemon, production JavaScript dependencies and compiled plugins; the qualification target adds tests without changing runtime code. Models, credentials, private documentation, host state, Rust build tools and test files are absent from the final image.

The first Rust image build downloads and compiles dependencies. BuildKit caches the package registry and architecture-specific compiler output for subsequent builds; changing JavaScript alone can reuse the daemon layer. `CARGO_BUILD_JOBS` is a build argument controlling compiler concurrency, defaulting to two. Ordinary CLI/component tests do not rebuild images.

## Managed startup

The final image entry point is `agent-terrier-runtime`, built from `crates/agentkeys-runtime`. `managed_agent::RuntimeBootstrap` owns the controller contract: version, the existing typed `ChainProfile`, and an allowlisted environment map. It accepts one newline-delimited JSON frame of at most 64 KiB on stdin within 30 seconds. Keep stdin open after that frame; EOF stops both children. Extra input is an error. The controller must provide translated loopback service endpoints, actor/operator identities, channel ID, model ID, session JWT, model proof, bridge proof and management proof. Private device keys, arbitrary environment names and nonlocal profiles/endpoints are refused. Optional application settings use the shared bound-channel and availability types; malformed namespaces, channel data, wake timestamps and timezone offsets are rejected before startup. The optional speech endpoint must belong to the model relay and follows the same translated origin.

The process owner creates private `home`, `runtime` and `work` directories under the persistent state volume. An exclusive state lock refuses a second writer. Configuration and credentials are not written to disk; the public chain profile is passed to the daemon through a private temporary file removed on shutdown. Child environments are explicitly constructed: the JavaScript loop receives only model configuration and its bridge/management proofs, not the daemon's session JWT, signer endpoint or chain profile. Child output is suppressed to avoid accidentally exposing credentials; failures report supervision failure and exit nonzero. Startup reserves the requested local ports and checks both health and authenticated component routes before emitting a JSON readiness record. Its `local-agent-processes` surface describes listener readiness, not chain authorization or channel synchronization.

Controller EOF, termination signals and either child's exit stop both children, allowing five seconds for each graceful shutdown before forced termination. Session directories survive restart. `--state-dir`, `--runtime-script`, `--daemon-binary`, `--daemon-port` and `--agent-port` support explicit native development; their image defaults use the canonical state directory, installed programs and shared protocol ports. The host uses `DockerRuntime::connect_managed` with an explicit local chain profile and canonical public transport script. It attaches the control stream, starts the shared transport, translates selected endpoints through the canonical service map, then supplies the bootstrap frame. Container networking is disabled. Runtime credentials never become Docker environment entries. The broker selects this managed path whenever an explicit image is configured. `AGENT_TERRIER_TRANSPORT_SCRIPT` must name the canonical public `service-transport.mjs` file; a missing script or a script without an image is an error. There is no automatic fallback to the generic fixture controller. The selected profile and its configured RPC override must remain local. The broker uses the canonical service map for both creation and restart, forwarding explicit signer and storage addresses alongside broker/channel addresses. Host signing keys and relay admin tokens are excluded. The [CLI supervisor](./local-services.md) prepares these service coordinates from the local deployment; its runtime configuration requires an explicitly selected preloaded image and Docker socket.

## Agent-loop configuration

`packages/agent-terrier-runtime/start.mjs` requires `--state-dir`, `--work-dir`, `--port` and `--daemon-url`. It listens only on loopback. State and work paths must be canonical, private, owned directories without linked ancestors. Startup refuses incomplete configuration before opening the listener. The [sessions plugin](../../packages/agentkeys-dsh/README.md) owns home-directory resolution; the bridge reuses it for session transfer and management.

| Environment | Purpose |
|---|---|
| `AGENTKEYS_MODEL_BASE_URL` | Explicit local compatibility endpoint or model relay |
| `AGENTKEYS_MODEL_API_KEY` | Per-runtime relay proof |
| `AGENTKEYS_MODEL_ID` | Explicit model selection |
| `AGENTKEYS_BRIDGE_TOKEN` | Proof required for chat and context changes |

Endpoints accept local HTTP origins only, without embedded credentials, query strings or fragments. Model environment names come from generated protocol definitions. The recipe owns context capacity; the composition bounds reply output. No provider discovery, credential file loading, shell tool or unrestricted filesystem tool is mounted. Advertised daemon actions retain both the shared grant guard and the daemon's independent authorization.

Session logs live under the private state directory; agent-process restart resumes them. The shared Docker lifecycle now mounts a persistent volume owned by the namespace, device and actor. Its image directory and numeric user/group come from `agentkeys-protocol::runtime_layout`, also consumed by the image build through generated TypeScript. The directory is initialized with mode 0700. Container replacement and ordinary teardown preserve the volume; explicit reset requires the matching actor and no remaining container. Host-backed volumes, foreign labels and unexpected mounts are refused.

Managed startup wires the agent's session directory to this mount. Its real-process qualifier verifies saved conversation recovery after restart and verifies that bootstrap credentials are absent from saved files. The [managed Docker qualifier](./docker-qualification.md) also verifies conversation recovery after container replacement through the actual controller and service transport, separate actor sessions, controller-loss shutdown and partial-start cleanup. Docker engine administrators can inspect container state; this development image does not claim production wallet custody.

The image also supplies `agentkeys-daemon` on PATH. The image qualifier starts that actual executable in an isolated temporary home, checks its health, rejects missing/wrong management proof and accepts the matching proof. Managed tests start both real children, reject wrong chat proofs before model calls, recover conversation history, reject duplicate writers and unsafe configuration/state, and prove cleanup after controller loss and partial startup failure. Their synthetic service endpoint denies signer/channel/chain requests; this explicitly does not qualify a real delegate session.

## Real-model qualification

Prepare the pinned models using [local models](./local-models.md). Local, from the public checkout on macOS:

```sh
python3 scripts/tests/qualify_local_models.py \
  --models-dir "${OLLAMA_MODELS:?Set the existing model directory}" \
  --agent-runtime
```

This reuses the capability probe's owned model runner and OS-level outbound network restriction. It starts the actual agent, refuses a wrong bridge proof, generates a real-model reply, restarts the agent process and checks conversation recall. Its daemon fixture exposes no actions; this is not a real-chain authorization qualification.

Local, from the public checkout on macOS after building the qualification image, the separate container probe is:

```sh
python3 scripts/tests/qualify_local_models.py \
  --models-dir "${OLLAMA_MODELS:?Set the existing model directory}" \
  --runtime-image agent-terrier-runtime:tests \
  --docker-socket "${AGENT_TERRIER_DOCKER_SOCKET:?Set the local Docker Unix socket}"
```

This probe runs the container with `--network=none`. The shared `service-transport.mjs` carries local HTTP through a Docker execution stream, using standard HTTP/2 multiplexing over stdin/stdout. It creates loopback listeners inside the container and returns their translated endpoints. The host explicitly selects named loopback targets and path prefixes; destination URLs never come from an agent request. Unknown services, path escapes, redirects and requests over one MiB are refused. Responses are streamed with a 32 MiB bound and a one-minute request deadline. Original application authorization remains required at the destination. No host listener, published container port, host filesystem mount or Docker socket is added to the agent.

The earlier direct host-gateway route failed on the internal network. The qualifier now uses this explicit transport and passes while a direct external socket returns `ENETUNREACH`. The runtime lifecycle owner uses this same implementation in managed mode. Parent shutdown closes the stream and its listeners, and qualification removes only its labeled container. End-to-end broker, signer, storage and real-model acceptance remains separate.

Recorded component evidence on macOS arm64: 123 shared plugin tests and six runtime, managed-process and transport cases passed through the combined CLI selection in 16.45 seconds, including 11.85 seconds of builds and 4.59 seconds of execution. All seven image cases, including the packaged daemon probe, passed inside Linux arm64 under Node 24.22.2 with a read-only filesystem and no network. The image test command took 2.01 seconds; its runner reported 1.83 seconds. Both packaged executables and the first-party runtime payload passed the public scan. The first optimized daemon compilation took 5 minutes 43 seconds; subsequent builds reuse the compiler cache. The earlier real-model container chat/restart probe passed in 5.05 seconds through the same transport. These are component measurements, not independent clean-install or full application acceptance; amd64 execution and complete controller/service composition remain unqualified.
