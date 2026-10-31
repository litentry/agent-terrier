The public runtime composition and image are available for component development. They reuse the shared agent loop, authenticated bridge, grant guards and session persistence. They are not yet the complete localhost deployment: broker-driven startup, saved-session wiring, signer/service composition and the lightweight manager remain open in [epic #1](https://github.com/litentry/agent-terrier/issues/1).

## Build and test

Local, from the public checkout, install the single packages workspace lockfile and run its CLI lane:

```sh
npm ci --prefix packages --ignore-scripts
python3 terrier test focused --component dsh
```

The lane builds shared plugins, checks types, runs their deterministic tests and starts real runtime processes for authentication, tool-denial and restart checks. It uses local fixture servers and loads no models.

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

## Explicit configuration

`packages/agent-terrier-runtime/start.mjs` requires `--state-dir`, `--work-dir`, `--port` and `--daemon-url`. It listens only on loopback. State and work paths must be canonical, private, owned directories without linked ancestors. Startup refuses incomplete configuration before opening the listener.

| Environment | Purpose |
|---|---|
| `AGENTKEYS_MODEL_BASE_URL` | Explicit local compatibility endpoint or model relay |
| `AGENTKEYS_MODEL_API_KEY` | Per-runtime relay proof |
| `AGENTKEYS_MODEL_ID` | Explicit model selection |
| `AGENTKEYS_BRIDGE_TOKEN` | Proof required for chat and context changes |

Endpoints accept local HTTP origins only, without embedded credentials, query strings or fragments. Model environment names come from generated protocol definitions. The recipe owns context capacity; the composition bounds reply output. No provider discovery, credential file loading, shell tool or unrestricted filesystem tool is mounted. Advertised daemon actions retain both the shared grant guard and the daemon's independent authorization.

Session logs live under the private state directory; agent-process restart resumes them. The shared Docker lifecycle now mounts a persistent volume owned by the namespace, device and actor. Its image directory and numeric user/group come from `agentkeys-protocol::runtime_layout`, also consumed by the image build through generated TypeScript. The directory is initialized with mode 0700. Container replacement and ordinary teardown preserve the volume; explicit reset requires the matching actor and no remaining container. Host-backed volumes, foreign labels and unexpected mounts are refused.

The runtime's `--state-dir` still needs to be wired to this mount by automatic startup. File persistence through the real lifecycle is qualified, while complete agent-session recovery through that lifecycle remains pending. Docker engine administrators can inspect container state; this development image does not claim production wallet custody.

The image also supplies `agentkeys-daemon` on PATH. The image qualifier starts that actual executable in an isolated temporary home, checks its health, rejects missing/wrong management proof and accepts the matching proof. Automatic composition of the daemon, agent process and translated local-service endpoints remains pending; the current image entry point still starts the JavaScript runtime with explicit arguments.

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

The earlier direct host-gateway route failed on the internal network. The qualifier now uses this explicit transport and passes while a direct external socket returns `ENETUNREACH`. The same transport implementation is intended for the runtime lifecycle owner; its automatic composition with broker, signer and storage services remains pending. Parent shutdown closes the stream and its listeners, and qualification removes only its labeled container.

Recorded component evidence on macOS arm64: 123 shared plugin tests; runtime process cases cover wrong proofs, denied tool effects with a granted positive control, restart recovery, missing configuration and unsafe directories. Transport cases cover concurrent streams, unknown services, path escape, redirect and oversized-request refusal, plus cleanup. All five image cases, including the packaged daemon's startup and authentication check, pass inside Linux arm64 under Node 24.22.2 with a read-only filesystem and no network. This image test command took 1.81 seconds; its test runner reported 1.44 seconds. The first optimized daemon compilation took 5 minutes 43 seconds; subsequent builds reuse the compiler cache. The extracted final daemon and first-party runtime payload passed the public scan. The earlier real-model container chat/restart probe passed in 5.05 seconds through the same transport. These are component measurements, not independent clean-install or full application acceptance; amd64 execution and automatic process composition remain unqualified.
