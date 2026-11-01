The local model probe exercises actual chat, streaming, tool execution and embedding-backed retrieval. It uses the same HTTP transport as the model relay. It is an explicit qualification command; normal unit tests use labeled deterministic fixtures and do not download or load models.

The selected recipe lives in [`presets/local-models.json`](../../presets/local-models.json), including runtime version, model names, exact digests and resource settings. `terrier models config` prints that same compiled recipe. The current recipe uses Ollama with Qwen3 for chat/tools and Nomic for embeddings. Both model listings identify Apache-2.0 licenses: [Qwen3](https://ollama.com/library/qwen3:1.7b), [Nomic](https://ollama.com/library/nomic-embed-text:v1.5). Review those model terms separately from this repository's licensing.

## Prepare models

Install the recipe's [Ollama release](https://github.com/ollama/ollama/releases) and build the public CLI. Downloads happen only when explicitly requested. Ollama documents its [local compatibility API](https://docs.ollama.com/api/openai-compatibility) and [cloud-disable setting](https://docs.ollama.com/faq#how-do-i-disable-ollamas-cloud-features).

Local, terminal A in the public checkout:

```bash
cargo build -p agentkeys-cli
./terrier models config
export OLLAMA_HOST="$(./terrier models config | jq -r '.base_url | sub("^http://"; "") | sub("/v1$"; "")')"
export OLLAMA_MODELS="${OLLAMA_MODELS:-${XDG_CACHE_HOME:-${HOME}/.cache}/agent-terrier/models}"
export OLLAMA_NO_CLOUD=1
export OLLAMA_NOPRUNE=1
export OLLAMA_CONTEXT_LENGTH="$(./terrier models config | jq -r .runtime.context_length)"
export OLLAMA_NUM_PARALLEL="$(./terrier models config | jq -r .runtime.parallel_requests)"
export OLLAMA_MAX_LOADED_MODELS="$(./terrier models config | jq -r .runtime.max_loaded_models)"
ollama serve
```

Local, terminal B in the same public checkout:

```bash
export OLLAMA_HOST="$(./terrier models config | jq -r '.base_url | sub("^http://"; "") | sub("/v1$"; "")')"
ollama pull "$(./terrier models config | jq -r .chat.model)"
ollama pull "$(./terrier models config | jq -r .embedding.model)"
./terrier models probe
```

An existing local compatibility server can be selected with `--base-url`, `--chat-model` and `--embedding-model`. The probe accepts only a loopback HTTP endpoint, rejects embedded credentials, disables proxies and redirects, and uses bounded requests/responses. It never selects another endpoint or downloads a missing model. An endpoint being loopback alone does not prove its server is performing inference locally.

Missing models fail before inference. Unsupported tools/streaming, invalid vectors and incomplete streams fail the capability check. A service error names its HTTP status and asks you to inspect model availability and runner memory. Smaller models or contexts can be tested explicitly, but their performance/capabilities are not covered by the pinned recipe until requalified.

## Supervised startup after downloads

Stop the preparation runner with Ctrl-C before starting the owned service group. Local, in the public checkout, after preparing contracts and service binaries:

```sh
./terrier stack start --model-dir "${OLLAMA_MODELS:?Set the prepared model directory}"
./terrier models probe
./terrier stack doctor
./terrier stack restart
./terrier stack stop
```

`services start` accepts the same `--model-dir` and optional `--model-binary` flags. The existing supervisor persists the absolute model directory and executable alongside its service configuration; later starts and restarts reuse them. Changing either requires stopping the services first. An existing model listener is never adopted or stopped. A missing executable, changed runner version, absent model or mismatched model digest refuses startup. Downloading or upgrading remains explicit.

The runner gets an isolated private home under the local state directory, the canonical recipe's loopback endpoint and resource settings, cloud features disabled, and pruning disabled. Host model/proxy/credential environment values are not inherited. The model files remain in the selected prepared directory; stop preserves them. The supervisor owns the runner's process group, including inference children, and includes model identity/availability in `doctor`. Readiness checks inventory; `models probe` separately proves inference capabilities. Without `--model-dir`, the backend-only mode remains available and does not claim model readiness. The cloud-disable setting is not an operating-system network firewall; the explicit offline qualifier below adds that boundary.

## Optional memory configuration

When memory is explicitly configured, its embedding settings default to the same recipe used by the CLI and relay: local endpoint, model and measured vector dimension. There is no host credential discovery or alternate hosted endpoint. With no memory configuration, the daemon leaves the optional engine unconfigured.

| Setting | Behavior |
|---|---|
| `OPENVIKING_WORKSPACE` / `OPENVIKING_CONFIG_FILE` | Explicit local storage and generated configuration locations |
| `OPENVIKING_EMBED_PROVIDER` | `openai` for the compatibility API; `local` for an installed model file; `disabled` to turn embeddings off |
| `OPENVIKING_EMBED_API_BASE` | Explicit endpoint override, validated without embedded credentials, query or fragment |
| `OPENVIKING_EMBED_API_KEY` | Optional credential; requires an explicit API base in the same configuration |
| `OPENVIKING_EMBED_MODEL` / `OPENVIKING_EMBED_DIMENSION` | Recipe defaults; a different model requires an explicit positive dimension |
| `OPENVIKING_EMBED_MODEL_PATH` | Model file for the file-based embedder; a missing file refuses startup |

The renderer requests text embeddings with float encoding. These fields and keyless local compatibility endpoints are supported by the [upstream 0.4.16 configuration schema](https://github.com/volcengine/OpenViking/blob/v0.4.16/openviking_cli/utils/config/embedding_config.py). Diagnostics report whether a key is set without printing it. Invalid explicit settings never select another provider. Do not change an existing memory index's model or dimension without an explicit rebuild/migration.

This config renderer is covered by deterministic tests. Actual OpenViking server startup, its distribution licensing and storage-backed agent recall remain release qualification work; the model capability evidence below does not establish those results.

The daemon writes generated memory configuration as an owner-only file through the shared atomic writer. Keep one daemon per configuration path. Symlinks, hard links, permissive existing files and writable-by-others destination directories are refused. Invalid settings remove a validated owned stale config and stop startup; explicit `disabled` removes that config without starting memory. A write or cleanup failure also stops startup before the chat loop/listener. Correct the reported configuration or permissions, then restart; the daemon does not reuse an old config after reporting successful recovery.

## Offline qualification

The checked-in macOS qualifier launches its own temporary runner with an isolated home directory, cloud features disabled and OS-level external IP connection denial. Loopback IP and local Unix control sockets remain available for the runner, service supervisors and explicit Docker socket. It verifies an external socket gets `PermissionError`, then runs the real CLI under the same restriction; successful loopback inference is the positive control. Existing model files are reused without download or pruning, exact runtime/model identities are checked, and only the qualifier's processes and temporary files are removed afterward.

Local, terminal A on macOS, after stopping the preparation runner and retaining its `OLLAMA_MODELS` setting:

```bash
python3 scripts/tests/qualify_local_models.py \
  --models-dir "${OLLAMA_MODELS:?Set the model directory used during preparation}"
```

Use `--ollama` to select an installed executable. The qualifier refuses a different runtime or model digest. Update the canonical recipe and re-run qualification when intentionally upgrading. The generic probe can run on other platforms; this offline qualifier and the recorded hardware acceptance currently cover macOS arm64 only.

## Recorded evidence

The [2026-10-31 report](../../e2e/fixtures/model-qualification/macos-arm64-2026-10-31.json) records macOS 15.7.4 on an Apple M3 Pro with 18 GiB physical RAM, Ollama 0.34.4, and both exact model digests. Its measured run used 1,633,595,894 model bytes (about 1.52 GiB), took 17.836 seconds to start the runner and 3.321 seconds for the probe. Within the probe: chat 1.491 seconds, streaming 0.411 seconds, tool round trip 0.765 seconds and embeddings 0.597 seconds. It received 29 stream events, executed addition returning 42, and retrieved the matching document from 768-dimensional embeddings.

Sampled runner-process RSS peaked at 1,911,104 KiB (about 1.82 GiB). This is process RSS sampled every half second, not total unified/GPU memory or a minimum RAM requirement. Installation and model download time are excluded. These are one-machine measurements, not CI performance promises.

## Authenticated relay

The relay defaults to the same local endpoint and chat model as the recipe, binds to loopback, and requires a caller relay key. An upstream model key is optional. Configuration comes only from explicit `AGENTKEYS_GATE_*` inputs or flags; the relay does not discover host credential files. Without a relay keys file, inference requests return 401. Use `agentkeys-gate --help` for the explicit configuration fields; the [local services launcher](./local-services.md) supervises the relay and optionally the prepared model runner through `--model-dir`.

`--admin-token-file`, `--upstream-api-key-file` and `--keys-file` must name owner-only regular files owned by the current user, with no symlinks or hard links. Supplying both inline and file forms of an admin or upstream credential is an error. Invalid explicit configuration fails startup instead of selecting another endpoint. The chat model override never overwrites an embedding request's model.

Keep one relay process per keys file. Its parent directory must be owned by the current user, must not be a symlink, and must not be writable by other users. Provisioning/rotation/revocation writes a private temporary file and atomically replaces the registry before changing live records. If persistence fails, new authenticated requests and readiness return 503 until restart. Stop the relay, correct the storage/permission problem, inspect or restore the last committed private registry, and restart; then explicitly reapply the failed change. Do not delete the registry as a recovery shortcut: a failed write may have reached disk before a later synchronization error. In-memory mode has no restart persistence and is reported at startup.

Optional decision endpoints use `--decision-config`, a protected JSON file with optional `jev` and `kev` objects. Each object has a required `base_url` and optional `api_key_file`; unknown fields fail. No default decision endpoint is selected. Search is disabled unless an endpoint is explicitly configured. Audio routes retain authentication and return 503 because this binary has no speech adapter. Downstream applications can inject the shared speech interface; they must pass its contract tests against their pinned source revision.

Local, in the public checkout on macOS, with downloaded models and cached Rust dependencies:

```bash
python3 scripts/tests/qualify_local_models.py --models-dir "${OLLAMA_MODELS}" --gate
```

This builds the explicit relay qualification without downloading dependencies, then runs it under the same outbound network denial as the model server. It reuses the canonical capability probe and requires positive usage accounting. Fast tests separately prove absent/wrong caller credentials are rejected without reaching the model, while an authorized caller succeeds; legacy host credentials do not affect the selected upstream.

The [relay qualification record](../../e2e/fixtures/model-qualification/macos-arm64-relay-2026-10-31.json) reports a 2.809-second relay probe on the same Mac/model recipe, including streamed chat, tool execution returning 42 and correct 768-dimensional embedding retrieval. The direct probe ran first, so this is a warm relay measurement, not a cold-start promise. Sampled model-runner RSS peaked at 1,965,792 KiB; relay memory is not included.

The recall probe uses three synthetic in-memory documents. It proves inference and vector retrieval, not persistent authorized application memory. The managed application check below qualifies persisted conversation recall separately. Authorized application memory and complete release acceptance remain open; the tool/channel application run below has separate evidence.

## Managed application qualification

`--application` reuses the existing local-agent lifecycle qualifier with actual inference. It creates disposable contracts and protected owners, logs in, creates an agent through the broker, sends a chat through the authenticated relay, recreates the runtime and checks conversation recall. Foreign-owner chat must fail without increasing model usage. Archive, relay revocation and retained volume data are checked before owned resources are removed.

Prepare the complete [local agent image](./local-agent-image.md), cached Rust/contract dependencies, and the compiler pinned in `foundry.toml`. Stop the preparation model runner: this test starts its own isolated runner at the recipe's endpoint and refuses an occupied port. It neither adopts nor stops another runner. Select a trusted downloaded compiler explicitly; its version is checked by the same helper used for normal contract commands and deployment. No model, image, dependency or compiler is downloaded during this check.

Local, in the public checkout on macOS:

```bash
python3 scripts/tests/qualify_local_models.py \
  --models-dir "${OLLAMA_MODELS:?Set the prepared model directory}" \
  --application \
  --solc "${AGENT_TERRIER_SOLC:?Set the downloaded compiler executable}" \
  --runtime-image "${AGENT_TERRIER_RUNTIME_IMAGE:?Set the reviewed complete image}" \
  --docker-socket "${AGENT_TERRIER_DOCKER_SOCKET:?Set the local Docker Unix socket}"
```

The [2026-11-01 application report](../../e2e/fixtures/model-qualification/macos-arm64-application-2026-11-01.json) records the immutable image identity, compiler hash and exact model digests. On that Mac, runner startup took 0.250 seconds, the preliminary capability probe 3.060 seconds, and the application leg 24.456 seconds. Models and compiled dependencies were already cached; these are measured warm timings, not cold-install or CI targets. The agent container had networking disabled and the host application/model processes ran under the external-connection denial policy, with local control sockets allowed.

That earlier run proves owner-to-agent chat and persisted conversation recall after runtime recreation. It did not exercise channel conversations or application tool authority; the expanded run below covers those paths. OpenViking-backed authorized memory, browser behavior and independent clean installation remain open. The direct capability probe's addition tool and three-document vector lookup remain separate component checks. Failed lifecycle tests retain a private diagnostic directory; review it before sharing.

## Supervised application qualification

Local, on macOS in the prepared public checkout, with the preparation runner stopped:

```sh
python3 scripts/tests/qualify_local_models.py --supervised-application \
  --models-dir "${OLLAMA_MODELS:?Set the prepared model directory}" \
  --runtime-image "${AGENT_TERRIER_RUNTIME_IMAGE:?Set the reviewed preloaded complete image}" \
  --docker-socket "${AGENT_TERRIER_DOCKER_SOCKET:?Set the local Docker Unix socket}" \
  --solc "${AGENT_TERRIER_SOLC:?Set the installed compiler matching foundry.toml}"
```

This reuses the real application scenario under external IP connection denial. The service supervisor starts the runner, the actual CLI probes chat/streaming/tools/embeddings, and the application exercises protected creation, real chat, service/model restart, conversation recall and revocation. The test verifies that model configuration is reused and the model port is released on shutdown. It removes only its owned temporary application state and labeled containers/volumes; downloaded models remain. The expanded tool/channel run below uses this same scenario; browser and independent clean-install acceptance remain separate gates.

The [2026-11-01 supervised report](../../e2e/fixtures/model-qualification/macos-arm64-supervised-2026-11-01.json) records a 42.546-second run on macOS arm64 with the pinned models and complete local image already prepared. That is a measured warm qualification time, not a fresh-install budget.

## Tool and channel application qualification

The [expanded macOS arm64 report](../qualification/application-tools-macos-arm64.json) records a 123.905-second supervised run with the exact image and model digests, external IP connections denied and container networking disabled. It covers actual model tool invocation, delivery of the exact text to storage, denial for an ungranted channel, success on that same channel after a real chain grant, and denial with unchanged messages after removal of the grant. An independent model session is used for each tool attempt; the persisted tool call and linked result must exist. A model saying that it acted is insufficient.

The same run sends an owner message through `terrier channel publish` and waits for a completed agent reply through `terrier channel poll`. It also retains the existing foreign-chat denial, model/service restart, conversation recall, archive, relay revocation and retained-data checks. Inputs were already downloaded and binaries/image built; the measured total includes the supervised application lifecycle, not image compilation or installation.

Rebuild the image from the corrected source before running this expanded scenario. The shared native client now joins trailing-slash service endpoints with canonical route paths; the previous double-slash request was rejected by the local transport. The source base and changed product-file hash in the report identify the tested correction. Both packaged executables and first-party runtime packages passed the artifact privacy check. Persistent authorized application memory, browser enrollment and independent clean installation remain unqualified. Failed runs retain private tool diagnostics alongside the existing private service logs.
