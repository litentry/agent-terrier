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

## Offline qualification

The checked-in macOS qualifier launches its own temporary runner with an isolated home directory, cloud features disabled and OS-level outbound network denial. It verifies an external socket gets `PermissionError`, then runs the real CLI under the same restriction; successful loopback inference is the positive control. Existing model files are reused without download or pruning, exact runtime/model identities are checked, and only the qualifier's processes and temporary files are removed afterward.

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

The relay defaults to the same local endpoint and chat model as the recipe, binds to loopback, and requires a caller relay key. An upstream model key is optional. Configuration comes only from explicit `AGENTKEYS_GATE_*` inputs or flags; the relay does not discover host credential files. Without a relay keys file, inference requests return 401. Use `agentkeys-gate --help` for the explicit configuration fields; the complete local launcher is still under development.

`--upstream-api-key-file` and `--keys-file` must name owner-only regular files owned by the current user, with no symlinks or hard links. Supplying both inline and file forms of the upstream credential is an error. Invalid explicit configuration fails startup instead of selecting another endpoint. The chat model override never overwrites an embedding request's model.

Keep one relay process per keys file. Its parent directory must be owned by the current user, must not be a symlink, and must not be writable by other users. Provisioning/rotation/revocation writes a private temporary file and atomically replaces the registry before changing live records. If persistence fails, new authenticated requests and readiness return 503 until restart. Stop the relay, correct the storage/permission problem, inspect or restore the last committed private registry, and restart; then explicitly reapply the failed change. Do not delete the registry as a recovery shortcut: a failed write may have reached disk before a later synchronization error. In-memory mode has no restart persistence and is reported at startup.

Optional decision endpoints use `--decision-config`, a protected JSON file with optional `jev` and `kev` objects. Each object has a required `base_url` and optional `api_key_file`; unknown fields fail. No default decision endpoint is selected. Search is disabled unless an endpoint is explicitly configured. Audio routes retain authentication and return 503 because this binary has no speech adapter. Downstream applications can inject the shared speech interface; they must pass its contract tests against their pinned source revision.

Local, in the public checkout on macOS, with downloaded models and cached Rust dependencies:

```bash
python3 scripts/tests/qualify_local_models.py --models-dir "${OLLAMA_MODELS}" --gate
```

This builds the explicit relay qualification without downloading dependencies, then runs it under the same outbound network denial as the model server. It reuses the canonical capability probe and requires positive usage accounting. Fast tests separately prove absent/wrong caller credentials are rejected without reaching the model, while an authorized caller succeeds; legacy host credentials do not affect the selected upstream.

The [relay qualification record](../../e2e/fixtures/model-qualification/macos-arm64-relay-2026-10-31.json) reports a 2.809-second relay probe on the same Mac/model recipe, including streamed chat, tool execution returning 42 and correct 768-dimensional embedding retrieval. The direct probe ran first, so this is a warm relay measurement, not a cold-start promise. Sampled model-runner RSS peaked at 1,965,792 KiB; relay memory is not included.

The recall probe uses three synthetic in-memory documents. It proves inference and vector retrieval, not persistent authorized application memory. Complete agent-image wiring, broker configuration, storage-backed recall and the full offline application journey remain tracked by the open local-runtime epic.
