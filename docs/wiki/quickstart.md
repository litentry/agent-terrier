Run a development chain, protected local owner, scoped storage, local model, Docker agent and website on one machine. No company account is required. Download dependencies, images and models before using the offline mode. Use new development identities only; the software signer is not production wallet custody.

## Prepare the public checkout

Use the Rust version in [rust-toolchain.toml](../../rust-toolchain.toml), Python 3, Node 24 or later, npm, jq, Foundry (`forge` and `anvil`), Docker with a local Unix socket, and `wasm-pack` with Rust's `wasm32-unknown-unknown` target. Install the model runner version declared in [the model recipe](../../presets/local-models.json). The recorded real-model configuration is macOS arm64 with an Apple M3 Pro and 18 GiB RAM; this is measured hardware, not a minimum requirement. Builds, model files and Docker layers need additional disk space.

Local, from a fresh public repository checkout:

```sh
./terrier contracts setup
./terrier contracts test
cargo build --workspace --bins
npm ci --ignore-scripts
python3 scripts/build-browser-core.py
npm --prefix apps/parent-control run build
```

The contract commands download only explicitly requested public build inputs. The Rust and npm lockfiles own application dependencies. [Contract development](./contract-development.md) explains the pinned compiler and an explicit compiler path when needed. State and keys are generated outside the checkout; never copy an existing wallet or deployment configuration into it.

Local, from that checkout, build the public runtime image:

```sh
export AGENT_TERRIER_RUNTIME_IMAGE="${AGENT_TERRIER_RUNTIME_IMAGE:-agent-terrier-runtime:local}"
docker build --file packages/agent-terrier-runtime/Dockerfile \
  --tag "${AGENT_TERRIER_RUNTIME_IMAGE}" .
```

Follow [Prepare models](./local-models.md#prepare-models) once to download the recipe's chat and embedding models and run the capability probe. Stop that preparation runner before starting the managed stack. Keep the model directory outside the development state directory so reset cannot erase downloaded models.

## Start and create an owner

Use the same local terminal and public checkout for the commands below. Set the explicitly selected Docker socket and prepared model directory. `AGENT_TERRIER_STATE_DIR` optionally selects a new absolute state directory outside the checkout; otherwise the CLI uses its standard private local state directory. Use a different state directory for an independent installation.

```sh
./terrier stack start --website \
  --runtime-image "${AGENT_TERRIER_RUNTIME_IMAGE:?Build and select the public image}" \
  --docker-socket "${AGENT_TERRIER_DOCKER_SOCKET:?Set the local Docker Unix socket path}" \
  --model-dir "${OLLAMA_MODELS:?Set the prepared model directory}"
./terrier stack doctor
./terrier models probe
export AGENT_TERRIER_OWNER_NAME="${AGENT_TERRIER_OWNER_NAME:-developer}"
./terrier owner register --name "${AGENT_TERRIER_OWNER_NAME}"
./terrier owner login --name "${AGENT_TERRIER_OWNER_NAME}" \
  --broker-url "$(./terrier stack status | jq -er '.services.services.broker.url')"
```

Registration prints the public owner ID (`operator_omni`) and account. Login writes the development session to protected local state and prints a receipt without its bearer. Stop on an error; readiness alone does not prove inference, which is why the model probe is separate. Repeating a healthy stack start reuses the existing stack. Later start/restart commands retain its image, model directory and website origin.

## Get a result from the CLI

Local, from the same checkout and selected state:

```sh
export AGENT_TERRIER_AGENT_LABEL="${AGENT_TERRIER_AGENT_LABEL:-assistant}"
./terrier agent spawn --name "${AGENT_TERRIER_OWNER_NAME}" \
  --label "${AGENT_TERRIER_AGENT_LABEL}"
```

Use `device_key_hash` from the successful creation receipt for the next command. A pending or partial creation is not success; [receipt recovery](./local-agents.md#check-confirmation-without-resubmitting) checks its recorded outcome without blindly creating another agent.

Local, from the same checkout, send a real model turn through the protected shared bridge:

```sh
jq -n --arg text 'Reply with a short greeting. /no_think' '{text:$text,stream:false}' |
  ./terrier agent bridge --name "${AGENT_TERRIER_OWNER_NAME}" \
    --device-key-hash "${AGENT_TERRIER_DEVICE_KEY_HASH:?Set the created agent device key hash}" \
    --path /v1/chat --json-stdin
```

The JSON response must contain the agent's actual reply. [Channel messages](./local-channels.md) and [persistent knowledge](./local-knowledge.md) use the same owner and agent. Knowledge access requires an exact chain grant; configuration names do not grant access.

## Use the website

Local, from the same checkout, print the saved website origin:

```sh
./terrier stack status | jq -er '.services.services.website.url'
```

Open that origin, enter the public owner ID, and follow [CLI-approved browser access](./local-browser.md). The browser creates its own passkey request; the owner reviews and approves it through the CLI, then the browser signs in. Owner key files never enter the browser. Recorded browser checks cover this handoff, repeat sign-in, agent creation, local-model chat, note storage and recovery of an interrupted creation after service restart. They use a temporary virtual authenticator; physical PRF-capable authenticators need separate testing. Keep the tab open while an operation is pending: reload or sign-out discards its in-memory recovery record. Optional audit-archive operations report that an archive is unconfigured; see [website configuration](./local-website.md).

## Stop, restart and develop

Local, from the same checkout and state directory:

```sh
./terrier stack stop
./terrier stack start
./terrier test core
./terrier test focused --component ui
```

Stop/start preserves contracts, owner identities, saved documents and agent state. Archive revokes an agent and retains its application data. [Explicit development reset](./local-manager.md#explicit-development-reset) requires the exact selected state path and erases that installation's identities, data and owned runtime resources. There is no automatic reset or migration on a version mismatch.

Use [the terminal manager](./local-manager.md) for the same lifecycle commands, [test lanes](./test-lanes.md) for CLI-only iteration and scheduled checks, and [the contributor guide](../../CONTRIBUTING.md) for changes. Missing binaries, unavailable Docker, a busy model port, missing models or unsafe state permissions fail explicitly; the linked service/model guides explain recovery. Logs can contain private development data and should be reviewed before sharing.
