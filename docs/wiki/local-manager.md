The lightweight manager is a terminal menu over the same `terrier stack` commands used by scripts. It adds no server, credential store, Docker controller or service supervisor. It manages the local chain, backend service group and an explicitly configured local model runner. It can also own the prebuilt [local website](./local-website.md).

## Prepare once

Build the binaries and prepare contract dependencies using [local services](./local-services.md). For agents, prepare the reviewed [local image](./local-agent-image.md) and [models](./local-models.md). Startup uses cached contract inputs only and never builds or downloads implicitly. State lives outside the checkout; select a dedicated development directory with `AGENT_TERRIER_STATE_DIR` when running multiple stacks.

Local, in the public checkout, after preparation:

```sh
./terrier stack start
./terrier manage
```

For the first managed-image startup, local in that same checkout and state directory:

```sh
./terrier stack start \
  --runtime-image "${AGENT_TERRIER_RUNTIME_IMAGE:?Set the reviewed preloaded image}" \
  --docker-socket "${AGENT_TERRIER_DOCKER_SOCKET:?Set the local Docker Unix socket}" \
  --model-dir "${OLLAMA_MODELS:?Set the prepared model directory}"
```

The menu displays the selected state directory and offers status, health, start, persistent restart, private logs, stop and explicitly confirmed reset. Add `--website` to `stack start` after building the console to include website startup; the menu reuses that persisted choice. It dispatches the canonical CLI and reports unsuccessful operations. Quit leaves services running. A terminal is required; automation should use the commands below.

## Scriptable lifecycle

Local, in the same public checkout and state directory:

```sh
./terrier stack status
./terrier stack doctor
./terrier stack logs
./terrier stack restart
./terrier stack stop
```

`start` starts the owned chain, verifies or deploys its contracts, then starts the existing service group. A second start reuses healthy owned processes. `restart` stops services before the chain, then starts from the same saved chain and service state. It preserves keys, contract addresses, service data and the broker endpoint. The existing chain profile owns the saved RPC port; no second manager configuration file is introduced. `--chain-port` explicitly selects a port, while `--bin-dir`, `--broker-port`, `--runtime-image`, `--docker-socket`, `--model-dir`, `--model-binary`, `--website` and `--web-port` use the service controller's existing configuration rules. Configuration flags require `start` or `restart`; keep a custom binary directory in `AGENT_TERRIER_BIN_DIR` for menu use.

`status` reports both controllers even when one cannot be reached. `doctor` exits nonzero unless both are healthy. Structured operation output includes `success`, `action`, `chain` and `services`. A startup failure also reports `failed_stage`, `error` and any cleanup outcome. A configured model runner is included in readiness through version/inventory checks. Without model configuration, readiness covers the backend only. Inference still requires `models probe`; website delivery is checked when configured; complete authenticated browser acceptance remains separate.

If startup fails, a chain started by that operation is stopped only when services are confirmed stopped. An already-running chain is preserved. An uncertain control response preserves the chain and reports the error. Stop requires confirmed service shutdown before stopping the chain. All process operations use the existing private control sockets; saved PIDs are never signal authority. Generated state is retained after failures so it can be inspected or resumed. Interrupted deployment still requires the explicit `chain deploy --resume` procedure from [local chain](./local-chain.md).

Logs contain private development diagnostics. Review them before sharing. Stop/restart do not erase local state or agent volumes. Complete browser acceptance remains separate release work.

## Explicit development reset

Reset permanently removes the selected stack's owner/device keys, saved sessions, contracts and local chain state, service databases, private diagnostics and owned agent containers/volumes. It is a new development installation, not account recovery or an on-chain revocation on another deployment. The original identities cannot be recovered without a separate private backup.

Local, from the prepared public checkout, select the exact canonical state directory you intend to erase. Build the runtime cleanup entry point if it is not already built:

```sh
cargo build -p agentkeys-runtime --bin agent-terrier-reset-runtime
export AGENT_TERRIER_STATE_DIR="${AGENT_TERRIER_STATE_DIR:?Set the exact absolute local state directory to erase}"
./terrier stack reset --confirm-state "${AGENT_TERRIER_STATE_DIR}"
```

The confirmation must exactly match the selected absolute path, including resolved directory aliases. The terminal menu requires typing that same path. There is no implicit reset during startup or version migration. Reset requires a valid development profile and, when services exist, their matching manifest. Missing/corrupt ownership metadata must be restored before retrying; reset does not guess which resources belong to it.

The existing controllers stop services and the chain, then their locks must be released before removal. The Docker adapter inventories the manifest's namespace and validates all container, volume and network ownership before cleanup. Another stack, unrelated files, image layers and downloaded models are retained. Models must live outside the selected state directory; reset refuses a configured model directory inside it. The Docker engine must be reachable when a runtime was configured. No image download or model startup is needed for removal.

Wrong confirmation, foreign metadata, links, unexpected root entries or uncertain shutdown refuse deletion. Runtime cleanup failure retains the host state for inspection/retry; some owned runtime resources may already be removed if the engine fails mid-operation. A filesystem failure is likewise reported as incomplete. The operation is not an atomic secure erasure guarantee. Three empty lock files remain to prevent concurrent commands from acquiring replacement locks. Repeating a completed reset succeeds. Start the stack again to deploy fresh contracts, then register a fresh owner; previous startup settings must be supplied again.

## Qualification

Local, from the prepared public checkout:

```sh
python3 -m unittest discover -s scripts/tests -p test_local_stack.py
python3 scripts/tests/qualify_local_services.py
```

The real-service qualifier drives the same CLI: failed fresh startup with missing binaries, owned-chain cleanup, retry using the saved nondefault RPC port, idempotent start and full backend restart. It verifies preserved keys, exact credential bytes, signer identity, contract profile and relay authorization alongside the existing service isolation checks. Fast tests cover uncertain shutdown, partial status, foreign-process preservation, reset confirmation, links/foreign files, lock ownership and menu/CLI dispatch parity. The real-service reset scenario proves refusal preserves the live stack and keys, confirmed deletion leaves another chain running, and the next start creates a fresh deployment and owner. The explicit Docker qualifier separately proves namespace reset preserves another running stack, its stored bytes and the shared image.

The native console’s **clear recovered binding** action is separate from a destructive stack reset. It confirms that authorized registry recovery already removed the master and all device bindings, then clears matching local state. It cannot sign a recovery transaction or discover a deployer key. Failed chain confirmation or pending-pairing cleanup preserves local binding state. Other owners and broker sessions are retained.
