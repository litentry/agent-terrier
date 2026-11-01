The lightweight manager is a terminal menu over the same `terrier stack` commands used by scripts. It adds no server, credential store, Docker controller or service supervisor. It manages the local chain, backend service group and an explicitly configured local model runner. Website startup remains separate.

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

The menu displays the selected state directory and offers status, health, start, persistent restart, private logs and stop. It dispatches the canonical CLI and reports unsuccessful operations. Quit leaves services running. A terminal is required; automation should use the commands below.

## Scriptable lifecycle

Local, in the same public checkout and state directory:

```sh
./terrier stack status
./terrier stack doctor
./terrier stack logs
./terrier stack restart
./terrier stack stop
```

`start` starts the owned chain, verifies or deploys its contracts, then starts the existing service group. A second start reuses healthy owned processes. `restart` stops services before the chain, then starts from the same saved chain and service state. It preserves keys, contract addresses, service data and the broker endpoint. The existing chain profile owns the saved RPC port; no second manager configuration file is introduced. `--chain-port` explicitly selects a port, while `--bin-dir`, `--broker-port`, `--runtime-image`, `--docker-socket`, `--model-dir` and `--model-binary` use the service controller's existing configuration rules. Configuration flags require `start` or `restart`; keep a custom binary directory in `AGENT_TERRIER_BIN_DIR` for menu use.

`status` reports both controllers even when one cannot be reached. `doctor` exits nonzero unless both are healthy. Structured operation output includes `success`, `action`, `chain` and `services`. A startup failure also reports `failed_stage`, `error` and any cleanup outcome. A configured model runner is included in readiness through version/inventory checks. Without model configuration, readiness covers the backend only. Inference still requires `models probe`; website/browser acceptance remains separate.

If startup fails, a chain started by that operation is stopped only when services are confirmed stopped. An already-running chain is preserved. An uncertain control response preserves the chain and reports the error. Stop requires confirmed service shutdown before stopping the chain. All process operations use the existing private control sockets; saved PIDs are never signal authority. Generated state is retained after failures so it can be inspected or resumed. Interrupted deployment still requires the explicit `chain deploy --resume` procedure from [local chain](./local-chain.md).

Logs contain private development diagnostics. Review them before sharing. Stop/restart do not erase local state or agent volumes. Destructive reset, website startup and complete browser acceptance remain separate release work; this menu does not imply those features are complete.

## Qualification

Local, from the prepared public checkout:

```sh
python3 -m unittest discover -s scripts/tests -p test_local_stack.py
python3 scripts/tests/qualify_local_services.py
```

The real-service qualifier drives the same CLI: failed fresh startup with missing binaries, owned-chain cleanup, retry using the saved nondefault RPC port, idempotent start and full backend restart. It verifies preserved keys, exact credential bytes, signer identity, contract profile and relay authorization alongside the existing service isolation checks. Fast tests cover uncertain shutdown, partial status, foreign-process preservation and menu/CLI dispatch parity.
