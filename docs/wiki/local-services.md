The local service launcher starts the real broker and four storage workers, each with its own persistent object database. It uses the existing chain controller, key generators, protected state files and worker executables. It does not start the full agent image, model server, browser signer or web console yet.

## Start the services

Local, from the public checkout, prepare dependencies and binaries:

```bash
./terrier contracts setup
cargo build -p agentkeys-cli -p agentkeys-broker-server -p agentkeys-local-store \
  -p agentkeys-worker-creds -p agentkeys-worker-config \
  -p agentkeys-worker-memory -p agentkeys-worker-channel
./terrier chain start
./terrier chain deploy
./terrier services start
```

State lives outside the source checkout in the same private directory used by `terrier chain` and `terrier owner`. `AGENT_TERRIER_STATE_DIR` selects an explicit directory. `--bin-dir` or `AGENT_TERRIER_BIN_DIR` selects built service binaries; the default is the checkout's `target/debug` directory. No build, model download or cloud discovery happens implicitly during startup.

The first start generates fresh broker signing keys and a separate development encryption key for every data class. It chooses and persists a broker port; `--broker-port` can select that port on the first start. Later starts retain the issuer address so existing sessions continue to work. Worker and object-service ports are assigned locally and reported in structured output. Every listener is loopback-only.

Repeating `services start` reuses a healthy owned supervisor. It refuses changed ports, another deployment, unhealthy existing services and missing original keys. Startup failures stop only the children launched by that supervisor. An unrelated listener on the selected port is preserved. No process is stopped using a PID found in a state file.

## Use the running broker

Local, from the same checkout and state directory:

```bash
./terrier owner register --name developer
./terrier owner login --name developer \
  --broker-url "$(./terrier services status | jq -r .services.broker.url)"
```

The login receipt omits the bearer. The protected development session file is described in [local owner](./local-owner.md). The launcher does not authorize data operations itself: the broker, workers and object services keep their independent signature and chain checks.

## Inspect and stop

Local, from the same checkout and state directory:

```bash
./terrier services status
./terrier services doctor
./terrier services logs
./terrier services stop
```

`status` reports the owned supervisor, component endpoints, health and chain/profile consistency. `doctor` returns a nonzero exit status if the supervised services are unavailable or unhealthy. Logs are private files with bounded tail output. A stopped or failed component is reported as unhealthy; it is not silently replaced. Inspect the error, stop the group and start it again after correcting the cause.

`services stop` preserves keys, databases and the chain. Restarting services uses the original keys and reads the same encrypted data. Stop the chain separately with `terrier chain stop` when finished. Destructive reset and automatic recovery are not part of this command yet. Missing keys are never regenerated over existing service state.

## Qualification

Local, after building the binaries and preparing contract dependencies:

```bash
python3 -m unittest discover -s scripts/tests
python3 scripts/tests/qualify_local_services.py
```

The explicit qualifier starts actual contracts and all nine service processes, registers and logs in an owner, stores/fetches a credential, and restarts the service group without replacing its keys or issuer. It checks missing-key and changed-deployment refusal, preserves an unrelated listener, injects a component startup failure, verifies cleanup and confirms the chain remains owned and running. It then restarts successfully and reads the same credential. This is separate from the fast default unit-test loop and from the remaining complete agent/model journey.
