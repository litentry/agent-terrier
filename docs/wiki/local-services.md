The local service launcher starts the real broker, development signer, authenticated model relay, transaction submitter and four storage workers, each with its own persistent object database. It uses the existing chain controller, signing implementation, key generators, protected state files and worker executables. It can configure the broker to use a reviewed local agent image. It does not start the model server or web console yet; full agent creation remains under integration.

## Start the services

Local, from the public checkout, prepare dependencies and binaries:

```bash
./terrier contracts setup
cargo build -p agentkeys-cli -p agentkeys-broker-server -p agentkeys-local-store \
  -p agentkeys-worker-creds -p agentkeys-worker-config \
  -p agentkeys-worker-memory -p agentkeys-worker-channel -p agentkeys-mock-server \
  -p agentkeys-gate -p agentkeys-bundler
./terrier chain start
./terrier chain deploy
./terrier services start
```

State lives outside the source checkout in the same private directory used by `terrier chain` and `terrier owner`. `AGENT_TERRIER_STATE_DIR` selects an explicit directory. `--bin-dir` or `AGENT_TERRIER_BIN_DIR` selects built service binaries; the default is the checkout's `target/debug` directory. No build, model download or cloud discovery happens implicitly during startup.

The first start generates fresh broker signing keys, a development signer master key, a model-relay admin token and a separate development encryption key for every data class. It chooses and persists a broker port; `--broker-port` can select that port on the first start. Later starts retain the issuer address so existing sessions continue to work. Signer and worker listeners are reserved before the broker starts, then verified against each child's announced address. The broker receives those explicit endpoints and uses the local signer for delegate keys. Relay and object-service ports are also assigned locally and reported in structured output. Every listener is loopback-only.

Repeating `services start` reuses a healthy owned supervisor. It refuses changed ports, another deployment, unhealthy existing services and missing original keys. Startup failures stop only the children launched by that supervisor. An unrelated listener on the selected port is preserved. No process is stopped using a PID found in a state file.

The service manifest is version 5. It retains the optional image/socket/runtime namespace configuration; older manifests migrate with agent runtime disabled until explicitly configured. Stop an older supervisor before starting the updated launcher. Migration verifies existing state and creates only newly introduced files: the signer key for version 1, relay admin/key-registry files for versions 1 and 2, and the transaction submitter key for versions 1 through 3. It preserves existing keys and data. Once introduced, a missing file requires restoration; migration never regenerates a previously required key.

## Configure the local agent image

After building the [public image](./local-agent-image.md), local in the same public checkout and state directory:

```sh
./terrier services stop
./terrier services start --runtime-image agent-terrier-runtime:local \
  --docker-socket "${AGENT_TERRIER_DOCKER_SOCKET:?Set the local Docker Unix socket}"
```

Image and socket must be supplied together the first time. The selected image must already exist and provide the managed entry point; startup never pulls it. Subsequent stop/start retains the image, socket and unique runtime namespace. Stop services before selecting an updated image. An existing state directory cannot silently switch Docker engines; use a separate state directory for another socket.

The supervisor gives the broker an isolated empty Docker client configuration and the canonical public transport script. It does not inherit Docker login configuration or context selection. The broker checks the image before reporting startup readiness. An absent/invalid image stops the owned startup group; correct the explicit image and retry. `status` reports the configured runtime separately from component health. This proves configuration and image availability, not successful agent creation or inference.

## Local model relay

The launcher starts the existing `agentkeys-gate` executable using the [local model recipe](./local-models.md). The model runner itself must be started separately. The relay binds to loopback and explicitly rejects a remote upstream. It starts with no authorized inference callers. The broker receives the relay endpoint and a path to the same protected admin token; the token is absent from command arguments and child environment values.

The broker and relay consume one shared provisioning schema in `agentkeys-protocol::model_relay`. Provisioned credentials include the selected model ID through the canonical runtime environment builder. Admin mutations require the admin token; inference and usage require a provisioned, enabled caller credential. The protected key registry persists creation and revocation before reporting success. Partial or conflicting admin configuration fails startup without falling back.

`services doctor` checks the relay's credential-persistence/readiness status along with the other services. It does not execute inference or prove that the model runner is available; run `terrier models probe` for real model capability checks. Usage counters remain process-local. The full broker-to-delegate session and managed-container wiring are still being completed.

## Local transaction submission

The supervisor starts the existing ERC-4337 bundler with an explicit development profile and a fresh protected submitter key. It uses the shared secp256k1 key reader/generator already used for device keys, but has its own identity and file. The key never appears in command arguments, environment values or structured receipts. Startup checks the owned Anvil identity and tops up this disposable account to the profile's development funding amount when needed. This funding helper cannot select a remote node.

The local bundler ignores ambient chain/key settings, requires a deployed EntryPoint, binds only to loopback and refuses missing or unsafe keys. `services doctor` treats an explicitly unready service as unhealthy even when its process is alive. Stop/start retains the submitter key and chain state. Pending-operation lookup is process-local; after a restart, use the transaction hash with the native receipt verifier instead of expecting the bundler to retain its in-memory receipt index.

The native `chain prepare-owner` result includes `rpc_user_op`, generated by the shared ERC-4337 converter for standard bundler submission. Contract authorization still comes from the owner's P-256 signature. The bundler submits the outer transaction; it cannot grant user authority. The broker reads the same protected development submitter key through its file option; its existing mandatory signer and contract authorization rules are retained. It resolves RPC, chain ID and contract addresses from the active profile, while existing explicit overrides remain subject to the profile drift check. A paymaster entry in the profile does not implicitly enable sponsorship. End-to-end delegate/container startup is still being connected.

## Development signing

`agentkeys-local-signer` is a small startup entry point in the existing mock-server package. It serves the shared signer routes, not mock identity or session APIs. It requires an explicit local development chain profile, the broker's session public key and an existing protected master-key file. The launcher creates that file with mode 0600 under the private `services/signer` directory; only its path is passed to the process. The local entry point ignores the legacy environment-secret configuration and keeps signing material out of command arguments, logs and containers.

Wallet signing requires a valid broker session for the requested actor. Device-key derivation also supports the existing verified parent/child rule; device capability proofs require the actor's own session. Missing or invalid sessions and cross-actor signing are refused. The local entry point exposes only loopback HTTP and refuses linked, shared, missing or malformed key files. The signer reuses existing derivation and authorization code, and its in-memory master key is cleared when dropped. This is development software signing; it provides no production custody or hardware protection. Browser integration and the complete delegate journey remain pending.

## Use the running broker

Local, from the same checkout and state directory:

```bash
./terrier owner register --name developer
./terrier owner login --name developer \
  --broker-url "$(./terrier services status | jq -r .services.broker.url)"
```

The login receipt omits the bearer. The protected development session file is described in [local owner](./local-owner.md). The launcher does not authorize data operations itself: the broker, workers and object services keep their independent signature and chain checks.

## Store and fetch a development credential

Local, from the same checkout and state directory, using a synthetic example:

```bash
printf %s 'local-development-example' | ./terrier cred store example --name developer --secret-stdin
./terrier cred fetch example --name developer
```

`store` reads exact UTF-8 bytes from stdin (including any newline), with a 64 KiB limit. Its JSON receipt contains no secret. `fetch` deliberately returns the decrypted value in the JSON `secret` field. Both commands load the existing protected owner session and request key directly in the native client; no bearer or key is copied into command arguments or the child environment. The wrapper resolves endpoints from the healthy owned supervisor and verifies the deployment identity.

Expired sessions, wrong owners, wrong request keys, a different broker, unsafe session files and missing original keys fail. Log in again when the session expires; missing keys must be restored. Native local credential requests require the development profile and loopback endpoints, ignore HTTP proxies, and refuse redirects. The shared credential client still obtains a fresh capability and the broker, worker and object store independently enforce authorization. This command currently supports owner credential storage/read; delegate-session commands and other data-class operations remain unfinished.

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
python3 scripts/tests/qualify_local_bundler.py
python3 scripts/tests/qualify_local_credential_cli.py
```

To include managed-image startup and missing-image recovery, set `AGENT_TERRIER_TEST_AGENT_IMAGE` and `AGENT_TERRIER_TEST_DOCKER_SOCKET` before running the service qualifier. Both must be set together. This mode uses the reviewed preloaded image and still performs no model inference.

The explicit qualifier starts actual contracts and all twelve service processes, registers and logs in an owner, verifies a real signature, stores/fetches a credential, and restarts the service group without replacing its keys, derived signing address or issuer. It builds a delegate operation through the real signer, checks repeat/restart identity consistency, rejects unauthenticated and foreign-owner builds, and verifies building alone leaves the chain unchanged. It checks unauthenticated and cross-actor signing denial, missing-key and changed-deployment refusal, preserves an unrelated listener, injects a component startup failure, verifies cleanup and confirms the chain remains owned and running. It also proves missing/wrong relay admin credentials cannot change the key registry, authorized provisioning survives restart, revocation survives restart, and missing relay files are refused. It then restarts successfully and reads the same credential. This is separate from the fast default unit-test loop and from the remaining complete agent/model journey.

The credential qualifier drives `terrier cred` through real owner sessions. It checks exact round-trip bytes and restart persistence, cross-owner isolation, expired/invalid/mismatched sessions, private-file permissions, missing keys, deployment mismatch, input bounds and remote endpoint refusal. Redirect and proxy controls prove no follow-on request reaches the alternate listener. Denied stores must leave the database unchanged, and error output must omit bearer and credential values.

The bundler qualifier submits real P-256-signed grant and revocation operations through the supervised service. A tampered signature must produce a failed chain receipt and leave the grant unchanged; the authorized operation must then succeed. It also verifies low-funds reporting, restart persistence, remote/non-loopback refusal and key-generation non-overwrite.
