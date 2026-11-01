**Status:** Protected creation and archive pass the real local-chain and Docker qualifier, including foreign-owner denial, revoked relay access and retained application data. Actual model chat and persisted conversation recall after runtime recreation also pass with external connections denied. The expanded offline qualifier also verifies model publish tools, grant/removal denials and owner-channel replies. Authorized persistent memory, browser acceptance and recovery of missing creation context remain under development.

## Prepare

Use the [local services](./local-services.md) guide to deploy the development contracts, configure a preloaded [agent image](./local-agent-image.md), register an owner and log in. The supervisor must report healthy services and an explicitly configured Docker runtime. Prepare the [local models](./local-models.md), select `--model-dir` when starting services, and run `terrier models probe` before expecting inference.

The wrapper resolves the existing local owner and current deployment, then passes only protected file paths and local service coordinates to the native CLI. It does not place the session bearer or signing keys in arguments or environment values. The existing session validator checks the development marker, broker, owner, request key and expiry. The native client also checks the bearer identity and requires a local development profile and loopback HTTP service. HTTP proxies and redirects cannot redirect these requests.

## Create

Local, from the public checkout and the same state directory used for owner login:

```sh
./terrier agent spawn --name developer --label assistant
```

Optional `--preset-id`, `--memory-ns` and `--memory-inherited` use the existing broker ceremony and its canonical protocol types. The command builds an operation, checks its chain, EntryPoint and operation hash, signs with the owner's protected development passkey and submits through the existing broker/bundler path. Contracts independently check the signature and authority. Guarded local profiles with zero configured fees use the shared checked live gas quote; explicit fees and nonlocal profile behavior remain unchanged. A failed quote stops the build. The broker derives delegate keys through the configured local signer; the CLI does not generate a second identity implementation.

## Delegate key custody

The broker requires the configured signer for creation and context recovery. Unset or empty `AGENTKEYS_DELEGATE_KEYS` also means signer custody; any other nonempty value is refused. Missing `AGENTKEYS_SIGNER_URL` fails instead of generating a key in the broker. Signer responses must prove the returned device identity; recovery must match the existing chain binding. The runtime receives a scoped session, never a broker-generated delegate private key.

Broker reconstruction rows contain the public address and runtime metadata. Startup refuses old databases with nonempty delegate-key fields before migrating their schema. It does not erase, export or migrate those keys. Preserve such state privately; use a separate fresh development state or an explicitly reviewed recovery procedure. Empty legacy key columns are removed while metadata is retained. Rows without a matching public address cannot recreate a runtime until their sealed context is restored. This schema change makes no claim about erasing historical database pages or backups.

## Call an agent without a browser

`terrier agent bridge` uses the same `BridgeProxyBody` contract and authenticated broker route as the console. The broker independently verifies the current chain owner and live instance, then enforces its route allowlist. No runtime token is exposed to the CLI. These calls do not read the owner's passkey or submit a transaction. `--sandbox-id` optionally pins an existing instance; a stale ID is refused.

Local, from the same public checkout and state directory, with the agent's `device_key_hash`:

```sh
./terrier agent bridge --name developer \
  --device-key-hash "${AGENT_TERRIER_DEVICE_KEY_HASH:?Set the agent device key hash}" \
  --method GET --path /healthz
```

Local, from that checkout, after starting the configured local model:

```sh
jq -n --arg text "${AGENT_TERRIER_CHAT_TEXT:?Set the message text}" '{text:$text,stream:false}' |
  ./terrier agent bridge --name developer \
    --device-key-hash "${AGENT_TERRIER_DEVICE_KEY_HASH:?Set the agent device key hash}" \
    --path /v1/chat --json-stdin
```

The existing bridge also exposes jobs, context files/application and agent restart. The broker owns the [route allowlist](../../crates/agentkeys-broker-server/src/handlers/bridge_proxy.rs); the [runtime bridge](../../packages/agentkeys-dsh/src/bridge.ts) owns each inner request/response. Supply a JSON object with `--json-stdin` for a POST body. GET requests have no body. This command supports JSON responses; streaming through the broker bridge remains unsupported. The model capability probe separately tests streaming.

Successful output wraps the route's JSON in `response` alongside `development_only`, `action` and `device_key_hash`. Non-success HTTP status, malformed/oversized JSON and transport failures exit nonzero; backend error bodies are not printed. Request and response bodies are limited to 1 MiB. `--timeout-seconds` controls the native request deadline (default 200, range 1–600); the broker may impose a shorter route deadline. Health success does not prove model inference; use a real chat turn to check that separately.

## Archive while retaining data

Local, from that same checkout and state directory, using `device_key_hash` from the creation receipt:

```sh
./terrier agent archive --name developer \
  --device-key-hash "${AGENT_TERRIER_DEVICE_KEY_HASH:?Set the agent device key hash}"
```

Archive revokes the selected delegate on chain, disables its model-relay key and requests runtime teardown. The wrapper always selects retained application resources and offers no data-delete flag. Ordinary runtime removal preserves the owned state volume. The broker independently reports runtime removal, deletion of its reconstruction context and relay revocation; a confirmed chain transaction does not conceal a cleanup failure. A different owner cannot archive the delegate.

## Interpret the receipt

JSON output contains public operation identity and stage flags, not raw backend error bodies or credentials. Exit zero requires `complete: true`: a confirmed chain receipt plus relay and runtime readiness for creation, or confirmed revocation plus relay disablement, context removal and stopped runtime for archive. This is lifecycle evidence, not proof of inference, channel synchronization or browser usability.

An incomplete or pending operation prints its available operation/transaction identity and exits nonzero. If a submission response is lost or invalid, `submission_status: unknown` preserves the built operation hash. Do not blindly submit again: the transaction may already have mined. Use receipt recovery instead. Restoring a missing request key means restoring the original file, not generating a replacement.

## Check confirmation without resubmitting

New operations save a protected record under the existing owner's `operations` directory before signing or submission. The record contains the canonical unsigned operation, its local owner/request-key/broker/chain binding and the requested resource-retention choice. It contains no session bearer, private key or passkey assertion. A failed save stops submission, and existing records are never overwritten.

Local, from the same public checkout and state directory, using the operation hash printed by the original command:

```sh
./terrier agent receipt --name developer \
  --user-op-hash "${AGENT_TERRIER_USER_OP_HASH:?Set the original operation hash}"
```

The command validates the protected record and current session, then calls the existing authenticated confirmation endpoint. It does not read the development passkey, sign or submit a transaction. The broker independently verifies the operation's owner and chain receipt, and may finish the already-authorized local lifecycle work. Keep the original request key and use a current owner login. Records from another owner, request key, broker or chain are refused.

Receipt confirmation is not a live health check. A missing record cannot be reconstructed from its hash alone by this command. Records are written only by the protected local commands introduced with this feature; older operations do not have them. Archive cleanup is reconstructed from the independently verified chain revocation, so a broker restart does not prevent retrying relay disablement, context removal or runtime teardown. It uses the shared cleanup owner and never submits a second transaction. The retained-data choice comes from the protected record or the original archive result; an older record without that choice stays incomplete if the original result is also unavailable. Missing creation context can likewise leave creation incomplete. These cases exit nonzero; never resubmit solely to clear that status.

## Console bridge routing

Managed console requests use the broker's authenticated bridge route. A configured broker, owner session and delegate binding are required; missing information is an error even when a direct agent URL is available. The broker independently checks chain ownership and the selected live instance. Without an instance ID it resolves the delegate's live runtime. A broker refusal or redirect never retries directly, and bridge requests ignore ambient HTTP proxy configuration. These routing checks do not complete browser enrollment or full browser acceptance.

## Explicit qualification

Local, from the public checkout, select an existing reviewed image and Docker socket, then run:

```sh
AGENT_TERRIER_TEST_AGENT_IMAGE="${AGENT_TERRIER_RUNTIME_IMAGE:?Set the reviewed preloaded image}" \
AGENT_TERRIER_TEST_DOCKER_SOCKET="${AGENT_TERRIER_DOCKER_SOCKET:?Set the local Docker Unix socket}" \
python3 scripts/tests/qualify_local_agents.py
```

The qualifier creates disposable owners, contracts and services. It checks session/file/owner denials for unchanged chain, relay and container state, then creates and archives an actual Docker runtime and verifies retained volume data and disabled relay access. It checks receipt recovery without the passkey, foreign and altered records, unchanged chain state on confirmation, and archive cleanup after a broker restart. A controlled local admin fixture provisions a leftover relay credential: it remains usable after a foreign-owner recovery denial and becomes unusable after the rightful owner recovers the confirmed revocation. Older records without retention evidence remain incomplete. A separate fast HTTP fixture simulates a lost submission response and proves recovery makes no second submission. It removes only its own labeled Docker resources. Failed runs retain a private diagnostic directory and report its path; review those files before sharing them. This heavier qualification is separate from ordinary CLI unit and HTTP checks.

For actual model-backed chat under external network denial, use the [managed application qualification](./local-models.md#managed-application-qualification). It calls this same lifecycle qualifier; there is no second service or Docker supervisor.
