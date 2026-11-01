**Status:** Protected creation and archive pass the real local-chain and Docker qualifier, including foreign-owner denial, revoked relay access and retained application data. Full model/browser journeys and complete recovery across broker restarts remain under development.

## Prepare

Use the [local services](./local-services.md) guide to deploy the development contracts, configure a preloaded [agent image](./local-agent-image.md), register an owner and log in. The supervisor must report healthy services and an explicitly configured Docker runtime. Start and qualify the [local models](./local-models.md) separately before expecting inference.

The wrapper resolves the existing local owner and current deployment, then passes only protected file paths and local service coordinates to the native CLI. It does not place the session bearer or signing keys in arguments or environment values. The existing session validator checks the development marker, broker, owner, request key and expiry. The native client also checks the bearer identity and requires a local development profile and loopback HTTP service. HTTP proxies and redirects cannot redirect these requests.

## Create

Local, from the public checkout and the same state directory used for owner login:

```sh
./terrier agent spawn --name developer --label assistant
```

Optional `--preset-id`, `--memory-ns` and `--memory-inherited` use the existing broker ceremony and its canonical protocol types. The command builds an operation, checks its chain, EntryPoint and operation hash, signs with the owner's protected development passkey and submits through the existing broker/bundler path. Contracts independently check the signature and authority. Guarded local profiles with zero configured fees use the shared checked live gas quote; explicit fees and nonlocal profile behavior remain unchanged. A failed quote stops the build. The broker derives delegate keys through the configured local signer; the CLI does not generate a second identity implementation.

## Archive while retaining data

Local, from that same checkout and state directory, using `device_key_hash` from the creation receipt:

```sh
./terrier agent archive --name developer \
  --device-key-hash "${AGENT_TERRIER_DEVICE_KEY_HASH:?Set the agent device key hash}"
```

Archive revokes the selected delegate on chain, disables its model-relay key and requests runtime teardown. The wrapper always selects retained application resources and offers no data-delete flag. Ordinary runtime removal preserves the owned state volume. The broker separately reports runtime removal and deletion of its reconstruction context; a confirmed chain transaction does not conceal a cleanup failure. A different owner cannot archive the delegate.

## Interpret the receipt

JSON output contains public operation identity and stage flags, not raw backend error bodies or credentials. Exit zero requires `complete: true`: a confirmed chain receipt plus relay and runtime readiness for creation, or confirmed revocation plus relay disablement, context removal and stopped runtime for archive. This is lifecycle evidence, not proof of inference, channel synchronization or browser usability.

An incomplete or pending operation prints its available operation/transaction identity and exits nonzero. If a submission response is lost or invalid, `submission_status: unknown` preserves the built operation hash. Do not blindly submit again: the transaction may already have mined. Use receipt recovery instead. Restoring a missing request key means restoring the original file, not generating a replacement.

## Check confirmation without resubmitting

New operations save a protected record under the existing owner's `operations` directory before signing or submission. The record contains the canonical unsigned operation and its local owner, request-key, broker and chain binding. It contains no session bearer, private key or passkey assertion. A failed save stops submission, and existing records are never overwritten.

Local, from the same public checkout and state directory, using the operation hash printed by the original command:

```sh
./terrier agent receipt --name developer \
  --user-op-hash "${AGENT_TERRIER_USER_OP_HASH:?Set the original operation hash}"
```

The command validates the protected record and current session, then calls the existing authenticated confirmation endpoint. It does not read the development passkey, sign or submit a transaction. The broker independently verifies the operation's owner and chain receipt, and may finish the already-authorized local lifecycle work. Keep the original request key and use a current owner login. Records from another owner, request key, broker or chain are refused.

Receipt confirmation is not a live health check. A missing record cannot be reconstructed from its hash alone by this command. Records are written only by the protected local commands introduced with this feature; older operations do not have them. A broker restart can lose pending ceremony details: chain confirmation can then succeed while lifecycle completion stays false. Such results still exit nonzero; complete lifecycle recovery across restarts remains open. Never resubmit solely to clear that status.

## Explicit qualification

Local, from the public checkout, select an existing reviewed image and Docker socket, then run:

```sh
AGENT_TERRIER_TEST_AGENT_IMAGE="${AGENT_TERRIER_RUNTIME_IMAGE:?Set the reviewed preloaded image}" \
AGENT_TERRIER_TEST_DOCKER_SOCKET="${AGENT_TERRIER_DOCKER_SOCKET:?Set the local Docker Unix socket}" \
python3 scripts/tests/qualify_local_agents.py
```

The qualifier creates disposable owners, contracts and services. It checks session/file/owner denials for unchanged chain, relay and container state, then creates and archives an actual Docker runtime and verifies retained volume data and disabled relay access. It checks receipt recovery without the passkey, foreign and altered records, unchanged chain state on confirmation, and incomplete lifecycle evidence after a broker restart. A separate fast HTTP fixture simulates a lost submission response and proves recovery makes no second submission. It removes only its own labeled Docker resources. Failed runs retain a private diagnostic directory and report its path; review those files before sharing them. This heavier qualification is separate from ordinary CLI unit and HTTP checks.
