# Architecture and ownership

This document describes the public source tree. The complete local runtime is still under development in [epic #1](https://github.com/litentry/agent-terrier/issues/1); this source-boundary revision is not a full localhost release.

## Components

| Component | Canonical owner | Consumers |
|---|---|---|
| Shared identity and cryptographic primitives | `crates/agentkeys-types`, `crates/agentkeys-device-core`, `crates/agentkeys-core` | Native and browser clients, broker and workers |
| Transport-free wire schemas | `crates/agentkeys-protocol` | Native clients and browser WASM |
| Native service client | `crates/agentkeys-backend-client` | CLI and daemon |
| Browser service client | `crates/agentkeys-web-core` | Web console and browser display |
| Authorization and request coordination | `crates/agentkeys-broker-server` | Product clients and workers |
| Independent worker verification | `crates/agentkeys-core::capability_verify` | Storage and compute workers |
| Smart contracts and contract tests | `crates/agentkeys-chain` | Local deployment and chain clients |
| Headless product operations | `crates/agentkeys-cli`, `crates/agentkeys-daemon` | Developers, tests and the future local manager |
| UI tokens and components | `design-system` | `apps/parent-control`, `apps/device-display` |
| Agent runtime plugins | `packages/agentkeys-dsh` | Agent environments |
| Protocol examples | `e2e/fixtures` | Shared drift and conformance checks |

The device-core crate contains reusable protocol and cryptographic primitives. It does not require firmware or a hardware toolchain for the public workspace build.

The public source excludes hardware firmware, inherited operator documentation and the full operator console. The duplicated design-only applications preview is removed; the product applications UI remains the owner. Both browser apps import one design system and build one WASM client through `scripts/build-browser-core.py`. Generated browser output is ignored by version control and checked again for embedded personal paths before distribution.

`.public-source.json` is the source-surface allowlist; `scripts/check-public.py` enforces it and checks source/artifact contents without printing matched credentials. Synthetic negative-test exceptions require an exact source-line hash and a review reason. They cannot exempt files, directories or unapproved repository links. The scanner supplements manual diff review; it does not prove arbitrary binary or encoded data safe.

Browser compilation remaps Rust source paths. The display build also makes route-manifest source metadata relative to the app root: the framework otherwise embeds workstation paths in its production manifest. Asset URLs and route behavior are unchanged; the artifact privacy check must pass after a framework update.

The card schema has one owner in `agentkeys-protocol::card`. Its TypeScript output lives in `design-system/generated/`; the renderer and both apps consume those generated types. Existing `CardView*` names are aliases, not separate field definitions. Regenerate with `cargo test -p agentkeys-protocol -p agentkeys-daemon export_bindings` after changing a card field.

## Trust boundaries

1. The chain owns identity and authority.
2. Broker state must not create a second authorization source.
3. Actor keys stay with the actor; development signing is explicit and limited.
4. Every access is scoped to an actor, proof and grant.
5. Owner-signed chain mutations may be relayed; the broker does not sign as an owner.
6. Readable personal data remains off-chain.
7. Each cross-component contract has one definition.

Independent checks at broker, worker and storage boundaries remain necessary even when they share types and pure helpers.

Signed capability operations, data classes, payloads and token envelopes have one owner in `agentkeys-protocol::capability`; broker and worker modules re-export those types. Native/browser cap requests and the broker receiver share `BrokerCapRequest`. A missing TTL uses the shared default; an explicit null remains invalid. Forwarding clients retain an opaque JSON transport alias, with no second token schema. Frozen payload-byte tests protect signature/audit compatibility; optional proof fields serialize using the issuer's omitted-field form while readers also accept legacy nulls. Moving the types does not move or bypass independent proof, signature, freshness, chain-binding and scope checks.

ERC-4337 receipt interpretation is owned by `agentkeys-core::user_operation_receipt`. Both bundler reporting and broker finalization check the exact operation event, sender, paymaster, nonce and receipt identity. A mined outer transaction alone is insufficient: a failed inner operation reports failure, while missing or malformed evidence is an error. The broker independently fetches the chain receipt before triggering lifecycle side effects.

## Migration gates

The source tree still contains runtime-specific integrations that must be replaced by neutral interfaces before local release. That work is tracked by [#3](https://github.com/litentry/agent-terrier/issues/3); real local chain/signing, storage, Docker and models follow in [#4](https://github.com/litentry/agent-terrier/issues/4), [#5](https://github.com/litentry/agent-terrier/issues/5), [#6](https://github.com/litentry/agent-terrier/issues/6) and [#7](https://github.com/litentry/agent-terrier/issues/7).

The complete CLI and light manager must call these owners rather than duplicate their implementation. Release acceptance requires a public-only clean install and an offline core journey after downloads. Existing inherited documentation is not the new local setup contract.

The public broker binary defaults to a loopback listener and local storage capabilities. It no longer requires a cloud role, constructs no external storage credential client and runs no cloud credential startup probe. External exchange is explicitly unavailable; embedding applications can inject their own implementation through the existing state interface. Provider selection is not forwarded to actor runtimes. This startup change does not complete source separation: inherited provider implementations, configuration fields and optional email integrations remain under #3 and must be removed before the local release.

| Remaining overlap | Owner | Removal gate |
|---|---|---|
| Remaining storage, signing and model provider integration | Shared neutral interfaces | #3 and local adapter issues remove remaining provider implementations before release |
| Repeated worker authorization helpers | Worker verification and protocol types | #3 and #5 consolidate pure policy while retaining independent enforcement at each boundary |

## Chain configuration

The only built-in profile and default is `anvil`. It contains no deployed accounts, contract addresses or reusable signing keys. Local setup must generate fresh throwaway identities and write deployment addresses to an ignored runtime profile. Explicit `AGENTKEYS_CHAIN_PROFILE_FILE` takes precedence over `--chain`, then `AGENTKEYS_CHAIN`, then the default. Invalid explicit profiles fail instead of silently falling back. Profile schemas reject embedded deploy keys and seed phrases.

Software passkey commands require `AGENT_TERRIER_LOCAL_DEV=1`, the local development chain kind and ID, and a loopback HTTP RPC endpoint. Deterministic K11 parser-test stubs are disabled by default and additionally require `AGENTKEYS_K11_STUB=1`. They are not acceptance evidence for authorization. Local deployment checks the actual node identity and chain ID. Real P-256 owner registration, grant/revocation and device binding have passed the explicit local-chain qualification; complete service/session orchestration remains pending.

Development passkeys are created as new owner-only files (0600) and reused without overwriting them. Loading rejects symlinks, hard links, other owners and group/world-readable files. Passkey contents never appear in CLI output. Unix file permissions are required for this development storage mode.

Native device keys and development passkeys share `agentkeys-core::protected_file`. It validates the opened file before reading or truncating it, refuses special files without blocking, and bounds secret records to 64 KiB. New keys use exclusive creation; explicit updates also reject linked or loosely readable files. The CLI device session consumes `DeviceKey` for custody, addresses and proof signing instead of carrying a second implementation.

Every software-key library call requires a `DevelopmentSigning` context constructed through the same local-profile guard. Agent and application signing commands additionally require a loopback service, refuse HTTP redirects, and recompute the operation hash against the generated profile's EntryPoint and chain ID before opening the key. Wire-to-packed operation conversion and hashing have one owner in `agentkeys-core::erc4337`, shared by broker and client. Seed derivation uses the same protected file reader; special files fail without blocking. These development checks do not attest to hardware custody.

## Contract tooling

`terrier` is the public local-tool entry point. Contract operations are owned by `scripts/terrier_local/contracts.py`; future local management surfaces must call this owner. The dependency revision and archive checksum have one owner in `crates/agentkeys-chain/foundry.lock`. The CLI uses a verified public archive instead of requiring submodule initialization. It builds an isolated generated cache with relative dependency paths, preserving reproducible contract metadata without workstation paths. [Contract development](wiki/contract-development.md) documents the supported commands and remaining local-chain acceptance.

`scripts/terrier_local/chain.py` owns the local Anvil process lifecycle; `local_state.py` owns private state permissions and locking. An owner-only control socket addresses the supervisor's actual child process without saved PID signals. `deployment.py` handles the disposable deployer, version checks and generated profile; the shared Solidity deployment script owns the contract set and constructor wiring. Contract transactions use a fresh encrypted local keystore, never Anvil's default unlocked accounts. The password is stored beside the keystore for unattended development, explicitly outside the production custody model. Generated state, broadcast records and credentials stay outside source/build artifacts. See [local chain](wiki/local-chain.md) for persistence, recovery and the trusted-local-machine boundary.

`agentkeys-cli::local_owner` prepares and verifies actual P-256 owner operations; `terrier_local/owner.py` handles private local state and gas submission. `terrier owner register/grant/revoke` reuses the canonical account derivation, calldata, signing and receipt owners. See [local owner](wiki/local-owner.md) for the supported scope, key persistence and remaining broker/agent integration. Owner registration binds a fresh random development identity; it does not attest to an external identity.

Local owner registration binds an actual actor-owned K10 request-signing key alongside the P-256 passkey. Both remain in protected files under the owner's private state directory. Repeat registration and later owner operations verify that the K10 record still matches the active master and passkey; a missing or substituted key fails without generating a replacement. The older `master_device_key_hash` / `device_key_hash_from_omni` helpers name deterministic passkey-only registry slots, not K10 keys; they remain only for consumers awaiting migration. Early local owners using those slots require a fresh named owner or separate local state, not a silent authority rewrite.

`terrier device identity` generates an actor-owned K10 and the existing `EndpointEnrollment` public schema. `owner bind/unbind` verifies HDKD lineage, proof and current chain binding before signing the canonical atomic registration/grant or revocation/scope-clear batch. The actor key is never read by the owner operation. `agentkeys-protocol::chain_abi` owns strict registry, boolean and epoch decoding shared by native and browser clients; `agentkeys-core::registry` adapts hexadecimal RPC responses and owns enrollment proof verification shared with the broker. Local device/delegate enrollment is headless; automatic container-owned identity generation and delegate session integration remain pending.

`terrier owner login` reuses the browser's `BrokerClient` and protocol-owned passkey request types. The CLI's software assertion encoder reuses its existing WebAuthn signer. Login verifies the local owner account and request-key binding, then obtains a real broker session through on-chain passkey verification. Only the explicit development host writes the session, using the protected atomic file owner; output is a receipt without the bearer. Replay and wrong-passkey denials retain the previous session. Automatic service startup and browser enrollment remain separate work.

Broker capability minting resolves authority coordinates through that same chain-profile owner. The explicit CLI credential qualification runs actual login, broker signing, worker verification and persistent SQLite storage against fresh local contracts. Owner and delegated access, negative authorization cases, grant/device revocation and worker/storage restart are exercised without a fixture issuer. This credential check does not complete delegate-session provisioning, browser signer setup or the container journey.

## Local agent runtime

The broker accepts an injected `SandboxRuntime`; its public composition uses `DockerRuntime`. Agent creation reuses the existing authorized broker routes and create-only credential callback. Docker connects through an explicit local Unix socket, requires the development profile guard, inspects an already-loaded image and creates by immutable image digest with pulling disabled.

Each actor runtime runs as an unprivileged user with a read-only root filesystem, limited CPU/memory/processes, temporary writable home and no host or Docker-socket mounts. Management ports bind only to host loopback. Namespaced device/actor labels are checked before reuse or removal; every device gets a separately labeled bridge network. Required actor identity, exactly one credential and both management bearers are checked before replacement. Network cleanup verifies ownership and refuses networks still in use. Container environment values travel over a pipe, not command arguments or logs; Docker host administrators can still inspect them. This is a local development trust boundary.

Image-status request and response types have one owner in `agentkeys-protocol::console`. Broker and daemon use those types directly; TypeScript clients are generated. Status uses immutable image IDs and generic image availability.

The adapter has deterministic lifecycle and denial tests plus an explicit [real Docker qualification](wiki/docker-qualification.md). That test exercises actual creation, reuse, restart, image identity, loopback HTTP, cross-runtime network denial and scoped removal using a small public fixture image. A reproducible agent image and complete local service/model wiring remain required by #6/#7; the adapter alone is not a runnable local release.

## Local model capabilities

`agentkeys-core::models::ModelClient` owns the HTTP transport used by the gate's model client and the headless capability probe. It has no provider discovery or fallback, disables proxy inheritance and redirects, and bounds each request. `presets/local-models.json` owns the qualified runtime/model recipe; the CLI reads its compiled copy. `terrier models config/probe` calls these owners without starting or downloading a model implicitly.

The [local model guide](wiki/local-models.md) distinguishes fast deterministic tests from actual chat, streaming, tool execution and embedding-backed recall. Its macOS qualifier runs the model server and client with outbound networking denied and reports exact artifact/hardware identities. The optional `--gate` qualification exercises the same capabilities through the authenticated relay and verifies usage accounting. This component qualification does not complete persistent memory or the full agent journey.

The relay reads explicit configuration once. Its default endpoint and chat model come from the local recipe; upstream credentials are optional and never discovered from host credential directories. Caller authentication remains mandatory. Optional decision endpoints require explicit configuration. `agentkeys-gate::speech::SpeechBackend` is the injected speech/voice boundary; the public binary has no speech adapter and returns 503 for authenticated audio requests. An embedding application can supply an adapter through `GateConfig`, keeping adapter credentials outside shared code. These are source-level Rust interfaces: adapters compile and test against a pinned source revision, rather than a dynamic plugin ABI. Changes to the shared interface require downstream recompilation and contract tests. Remaining provider integrations in broker, storage and other clients remain tracked by #3/#7.

Relay-key mutations serialize behind one write lock and persist before becoming available to callers. `agentkeys-core::protected_file::replace_atomic` owns private temporary creation, descriptor-relative replacement and file/directory synchronization. A persistence error retains the last committed in-memory records but latches caller authentication and readiness unavailable until recovery/restart; it never reports a failed revocation as usable service. One relay process owns each keys file. The local service lifecycle must preserve that ownership.

Independent capability verification has one implementation in `agentkeys-core::capability_verify`, re-exported by the worker library. Each worker still invokes it at its own request boundary, including current on-chain device binding, scope and epoch checks. Actor proof of possession is mandatory; there is no environment switch to admit broker-only capabilities. Clients without an enrolled signing key are denied until enrollment is completed. This does not complete local storage or owner-session integration.

Chain authority decoding rejects malformed lengths, noncanonical integer padding and boolean values other than zero or one. Broker and worker checks project the same decoded registry record; they never truncate malformed values or treat parse errors as unrevoked devices. Registered state derives from the decoded registration timestamp. Unknown or revoked entries remain subject to each caller’s explicit authorization policy.

## Local object storage

`agentkeys-local-store` owns the local SQLite object service. `agentkeys-protocol::object_store` owns its wire schema and capability-to-key/action rules. The service verifies signatures, actor proofs and current chain authority independently before any object operation; databases are bound to a single data class and have private file permissions. Expected-revision updates commit atomically. Database identity/version checks reject unrelated files.

The [storage qualification](wiki/local-storage.md) covers real local contracts and a separate service process, with a deliberately untrusted test issuer. `agentkeys-core::object_store` owns the injected `ObjectStore` interface, bounded HTTP transport and native object client. `capability_verify::AuthorityConfig` resolves authority coordinates from one chain profile. The credential worker now uses that object client for encrypted storage, fetch, paginated listing and owner-only teardown; it has no cloud credential or ambient storage fallback. Its explicit local configuration guards the profile, loopback endpoints and private development encryption key. Both the worker and storage service independently check authority.

Credential request/response schemas live once in `agentkeys-protocol`; request types accept either an opaque client-forwarded capability or the worker's canonical signed type. The legacy response name `s3_key` denotes an object key and does not select a storage provider. The protocol also owns missing-object classification: HTTP 404 plus `object_not_found`, with `s3_no_such_key` retained as an explicit compatibility alias while other workers migrate. An unknown 404 is an error, never permission to overwrite data. The worker's controlled-chain HTTP/SQLite integration tests supplement the real-chain storage qualifier. Other worker/client migration and real broker session/mint integration remain open; the local adapter replaces the previous product storage path as each consumer migrates.

Configuration uses the same local worker startup, guarded configuration, capability checks, encryption handling and object client as credentials. Each request is verified independently at the worker and storage service; configuration additionally requires owner-self authority even when an agent has a valid service grant. Config writes use storage-atomic expected revisions, and teardown paginates and reports deletion failures. Both workers accept client-encrypted v3 envelopes without a worker encryption key; plaintext development writes require an explicit protected `--development-kek-file`. Configuration wire bodies and generic teardown schemas have one owner in `agentkeys-protocol`. Shared fixtures exercise both workers rather than duplicating chain simulators or process supervisors.

Memory uses those same worker owners and a distinct local database/key. Own-memory capabilities address the actor's namespace, canonical reads address the owner's single knowledge object, and proposal appends are create-only under the caller's inbox subdirectory. Expected plaintext hashes are checked against a read revision, then committed with atomic storage compare-and-swap. Inbox listing paginates and surfaces unreadable records as errors. Owner inbox deletion has its own `CapMintOp::MemoryInboxDelete` route and signed teardown operation; storage confines that capability to inbox objects. A fetch capability cannot delete, and an inbox-delete capability cannot delete ordinary memory. Memory and inbox wire schemas are shared with native/browser clients.

Channel messaging uses the same scoped object client, local startup, CORS and independent verification owners. Its extra state consists of bounded channel settings, an optional explicit wake client and transient owner/feed-scoped notifications. Publish permits create-only events and attachments; subscribe permits reads and listings. Encryption binds each record to its exact object key, preventing ciphertext replay under a new event or attachment name. Owner teardown is a distinct mint operation limited to one signed channel's events and attachments. Poll cursors read one page; tail reads follow all pages. Registered waiters retain notifications arriving during the initial read, and each subsequent storage request checks current authority. Application wake requests share one protocol schema with the broker and use a protected token file plus an explicit local URL. Remaining product-client transport, broker session enrollment and complete service orchestration are still pending.

The default source license is Apache-2.0. Existing file-level and package exceptions are recorded in [licensing](wiki/licensing.md) and the root NOTICE; runtime artifacts and dependencies retain their own terms. This license inventory is separate from the remaining release qualification.

`agentkeys-web-core::data::DataClient`, the native `BackendClient` and daemon UI send signed capabilities directly to their storage workers, without exchanging identity tokens for storage credentials or forwarding session bearers to workers. Browser client-side encryption and its explicit key-derivation signer remain separate from storage transport; signer refusals prevent writes. The native client takes four endpoint coordinates and requires a configured device proof before minting. CLI credential and memory commands load existing protected device keys, derive their hashes and share the protocol service-name builders. Checkpoint and audit clients no longer carry cloud storage provider settings. CLI-run tests exercise both client libraries against actual workers and SQLite, including missing-proof and revoked-grant denials. These tests do not cover interactive browser sessions or complete local signer orchestration; broker enrollment still requires migration.

Daemon UI worker contexts receive the explicitly loaded device key through their state constructor. Storage and channel capability requests derive proof identity from that key, without consulting environment variables during a request. Channel cache entries include the signing-key hash and require a currently configured key before lookup. Display and legacy registration metadata are not a substitute for request-signing authority; their enrollment migration remains open.

The daemon shares one storage context for memory, configuration and credentials. Worker URLs are explicit startup inputs, including `--cred-url`; no storage roles or region are required. Configuration and UI credential writes use client-encrypted v3 envelopes and require a confirmed worker receipt. UI credential encryption always requires the owner's key-derivation signer; local signer orchestration and delegated decryption of these envelopes remain unfinished. The CLI's explicitly development-only worker-encrypted credential path is separate and retains its qualified delegated-read behavior.
