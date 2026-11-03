# Architecture and ownership

This document owns the public component inventory and trust boundaries. Start with the [quickstart](wiki/quickstart.md); [qualification and limits](wiki/qualification.md) records exact tested revisions, platforms and remaining release gates. Behavior belongs in the guides linked here rather than a second implementation or a chronological migration log.

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
| Headless product operations | `crates/agentkeys-cli`, `crates/agentkeys-daemon` | Developers, tests and the local manager |
| Local stack composition and terminal manager | `scripts/terrier_local/stack.py` composes existing controllers; `manager.py` dispatches the canonical CLI | Developers and CLI qualification |
| Local service supervision | `scripts/terrier_local/services.py` | `terrier services`, local manager and explicit qualification |
| Development signing | `crates/agentkeys-mock-server` signer implementation and `agentkeys-local-signer` entry point | Local services and authenticated native/browser clients |
| UI tokens and components | `design-system` | `apps/parent-control`, `apps/device-display` |
| Agent runtime plugins | `packages/agentkeys-dsh` | Agent environments |
| Local agent composition and image | `agentkeys-runtime::managed_agent` configuration and `agent-terrier-runtime` process owner; `packages/agent-terrier-runtime` agent loop and image | Local component development and image qualification |
| Runtime lifecycle and Docker ownership | `crates/agentkeys-runtime` | Broker and local runtime controllers |
| Persistent knowledge retrieval | Canonical memory worker, `agentkeys-daemon::knowledge_recall`, shared model transport and action contract | Generic agent action plugin |
| Protocol examples | `e2e/fixtures` | Shared drift and conformance checks |


The public tree owns shared product code and local development adapters. It excludes firmware, hardware build/flash assets, full operator applications, private deployment configuration and inherited operational documentation. The device-core crate supplies reusable protocol and cryptographic primitives without a firmware toolchain. The default license is Apache-2.0 with the existing [documented exceptions](wiki/licensing.md).

## Trust boundaries

1. The chain owns identity and grants. Local records and broker caches cannot grant authority.
2. Broker, worker and object service independently verify the relevant actor, proof, service, operation and current chain binding.
3. Owner signatures authorize account changes. A development submitter pays for the outer transaction; it cannot act as the owner.
4. Keys stay with their actor or explicitly configured development signer. The broker stores public runtime reconstruction metadata, never delegate private keys; key-bearing legacy databases are refused.
5. Readable personal data stays off-chain. Each data class has separate object storage and a signed scope.
6. Missing configuration, proof, current authority or original keys causes an explicit failure. There is no ambient provider discovery, silent credential fallback or local allow-all mode.
7. Wire schemas and pure policy have one owner; sharing them does not remove independent enforcement.

Local software keys and services trust the host administrator. Protected files are development custody, not hardware protection. `agentkeys-core::protected_file` checks the opened file, ownership, permissions, links and size; creation is exclusive and updates are atomic. Runtime and test environments are explicitly constructed. The public scanner supplements manual source/artifact review and cannot certify arbitrary encoded data or retained hosted history.

## Chain configuration

The only built-in profile is `anvil`, with no deployed accounts, contract addresses or reusable keys. Setup generates fresh development identities and a runtime profile outside the source tree. Profile selection is explicit profile file, CLI chain, environment chain, then the built-in default; an invalid explicit profile fails. Profiles reject embedded deploy keys and seed phrases.

Software signing requires the shared `DevelopmentSigning` guard: the explicit local development flag, correct development chain kind/ID and loopback RPC. Signing clients also refuse service redirects and recompute the operation hash against the selected EntryPoint and chain ID. K11 parser stubs require a separate explicit flag and do not establish authorization acceptance. See [local chain](wiki/local-chain.md) and [local owner](wiki/local-owner.md).

Owner operations reuse canonical account derivation, calldata, P-256 signatures and ERC-4337 conversion. Owners have an actual K10 request-signing key alongside their development passkey. Device enrollment verifies the protocol-owned public proof, HDKD lineage and current binding before signing registration or revocation. Older deterministic passkey-only registry slots are not K10 identities; they require a new development owner rather than a silent authority rewrite.

`terrier owner login` reuses the browser `BrokerClient` and shared WebAuthn shapes. Its protected session is bound to owner, broker and request key. `terrier browser approve` validates the shared public approval, exact origin, owner/account/nonce/expiry and both possession proofs, then signs the canonical batch. Approval creates no browser session: the browser must subsequently authenticate using its own PRF-capable passkey. See [browser approval](wiki/local-browser.md).

## Contract tooling

`terrier_local/contracts.py` owns dependency preparation, compiler selection and contract build/test commands. The compiler pin and `foundry.lock` own public input identities; a verified archive supplies dependencies without submodule setup. Generated build caches use relative dependency paths. The Solidity deployment script owns the contract set, and `deployment.py` owns generated profiles and version checks. A mismatch never silently redeploys over state. See [contract development](wiki/contract-development.md).

`chain.py` owns Anvil; `local_state.py` owns private state and the operation lock. Supervisors address their actual children through owned control sockets, not saved PID authority. Local contract transactions use fresh encrypted keystores rather than Anvil's default unlocked accounts. The unattended development password is stored beside its keystore; this is outside the production custody model.

`stack.py` composes these owners with `services.py`. The terminal manager dispatches the same CLI rather than implementing a second supervisor, store or resolver. Services retain original keys, exact loopback addresses, website origin and selected image/model configuration across restart. Failed startup preserves unrelated listeners and existing data. Confirmed stop precedes chain shutdown. Explicit reset requires the exact selected state path and removes only verified owned resources; downloaded models and shared images remain. See [local management](wiki/local-manager.md) and [services](wiki/local-services.md).

## Local agent runtime

`agentkeys-runtime` owns `SandboxRuntime`, `DockerRuntime`, lifecycle serialization, image identity and managed process supervision. Broker creation, reconnect, health, restart and removal use this owner. An explicit Unix socket and preloaded immutable image are required; startup does not pull an image. Namespaced device/actor labels and mount ownership are checked before reuse or removal.

Managed agents run unprivileged with no container networking, no published ports, a read-only root filesystem, bounded CPU/memory/processes and one private state volume. No host filesystem or Docker socket is mounted into the agent. The approved [development disk policy](wiki/docker-qualification.md#development-disk-policy) refuses low space and stops an over-limit agent while retaining its volume; it is not a hard filesystem quota.

`RuntimeBootstrap` owns the bounded, versioned stdin frame. It carries the local chain profile and allowlisted fields after transport readiness, not Docker environment metadata. The controller keeps the stream open for the lifetime of the daemon and agent loop; EOF, signals, child failure and partial startup stop both. An exclusive state lock rejects a second writer. Bootstrap credentials are not persisted; the protocol-owned volume layout retains conversations.

`service-transport.mjs` owns both ends of HTTP/2 forwarding over the Docker execution stream. One service map translates host loopback services to container loopback listeners. Targets and path prefixes come from the trusted controller, never an agent-supplied URL. Redirects, escaped paths and oversized traffic fail. Transport does not mint authority; the receiving service still checks application proofs. The same map is used for creation and restart. See [image build and process contract](wiki/local-agent-image.md) and [Docker qualification](wiki/docker-qualification.md).

The protected agent CLI and console call the existing authenticated broker routes. The CLI reuses owner/session validation and build/sign/submit owners, journals unsigned operations before broadcast and recovers through authenticated receipt lookup without signing again. Archive reports chain confirmation separately from relay/runtime cleanup and retains application data. Incomplete cleanup remains retryable. Browser pending records remain in memory; confirmation refreshes the broker receipt before metadata retry so a restarted broker can reconstruct the runtime. See [agent operations](wiki/local-agents.md).

## Local model capabilities

`presets/local-models.json` owns the runner/model/dimension recipe. `agentkeys-protocol::model_config`, `model_runtime` and `model_relay` own shared settings and wire shapes; generated TypeScript consumers use those definitions. `ModelClient` owns the bounded native local HTTP transport, with no proxy inheritance, redirects or hosted fallback.

The service supervisor may own the prepared Ollama runner. Version, model digests, configuration and endpoint are checked before startup; existing foreign listeners are not adopted. Downloads and upgrades are explicit. A protected admin-token file controls the authenticated relay; caller credentials persist before success and are revoked by the same owner. Readiness checks inventory while `models probe` separately proves real inference. See [models](wiki/local-models.md).

Persistent knowledge reuses canonical memory documents, `DataClient`, the shared embedding transport and the daemon's `recall_knowledge` action. The generic agent action plugin consumes the advertised protocol action; there is no second document store or persistent vector index. Retrieval checks its exact namespace grant, rechecks authority/source equality and returns bounded results without changing canonical documents. Conversation checkpoints survive restart. Optional OpenViking configuration is separate and is not required for this qualified path. See [knowledge](wiki/local-knowledge.md).

Speech uses the injectable `SpeechBackend`; the public executable has no speech adapter. Development email uses `EmailSender` with the protected local outbox. Downstream adapters compile against pinned interfaces and own any external deployment integration; the shared core has no cloud credential-exchange routes. See [adapter contracts and compatibility](wiki/adapter-contracts.md).

## Local object storage

`agentkeys-local-store` owns SQLite object persistence, one database per data class. The broker mints signed capabilities; each worker and the store independently verify current authority and proof before access. Object scope includes actor, service, operation and data class. Create-only writes and compare-and-swap preserve atomicity. `agentkeys-core::object_store` and transport-free protocol types own the common client contract.

Credential, memory, configuration and channel workers share pure verification/startup helpers while enforcing authorization independently. Clients send capabilities directly to workers, without exchanging identity tokens for storage credentials. Native `BackendClient`, browser `DataClient`, the daemon and CLI consume shared types and service-name builders. Data access contexts require a real configured device signing key; display/legacy metadata cannot substitute for proof.

Owner credential CLI reads reuse browser decryption for v3 and legacy records. Browser/daemon v3 writes use the explicit key-derivation signer. Delegated decryption of owner-encrypted v3 credentials is unavailable; a read grant does not provide the owner's encryption key. The development CLI's worker-encrypted write path has separately qualified delegated reads. Memory records use worker encryption, not client-encrypted v3 memory. Existing records are never silently re-keyed. See [storage](wiki/local-storage.md).

Channel records bind encrypted content to object keys. Publish is create-only; subscribe reads bounded pages; owner teardown is separately scoped. Wake requires an explicit local URL and protected shared token file; it is not automatically configured. The classifier independently uses the shared worker authority pipeline and creates no durable store. Individual capability-ID revocation is unavailable: revoke chain scope/device authority or let the capability expire. See [channels](wiki/local-channels.md) and [services](wiki/local-services.md).

## Browser and generated contracts

The console and display share `design-system`, a root npm workspace/lockfile and one WASM build owner. Card and web API types come from `agentkeys-protocol` and generated bindings; do not add handwritten copies. Runtime backend configuration has one validated owner. Managed bridge calls require the broker/session/binding and never fall back to an anonymous direct proxy. Worker/signer CORS permits only the selected exact website origin and does not bypass authorization.

An optional unconfigured audit archive is represented as null; append/fetch fails explicitly before transport. On-chain audit reads retain their protected route. Browser authentication is in memory, and pending records are lost on reload/sign-out. Physical passkeys, display enrollment and auxiliary services have separate acceptance limits. See [website behavior](wiki/local-website.md) and the current [qualification scope](wiki/qualification.md).

## Migration gates

Each cross-component boundary has one owner listed above and in [adapter contracts](wiki/adapter-contracts.md). Change schemas and generated consumers together. Pin source, lockfiles, image and model recipe as one tested combination; package versions alone are insufficient. Preserve original keys and refuse unsupported state instead of recreating it.

The public [test lanes](wiki/test-lanes.md) reuse product CLI/client owners and isolated scenario helpers. Core negatives and affected tests run without models or a browser. Explicit nightly and weekly checks cover services, Docker, real models and bounded browser behavior. A missing, ignored-only or empty suite is not a pass. Security mutation checks export an exact reviewed revision into disposable state and reuse the existing assertions.

`.public-source.json` and `check-public.py` enforce the public surface, secret/context checks and narrowly hashed synthetic exceptions. Source, build context, generated web/WASM assets, image layers and metadata need review before publication. New documentation is authored in `docs/wiki`; generated CLI reference and revision-pinned wiki rendering have one source. Current acceptance evidence and unresolved hosted-history review are recorded in [qualification and limits](wiki/qualification.md), rather than inferred from a successful component test.
