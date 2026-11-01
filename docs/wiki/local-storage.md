The local storage implementation serves credentials, configuration, memory and channel messages through independently verified capabilities. The real broker-login/credential journey and each worker's real-contract qualification have separate evidence. Browser enrollment, client-encrypted delegated credential decryption and full application acceptance remain release work; they are not implied by storage qualification.

## Run locally

Prepare the public binaries and contracts using [local services](./local-services.md), then use the [local manager](./local-manager.md) to start the backend. It creates protected keys, starts four workers and gives each data class its own persistent object database. Every listener is loopback-only. State lives outside the checkout; preserve its keys with its databases.

Local, in the prepared public checkout and the same state directory:

```sh
./terrier stack start
./terrier owner register --name developer
./terrier owner login --name developer \
  --broker-url "$(./terrier services status | jq -r .services.broker.url)"
printf %s 'local-development-example' | ./terrier cred store example --name developer --secret-stdin
./terrier cred fetch example --name developer
```

The fetch command deliberately prints the decrypted credential. The protected session file and actor request key are loaded by the native client; no bearer or key value is passed in command arguments. Invalid sessions, missing original keys and unsafe file permissions fail. [Local services](./local-services.md) describes restart, configuration and recovery; [local owner](./local-owner.md) describes development-only signing.

## Canonical owners

| Responsibility | Source owner |
|---|---|
| Capability fields, object request schema, allowed key/action combinations | `agentkeys-protocol::capability` and `agentkeys-protocol::object_store` |
| Pure signature, device-binding, grant and epoch verification | `agentkeys-core::capability_verify` |
| Native bounded HTTP object client | `agentkeys-core::object_store::ObjectClient` |
| SQLite identity, persistence and atomic object operations | `agentkeys-local-store` |
| Worker startup, protected development keys and shared verification adapter | `agentkeys-worker-creds` shared modules |
| Data-class behavior and encryption | Credential, configuration, memory and channel worker crates |
| Native and browser product calls | `agentkeys-backend-client` and `agentkeys-web-core` |
| Local process lifecycle | `scripts/terrier_local/services.py` |

The broker, worker and object service independently enforce authority even though they share types and pure verification helpers. A valid broker signature alone is insufficient. Storage also requires a fresh actor proof, current chain binding, permitted service and matching epoch. It confines objects to the signed actor, service, operation and data class before reading or changing bytes. Host administrators remain trusted in this development environment.

Each SQLite database records its application, schema and data class. Unrelated databases, wrong-class databases, links, unsafe ownership and permissive file modes are rejected. Callers never supply SQL or filesystem paths. Object size and list pages are bounded; conditional updates use an atomic expected revision. Workers own encryption; the object service stores opaque bytes.

## Data-class behavior

| Class | Authorized behavior | Additional restrictions |
|---|---|---|
| Credentials | Owner store/list/delete; granted delegate fetch | Delegated writes fail; deletion failures are reported |
| Configuration | Owner put/get/delete | A delegate grant never permits access; stale revisions return `409 stale_base` |
| Memory | Actor-owned memory, distinct canonical owner-memory read, append-only proposals | Canonical reads cannot address checkpoints; proposals cannot overwrite; owner inbox deletion cannot delete ordinary memory |
| Channel | Signed-feed publish or subscribe; owner feed teardown | Publish cannot read/overwrite/delete; subscribe cannot publish; teardown is limited to one feed and its attachments |

Workers start with an explicit local profile, broker public key and loopback storage URL. The service launcher supplies these through the same public binary options. `--development-kek-file` names a fresh protected 32-byte hex key. Credential and configuration workers can instead accept client-encrypted v3 envelopes without a worker key. Memory and channel workers require their separate development key. Missing original keys are never silently regenerated over existing state.

The credential/configuration v3 path keeps encryption in the client and requires its explicit key-derivation signer. Daemon/browser owner encryption is separate from the CLI's qualified worker-encrypted development path. Delegated v3 decryption and interactive browser signer enrollment remain unfinished. The memory worker encrypts its development records; client-encrypted v3 memory is not implemented. Existing envelopes are never silently re-keyed or switched between modes.

The retained wire field `s3_key` is a compatibility name for an object key; these workers do not use cloud storage credentials. Shared native/browser clients send signed capabilities directly to workers. HTTP adapters disable inherited proxies and redirects, bound responses, verify content revisions and validate pagination scope/progress. The audit emitter is a separate interface; audit-service acceptance is outside this storage qualification.

## Memory and channels

The [local channel CLI](./local-channels.md) publishes text and polls messages through the same client as the website, using the protected owner session.

The signed service owns the memory namespace; an unsigned request hint cannot change it. Native memory/inbox commands load the actor's existing `--device-key-file`. Canonical reads may instead use an explicit delegation file, never both. Protocol helpers own the `knowledge:<namespace>` service spelling. Missing keys fail without replacement.

Memory updates compare the expected plaintext hash with a read revision before atomic storage update. Proposals stamp provenance from the signed actor/service and reject an existing object with `409 object_revision_conflict`. Owner inbox listing follows pagination and surfaces unreadable records. Deletion requires the distinct signed `MemoryInboxDelete` operation and is confined to inbox objects; a fetch token cannot delete.

Channel encryption binds each record to its exact object key, preventing replay under a new event or attachment name. Poll cursors read one page; tail requests follow all pages. Notifications are scoped to owner/feed and retained across the initial read race. Storage checks current authority again after a long-poll wake, so revoked readers receive no messages.

Channel startup can lower limits with `--max-poll-seconds`, `--inline-max-bytes` and `--blob-max-bytes`; the source defaults are 25 seconds, 1 MiB and 16 MiB. Optional wake delivery requires an explicit local `--wake-url` and protected `--wake-token-file`. Without them messaging works but auto-wake is disabled. Wake failure is reported after storing the message. Complete agent channel conversation remains a separate application check.

## Test lanes and evidence

Local, from the public checkout, for fast object and worker/client checks:

```sh
./terrier test focused --component storage
cargo test --offline -p agentkeys-worker-creds --test local_storage
```

After preparing the CLI, service binaries and cached contract inputs, local in that checkout:

```sh
./terrier test qualification --component storage \
  --report "${AGENT_TERRIER_TEST_REPORT:?Choose a new report path outside the checkout}"
```

This explicit lane reuses the existing scenarios; ordinary PR lanes do not invoke it. It runs object-store checks, shared worker/native/browser-library tests, then real-chain object, credential, configuration, memory, channel, broker-storage and protected CLI qualifiers. Each real-worker qualifier executes active access, actual grant revocation and actual device revocation. The selected ignored Rust test must actually execute; missing, empty or skipped-only suites cannot pass. Reports contain test counts and timings; raw logs remain private.

| Boundary tested | Positive control | Negative evidence |
|---|---|---|
| Object service with real contracts | Write/read and reopen persisted bytes | Wrong actor/key/class/proof, expiry, forged binding and ungranted service return the exact error; database rows/revisions remain unchanged |
| Each real worker | Owner data persists across worker restart; permitted delegate reads succeed | Missing proof, wrong actor/class/service, revoked grant/device fail with exact status/reason, no plaintext and unchanged objects; configuration remains owner-only |
| Shared worker/client HTTP tests | Real SQLite, encryption and native/browser library requests | Rejected worker authority forwards no storage operation; storage independently rejects unauthorized requests; competing writes, append-only rules and cross-feed deletion are checked |
| Real broker and protected credential CLI | Actual passkey login, minting, store/read, restart and delegated read | Invalid/expired/mismatched sessions, wrong or missing keys, foreign owners, delegated writes and revoked authority fail without unauthorized changes |

The object/worker qualifiers deliberately use a test issuer that can sign an unauthorized capability. That is the positive control for independent chain enforcement after broker compromise; it is not a replacement for broker login. The separate broker qualifier uses actual login and capability minting. Its delegated read uses the owner's session with the enrolled delegate key; automatic container use and browser interaction are different acceptance surfaces.

See the [recorded qualification report](../../e2e/fixtures/storage-qualification/macos-arm64-2026-11-01.json) for the exact measured run. Fixture setup/build/execution/cleanup is included in each scenario's elapsed time; the report does not pretend to split those internal phases. No production scale, hardware custody or hosted-policy equivalence is claimed.

## Backend maintenance and licensing

The component uses the pinned `rusqlite` dependency with bundled SQLite. SQLite documents local application storage and application-specific servers as [intended uses](https://sqlite.org/whentouse.html), and distributes its library as [public domain](https://sqlite.org/copyright.html). The pinned `rusqlite` package declares MIT in its [manifest](https://docs.rs/crate/rusqlite/0.31.0/source/Cargo.toml.orig). Maintain dependency updates and this license inventory in the public repository. API compatibility alone is not the qualification evidence: the executable boundary and persistence checks above are.
