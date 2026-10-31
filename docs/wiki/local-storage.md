The local object service is a qualified storage component. The credential and configuration workers use it for encrypted data operations. Integration with the other workers, product clients, broker sessions and complete local application remains open in [#5](https://github.com/litentry/agent-terrier/issues/5).

## Ownership and boundaries

`agentkeys-local-store` runs a small authenticated HTTP service with a separate SQLite database for each data class. The database records its application, schema and data-class identity; an unrelated database or a database belonging to another class is rejected. Database directories must be private, and files must be owned by the current user with no symbolic or hard links. Host administrators remain trusted in this local development environment.

Every object request carries a broker signature and a fresh actor proof. Before reading or changing objects, the service independently checks the current chain device binding, grant and epoch using `agentkeys-core::capability_verify`. `agentkeys-protocol::object_store` owns the request schema and key/action restrictions. Neither a caller-supplied key nor a broker signature alone grants access to another actor or data class.

Objects are opaque bytes. Product workers remain responsible for envelope encryption; the storage component does not turn arbitrary input into ciphertext. It never receives SQL or filesystem paths from callers. Object sizes and list pages are bounded; updates support an atomic expected-revision condition. Inbox append is create-only, and channel publish does not grant subscribe or delete permission.

## Backend choice

The experiment uses the already-pinned `rusqlite` dependency with bundled SQLite, avoiding another local infrastructure service. SQLite documents local application storage and application-specific servers as [intended uses](https://sqlite.org/whentouse.html). Its deliverable library is [public domain](https://sqlite.org/copyright.html); the pinned `rusqlite` 0.31.0 package declares MIT in its [package manifest](https://docs.rs/crate/rusqlite/0.31.0/source/Cargo.toml.orig). Keep dependency updates and license inventory in the public repository. This qualification establishes local behavior, not production scale or cloud-policy equivalence.

## Fast checks

Run locally from the public repository root:

```sh
cargo test -p agentkeys-local-store
cargo test -p agentkeys-protocol object_store
cargo test -p agentkeys-core object_store
cargo test -p agentkeys-worker-creds --test local_storage
```

These tests use controlled chain responses and real signatures. They pair valid access with wrong-actor, wrong-class, wrong-operation, missing/forged proof, expiry, binding, scope, epoch and revocation denials. Denials assert the exact error, no object-service storage operation and unchanged stored data. Additional tests cover concurrent updates, append-only behavior, reopen persistence and unsafe file rejection.

## Credential worker integration

The credential worker invokes `agentkeys-core::object_store::ObjectClient` through the `ObjectStore` interface. The HTTP adapter sends the signed capability on every request, has no ambient cloud credentials, rejects redirects and bounds responses. It verifies returned content revisions and validates list scope, ordering and cursor progress. The worker independently verifies authority before contacting storage; the object service repeats verification before using its database.

The worker binary requires `--development`, a generated `--profile`, a broker public-key file and an explicit loopback `--storage-url`. For plaintext development writes, pass `--development-kek-file`; without it, writes must contain a client-encrypted v3 envelope. That encryption key must be freshly generated, 32 bytes encoded as hex, and stored in an owner-only file. It is an explicitly development-only software encryption key. Symlinks, hard links and readable-by-others key files are refused by the shared protected-file reader. The binary listens only on loopback. Run `cargo run -p agentkeys-worker-creds -- --help` locally from the public checkout for its flags. Automatic creation and supervision of these component inputs remains part of the local lifecycle work.

The encrypted v2 development flow and client-encrypted v3 envelope flow keep their existing wire format. The response field `s3_key` is a compatibility name for an object key; the credential worker no longer uses S3. Owner-only listing follows pagination, and teardown propagates storage failures rather than reporting partial deletion as success. The existing audit emitter remains in use; audit-service qualification is separate from storage qualification.

The worker integration test runs the actual worker router, cryptography, HTTP adapter and SQLite service with controlled chain responses. It proves encrypted store/read, delegated fetch, owner listing/deletion, rejection before storage access, independent storage denial and deletion-error reporting. It does not establish real broker enrollment or a complete product journey. Other workers still use their previous storage path until migrated.

After building the public CLI and preparing contract dependencies, run `python3 scripts/tests/qualify_local_credentials.py` locally from the public checkout for the explicit real-contract credential qualification. It uses the actual credential-worker executable and newly enrolled owner/delegate request keys, verifies encrypted storage and readback, restarts the worker, and applies real scope and device revocations. Owner access remains available after the delegate is revoked. The issuer remains a deliberately untrusted fixture; this does not claim real broker login or mint acceptance.

## Explicit real-chain qualification

### Configuration worker

Configuration and credential workers share the same local startup options: `--development`, `--profile`, `--broker-public-key`, `--storage-url`, optional `--browser-origins`, and loopback `--listen`. Use a separate storage service/database bound to the `config` data class. The configuration worker has no cloud storage credentials or fallback.

Without `--development-kek-file`, the workers accept only client-encrypted v3 writes and return those envelopes unchanged. Supplying a protected file containing a fresh random 32-byte hex key enables development-only plaintext writes encrypted by the worker. Preserve that key with the private runtime state to read those records after restart. Existing encrypted records are never silently re-keyed. This explicit option replaces the configuration worker's former environment-based encryption switches.

Configuration is owner-only for put, get and teardown. A valid delegate grant does not confer access. Reads return an opaque revision; send that exact value as `expected_revision` to update the value you read, or an empty string for create-only. A competing update returns HTTP 409 `stale_base`; reload before saving. Teardown reports storage failures instead of counting failed deletes as success.

Run locally from the public checkout:

```bash
cargo test -p agentkeys-worker-creds --test local_storage
python3 scripts/tests/qualify_local_config.py
```

The shared Rust integration target belongs to `agentkeys-worker-creds` and covers both workers. It checks real SQLite writes, owner-only denial before storage access, independent storage denial, concurrent revision conflicts, ciphertext-only storage, v3 passthrough without a worker key, and deletion failures. The explicit qualifier runs the configuration executable against real local contracts, then restarts it and revokes the delegate's grant and device while retaining owner access. Its issuer is a fixture; broker login/mint and the complete application remain separate acceptance work.

### Object service

Install the pinned Rust toolchain and Foundry, prepare the contract cache with `terrier contracts setup`, and build the CLI. Run locally from the public repository root:

```sh
cargo build -p agentkeys-cli
python3 scripts/tests/qualify_local_storage.py
```

The qualifier creates disposable identities, deploys the real contracts, enrolls an actor and launches the object-service binary. It checks authorized write/read, wrong actor/class/proof/expiry, broker-signed but chain-unauthorized requests, persistence after killing and restarting the service, and denial after actual scope and device revocations. Generated keys, profiles and databases stay in private temporary directories and are removed by the fixture.

The capability issuer is a test fixture, deliberately able to sign unauthorized requests. This proves independent storage enforcement. It does not qualify broker login or capability minting; those must pass through the real broker when the workers and clients are connected. The latest local run completed this storage qualification in 27.049 seconds on macOS, including the affected test-binary rebuild. An earlier run with warmed binaries took 12.262 seconds. A cold build or first download adds time.
