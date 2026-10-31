The local object service is a qualified storage component. Integration with the product workers, broker sessions and complete local application remains open in [#5](https://github.com/litentry/agent-terrier/issues/5).

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
```

These tests use controlled chain responses and real signatures. They pair valid access with wrong-actor, wrong-class, wrong-operation, missing/forged proof, expiry, binding, scope, epoch and revocation denials. Denials assert the exact error, no object-service storage operation and unchanged stored data. Additional tests cover concurrent updates, append-only behavior, reopen persistence and unsafe file rejection.

## Explicit real-chain qualification

Install the pinned Rust toolchain and Foundry, prepare the contract cache with `terrier contracts setup`, and build the CLI. Run locally from the public repository root:

```sh
cargo build -p agentkeys-cli
python3 scripts/tests/qualify_local_storage.py
```

The qualifier creates disposable identities, deploys the real contracts, enrolls an actor and launches the object-service binary. It checks authorized write/read, wrong actor/class/proof/expiry, broker-signed but chain-unauthorized requests, persistence after killing and restarting the service, and denial after actual scope and device revocations. Generated keys, profiles and databases stay in private temporary directories and are removed by the fixture.

The capability issuer is a test fixture, deliberately able to sign unauthorized requests. This proves independent storage enforcement. It does not qualify broker login or capability minting; those must pass through the real broker when the workers and clients are connected. The latest local run completed this storage qualification in 12.262 seconds on macOS with a warm build cache. A cold build or first download adds time.
