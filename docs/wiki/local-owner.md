The local owner CLI registers a real P-256 smart account and signs scope grants and revocations against the deployed contracts. It requires the [owned local chain](./local-chain.md) and a built public CLI. No browser or company account is needed.

This implements owner registration and scope mutation. Broker login, agent identity binding, storage access and the complete agent journey remain under development. A scope grant alone does not create an agent or bypass its independent device authorization.

## Register an owner

Local, from the public checkout after starting the chain and deploying its contracts:

```bash
cargo build -p agentkeys-cli
./terrier owner register --name developer
```

The command generates a fresh operator identity and software passkey under the private local state directory. It deploys the counterfactual P256Account through EntryPoint and registers its master device in one passkey-signed operation. The local deployer only pays for submitting that operation; the account's P-256 signature authorizes its contents. Anvil supplies disposable development funds to the account.

The result includes the operator identity, account and verified operation/transaction hashes. Repeating the command verifies the same on-chain binding without another transaction. The same identity survives a normal chain stop/start. A different contract deployment or a missing original passkey is rejected; no replacement key silently takes over an existing owner.

## Grant and revoke scope

Local, from the same checkout and shell, set the actor identity you intend to authorize:

```bash
export ACTOR_OMNI="${ACTOR_OMNI:?Set the actor identity to authorize}"
./terrier owner grant --name developer --actor-omni "${ACTOR_OMNI}" \
  --service knowledge:example --read-only
./terrier owner revoke --name developer --actor-omni "${ACTOR_OMNI}"
```

`--service` is repeatable. Grant replaces the actor's complete service set for this owner. The scope has no monetary caps; this local command does not expose payment-policy configuration. Revoking an absent scope fails with the actual on-chain operation result. A mined outer transaction is never sufficient evidence of success.

## Keys, state and recovery

Each named owner has `owners/<name>/identity.json` and `passkey.pem` beneath the configured local state directory, outside the source tree. Directories are 0700 and files are 0600. The existing passkey reader rejects symlinks, hard links, special files, other owners and group/world-readable files. Passkey contents are never emitted by the CLI.

These are development software keys without hardware or TEE custody. The localhost machine and Anvil administrator are trusted; they can change development balances or chain state. Registration is first-come for a fresh random local operator identity and does not establish ownership of an external account or email address.

Preserve the original state directory to retain identities. If a passkey is lost, restore that original file from a private backup; do not substitute another owner's key. There is no automatic reset or key recovery command. Existing contracts provide recovery primitives, but the full public recovery workflow is still pending. Do not move development keys or chain state into a production deployment.

## Shared implementation and qualification

`scripts/terrier_local/owner.py` owns local state and transaction orchestration. It calls `agentkeys chain prepare-owner` and `verify-owner`; the Rust library owns signing and preparation. Calldata, operation hashing and strict receipt verification are shared with the broker and bundler. Future local management interfaces must call these owners.

Native preparation also requires `AGENT_TERRIER_LOCAL_DEV=1`, the local chain profile, a loopback RPC endpoint and an unforked Anvil node with no unlocked accounts. Contract addresses must have code. The wrapper supplies this explicit development configuration after verifying its owned chain. It can use an alternate built CLI through `AGENT_TERRIER_CLI`; `AGENT_TERRIER_OWNER_TRANSACTION_GAS` controls the outer transaction gas limit.

Local, from the public checkout after downloading contract dependencies, run the heavier qualification explicitly:

```bash
python3 scripts/tests/qualify_local_owner.py
```

It covers real registration, idempotence, grant/revoke, tampered-signature rejection with unchanged scope, wrong-owner rejection, inner-operation revert, protected key permissions, missing-key refusal and persistent restart. Fast CLI tests separately reject disabled development mode, a remote RPC and a production chain profile before writing a key.
