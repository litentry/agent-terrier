The local owner CLI registers a real P-256 smart account and signs scope grants and revocations against the deployed contracts. It requires the [owned local chain](./local-chain.md) and a built public CLI. No browser or company account is needed.

This implements owner registration, device/delegate binding and scope mutation. Broker login, storage access and the complete running-agent journey remain under development. A scope grant alone does not create an agent or bypass its independent device authorization.

## Register an owner

Local, from the public checkout after starting the chain and deploying its contracts:

```bash
cargo build -p agentkeys-cli
./terrier owner register --name developer
```

The command generates a fresh operator identity, software passkey and owner request-signing key (K10) under the private local state directory. It deploys the counterfactual P256Account through EntryPoint and registers the actual K10 device-key hash as its master device in one passkey-signed operation. The passkey authorizes contract mutations; K10 signs protected data requests. The local deployer only pays for submitting the operation. Anvil supplies disposable development funds to the account.

The result includes the operator identity, account, device-key hash and verified operation/transaction hashes. Repeating the command verifies the same on-chain binding without another transaction, including the K10, actor, owner, master tier, roles and passkey coordinates. The same identity survives a normal chain stop/start. A different contract deployment, missing original key or mismatched request key is rejected; no replacement key silently takes over an existing owner.

## Grant and revoke scope

Local, from the same checkout and shell, set the actor identity you intend to authorize:

```bash
export ACTOR_OMNI="${ACTOR_OMNI:?Set the actor identity to authorize}"
./terrier owner grant --name developer --actor-omni "${ACTOR_OMNI}" \
  --service knowledge:example --read-only
./terrier owner revoke --name developer --actor-omni "${ACTOR_OMNI}"
```

`--service` is repeatable. Grant replaces the actor's complete service set for this owner. The scope has no monetary caps; this local command does not expose payment-policy configuration. Revoking an absent scope fails with the actual on-chain operation result. A mined outer transaction is never sufficient evidence of success.

## Bind and unbind a local actor

An actor generates its own secp256k1 device key. Only its public enrollment record is given to the owner. The record uses the shared `EndpointEnrollment` schema; its actor identity is the owner's HDKD child for the selected label. The owner verifies that lineage and proof of possession before signing. This is a direct local enrollment ceremony, without broker pairing codes.

Local, in the public checkout on the machine that will own the development actor key:

```bash
operator="$(./terrier owner register --name developer | jq -r .operator_omni)"
enrollment="$(./terrier device identity --name example-agent \
  --operator-omni "${operator}" --label example-agent --kind delegate \
  | jq -r .enrollment_file)"
./terrier owner bind --name developer --enrollment-file "${enrollment}" \
  --service knowledge:example
./terrier owner unbind --name developer --enrollment-file "${enrollment}"
```

This example owns both development identities on one laptop. For an actor on a separate machine, generate its key there using `agentkeys chain device-identity` with an explicit local profile and development mode. Transfer only the enrollment JSON, keeping that file owner-only (0600); never transfer the device key or mount it into another actor. Automatic container-owned identity generation is part of the remaining runtime integration.

Use `--kind device` for a channel endpoint; its bind command accepts only `channel-pub:<id>` and `channel-sub:<id>` grants. A delegate consumes a contract-enforced agent slot; a device does not. Binding and its initial grant are one signed atomic transaction. Rebinding an existing or revoked device key fails. Use `owner grant` to change an active actor's scope, and use a fresh actor key for a new binding after revocation.

Unbind verifies the current on-chain owner, actor and tier, then revokes the device and clears the actor's entire service set atomically. It also frees a delegate's slot. It works when scope was already revoked separately. Repeating an unbind reports that the device is already revoked; it does not create another identity.

Actor state lives in `devices/<name>/` under the private local state directory. `device.key` remains local; `enrollment.json` contains only public coordinates/proof. Repeating identity creation retains the key. A changed operator/label/kind or missing original key is rejected. Enrollment records are not a substitute for a service's independent chain and proof checks.

## Keys, state and recovery

Each named owner has `owners/<name>/identity.json`, `passkey.pem` and `device.key` beneath the configured local state directory, outside the source tree. Directories are 0700 and files are 0600. Both key readers reject symlinks, hard links, special files, other owners and group/world-readable files. Key contents are never emitted by the CLI.

These are development software keys without hardware or TEE custody. The localhost machine and Anvil administrator are trusted; they can change development balances or chain state. Registration is first-come for a fresh random local operator identity and does not establish ownership of an external account or email address.

Preserve the original state directory to retain identities. If either key is lost, restore that original file from a private backup; do not substitute another owner's key. There is no automatic reset or key recovery command. Existing contracts provide recovery primitives, but the full public recovery workflow is still pending. Do not move development keys or chain state into a production deployment.

Earlier development owners used a deterministic passkey-only registry slot instead of a real K10 binding. They cannot satisfy mandatory request proofs. Registration does not silently replace that slot or its authority. Preserve the old state and register a fresh named local owner for the new flow, or use a separate fresh state directory as below. Automatic migration of those early development identities is not implemented.

For a fresh development reset, stop the current local chain and select a new empty directory with `AGENT_TERRIER_STATE_DIR`, then repeat chain start, deployment and owner registration. This creates a separate contract deployment and fresh identities. Keep the old directory intact if you need to return to it; select it again with the same setting to restore its chain and identities together. Deleting only a key is not a reset and does not revoke its on-chain authority.

## Shared implementation and qualification

`scripts/terrier_local/owner.py` owns local state and transaction orchestration. It calls `agentkeys chain prepare-owner` and `verify-owner`; the Rust library owns signing and preparation. Calldata, operation hashing and strict receipt verification are shared with the broker and bundler. Future local management interfaces must call these owners.

Native preparation also requires `AGENT_TERRIER_LOCAL_DEV=1`, the local chain profile, a loopback RPC endpoint and an unforked Anvil node with no unlocked accounts. Contract addresses must have code. The wrapper supplies this explicit development configuration after verifying its owned chain. It can use an alternate built CLI through `AGENT_TERRIER_CLI`; `AGENT_TERRIER_OWNER_TRANSACTION_GAS` controls the outer transaction gas limit.

Local, from the public checkout after downloading contract dependencies, run the heavier qualification explicitly:

```bash
python3 scripts/tests/qualify_local_owner.py
python3 scripts/tests/qualify_local_binding.py
python3 scripts/tests/qualify_local_credentials.py
```

It covers real registration, idempotence, grant/revoke, tampered-signature rejection with unchanged scope, wrong-owner rejection, inner-operation revert, protected key permissions, missing-key and wrong-request-key refusal and persistent restart. Fast CLI tests separately reject disabled development mode, a remote RPC and a production chain profile before writing a key.

The credential qualifier uses the actual worker executable, SQLite service and local contracts. It exercises owner store/fetch, delegated fetch, worker restart, malformed/missing proof and broker-signed unauthorized requests, then real scope and device revocations while owner access stays available. Its capability issuer is a test fixture; real broker session and mint integration remains open.

The binding qualification uses actual contracts for device and delegate registration, slot accounting, proof/lineage rejection without chain changes, channel-only device grants, atomic unbind, existing scope revocation and restart persistence. It also verifies that public enrollment output contains no private key.
