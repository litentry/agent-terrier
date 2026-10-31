The local chain CLI runs Anvil with the real contracts, freshly generated development signing material and persistent state. It is one part of the local environment; complete onboarding, storage, agent runtimes and model integration are still being implemented.

## Start and deploy

Install Python 3.10 or newer and Foundry (`anvil`, `cast`, `forge`). Download the contract dependency and Solidity compiler with the [contract development](./contract-development.md) commands first. The commands below then work without downloads.

Run locally from the repository root:

```sh
./terrier chain start
./terrier chain deploy --offline
./terrier chain status
./terrier chain stop
```

`start` returns the loopback RPC endpoint and node instance identity. Use `chain start --port <port>` if the default profile's port is occupied. Repeating `start` reuses this manager's running node; it does not adopt another listener. Anvil starts with no unlocked accounts, no remote fork and no browser CORS access.

`deploy` creates a random disposable deployer, funds it through the local node's development RPC, signs the deployment transactions and verifies that every returned contract has code. The shared Solidity script owns deployment order and constructor wiring. It includes the checked-in EntryPoint creation bytecode, P-256 account factory and paymaster alongside the authorization contracts. No production wallet or externally supplied private key is read.

The result includes the generated `chain-profile.json` path for `AGENTKEYS_CHAIN_PROFILE_FILE`. The deployment command rechecks the running node's chain ID, client identity, instance and lack of unlocked accounts. Repeating deployment with the same contract version checks the existing contracts and writes no chain transactions. A version mismatch stops for an explicit migration or reset decision; it never redeploys automatically.

## State and development trust

State defaults to the `agent-terrier` directory under `XDG_STATE_HOME`, or `~/.local/state` when that variable is unset. Set `AGENT_TERRIER_STATE_DIR` to select a different directory **outside the repository**. Keep the path short enough for a Unix control socket. Source-contained state paths are rejected.

The state directory is owner-only (0700); keystore, password, profile, deployment records, chain snapshot and logs are owner-only files (0600). Symlinks, hard-linked files and permissive existing files are rejected. The deployer uses an encrypted keystore and a generated password stored beside it for unattended local testing. Both belong to the local developer. This arrangement provides no production custody or TEE protection: another process running as the same user can read the password and sign. Never fund these identities on a public network or reuse this state for production.

Anvil's administrative RPC is reachable by other local processes. Loopback binding and disabled CORS do not turn it into a production authorization boundary. Use a trusted development machine and disposable data. Product authorization must still be checked by the real contracts and service boundaries.

Normal `stop` waits for Anvil to save its chain state; `start` loads that state. It preserves the deployer and generated profile. If the RPC port changes, run `deploy` again to verify contracts and update the generated profile's endpoint. Keep the whole state directory together when backing it up; it contains development signing material. Abrupt process termination and manual edits are not a recovery mechanism.

The manager controls its child process through an owner-only Unix socket. It never trusts a stored PID to stop a process. An occupied port, foreign control file or insecure state directory fails without stopping another node. An orphaned node after a forced supervisor kill requires operator diagnosis; the CLI does not guess which process to kill.

## Interrupted deployment

Run locally from the same repository root and with the same state/cache settings:

```sh
./terrier chain logs
./terrier chain deploy --offline --resume
```

An incomplete deployment blocks a fresh attempt. Explicit resume uses Foundry's recorded transactions; it refuses changed source inputs, version, deployer or endpoint. Successful recovery verifies deployed code before publishing the profile. If no transactions were recorded, or a recorded transaction cannot be resumed, keep the state for diagnosis. Automatic destructive reset and contract migration are not implemented yet.

## Qualification

Run the fast filesystem and configuration checks locally from the repository root:

```sh
python3 -m unittest discover -s scripts/tests
```

Run real chain acceptance separately, locally from the repository root:

```sh
python3 scripts/tests/qualify_local_chain.py
```

The real suite starts temporary owned nodes, deploys contracts with downloads disabled, checks constructor wiring, submits authorized and unauthorized signed transactions, checks the unauthorized receipt and unchanged protected state, verifies persistence and idempotence, and recovers a completed broadcast whose process reported failure. This suite does not yet qualify full identity onboarding, grant/revocation flows or the complete application.
