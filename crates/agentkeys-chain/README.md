# agentkeys-chain — v2 stage-1 Solidity contracts

Foundry project for the four contracts that anchor AgentKeys v2 on-chain
state per `docs/arch.md`:

| Contract | Source | Purpose |
|---|---|---|
| `SidecarRegistry` | [`src/SidecarRegistry.sol`](src/SidecarRegistry.sol) | Per-operator device-key bindings (K10 + K11 + actor_omni). The single source of truth for "is this device registered to this operator?" Workers re-verify caps against this on every call (arch.md §10, §13.1). |
| `AgentKeysScope` | [`src/AgentKeysScope.sol`](src/AgentKeysScope.sol) | What services each agent is scoped to. Read by broker on cap-mint AND by workers on cap-verify (arch.md §12.4, §13.1). |
| `K3EpochCounter` | [`src/K3EpochCounter.sol`](src/K3EpochCounter.sol) | Current K3 epoch for signer-side KEK + K4 derivation. Advanced by signer-governance only (arch.md §16). |
| `CredentialAudit` | [`src/CredentialAudit.sol`](src/CredentialAudit.sol) | Append-only audit log (tier C per arch.md §15.3). Workers append on every credential CRUD; explorer indexers consume the events. |

## Stage-1 scope clarifications

Some on-chain features are intentionally MINIMAL in stage 1 to keep the
chain crate shippable. The deferrals are tracked here so reviewers know
they were deliberate.

| Concern | Stage 1 (this code) | Stage 2+ |
|---|---|---|
| K11 WebAuthn assertion verification | Accept-but-ignore on-chain (broker pre-verifies; bytes are stored for audit). | Verify P-256 signature on-chain when EIP-7212 precompile lands on Heima. |
| Master-mutation authorization | `msg.sender == operatorMasterWallet[operator_omni]` (sovereign mode). | Broker-mode + M-of-N recovery quorum (arch.md §11). |
| Service name encoding | `bytes32 service_hash = keccak256(name)`. | Keep — hash is canonical. |
| Per-period spend tracking | Stored but NOT enforced on-chain (workers enforce against `maxPerPeriod`). | Optional on-chain enforcement if gas budget allows. |

## Build + deploy

```bash
# Compile contracts and run tests
cd crates/agentkeys-chain
forge build
forge test

# Deploy locally (anvil)
anvil &
forge script script/DeployAgentKeysV1.s.sol \
  --rpc-url http://localhost:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast

# Deploy to Heima mainnet (driven by harness/v2-stage1-demo.sh step 9 — handles
# safety prompts, deployer-funding check, on-chain idempotency)
cd ../..
MAINNET_CONFIRM=1 bash harness/v2-stage1-demo.sh --only-step 9
```

## Wire shape — what the broker / workers / CLI read

The broker's cap-mint flow (arch.md §12.4) reads three of these on every
request:

```
Brk → SidecarRegistry.devices(deviceKeyHash)
        → DeviceEntry { operatorOmni, actorOmni, k11CredId, tier, roles, revoked }
Brk → AgentKeysScope.getScope(operatorOmni, agentOmni)
        → Scope { services[], readOnly, maxPerCall, maxPerPeriod, ... }
Brk → K3EpochCounter.currentEpoch()
        → uint256
```

Workers re-verify the same reads independently on every cap. This is the
"workers re-verify against chain on every call" guarantee from arch.md §6.
