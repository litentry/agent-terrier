# Deployed contracts — canonical registry

**Single source of truth** for every on-chain contract address AgentKeys has deployed, per chain. Answers "what's the live address of `SidecarRegistry` / the ERC-4337 `EntryPoint` on Heima mainnet right now?"

Mirrored into [`scripts/operator-workstation.env`](../scripts/operator-workstation.env) (the shell-consumable form, written by `scripts/heima-bring-up.sh` step 6 via `env_set`). When the two diverge, **this doc is authoritative for human reads, the env file for tooling**; the bring-up script keeps both in sync. Indexed from [`arch.md`](arch.md) §5.

---

## Heima mainnet (chain_id = 212013)

### v2 stage-1 set (current live)

| Contract | Address | Bytecode |
|---|---|---|
| `AgentKeysScope` | `0xd44b375daefc65768f417d0f0125b68d5ba7df3b` | 4572 bytes |
| `SidecarRegistry` | `0x1Ac62f1C2D828476a5D784e850a700dC1f17e0bE` | 4572 bytes |
| `K3EpochCounter` | `0x6c9e675c699a06acefbc156afdee6bfbfe32ccb3` | 591 bytes |
| `CredentialAudit` | `0x63c4545ac01c77cc74044f25b8edea3880224577` | 3043 bytes |
| `P256Verifier` | `0xda5b772f9d6c09abe80414eea908612df9b54749` | (pre-deployed verifier) |
| `K11Verifier` | `0x5a441431f08e0f5f5ed10659620cb4e0e814e627` | (pre-deployed verifier) |

### ERC-4337 master infra (#164, deployed 2026-06-02)

Foundation plumbing for the P-256 smart-account master ([plan](plan/chain/erc4337-master-account.md)). **NOT yet the live master-auth:** the registry/scope cutover to account-authorization (#164 E3/E7) is a later coordinated redeploy; these are inert until masters are registered as accounts.

| Contract | Address | Notes |
|---|---|---|
| `EntryPoint` (ERC-4337 v0.7) | `0x6672E1b315332167aBA12E0B1d3532a7e9B1ADE9` | canonical eth-infinitism v0.7 bytecode; landed a UserOp end-to-end in the spike |
| `P256AccountFactory` | `0x1ccCe65b22De81aDA4F378FeAf7503d93f5d27a3` | CREATE2 factory; `constructor(entryPoint, k11Verifier)`; wired to the live `K11Verifier`; mainnet CREATE2 determinism smoke-verified |

### Historical v1 deploy (superseded by v2; preserved for old-tx cross-reference)

| Contract | Address | Bytecode |
|---|---|---|
| `AgentKeysScope` | `0x14C23B5D1cE20c094af643a20e6b0972dAD12aa8` | 3146 bytes |
| `SidecarRegistry` | `0x76D574a107727bE87fc1422661A030FEFda70786` | 3301 bytes |
| `K3EpochCounter` | `0x8396dEc50ff755d6DE7728DABB00Be2eFBCdf4dF` | 687 bytes |
| `CredentialAudit` | `0x1801ded1a4FBD8c9224Ab18B9EcbB293B8674c06` | 1421 bytes |

## Heima Paseo testnet (chain_id = 2013)

Halted (block 2,905,430 frozen since 2026-01-15). **No contracts deployed** — the `*_ADDRESS_HEIMA_PASEO` entries in `operator-workstation.env` are placeholders (`0x..01`–`0x..04`). When collators return: `AGENTKEYS_CHAIN=heima-paseo bash harness/v2-stage1-demo.sh --only-step 9` deploys + auto-funds via Alice sudo; update this doc with the live testnet addresses then.

---

## Deploy metadata (Heima mainnet v2)

- Deployer wallet (EVM): `0xdE644936D5B7d5d42032fd08bbA42Fbbfd6663Bc`
- Deployer wallet (Substrate SS58 prefix 31): `47NGSq6JE5ZSnymGNa4nFVjWbsuhTfoSKN2jtpk28mUyC1M3` *(see [funding the EVM side via the Substrate twin](../scripts/evm-to-substrate-address.mjs))*
- v2 deploy date: 2026-05-19 · #164 E1 deploy date: 2026-06-02
- Compiler: Solc 0.8.20, `evm_version = "london"` (a `forge script` header-validation workaround, NOT Heima's EVM level — Heima executes **Cancun**; see CLAUDE.md "Heima EVM compatibility level"). The EntryPoint v0.7 is the canonical eth-infinitism bytecode, deployed via `forge create`.
- Deploy script: [`crates/agentkeys-chain/script/DeployAgentKeysV1.s.sol`](../crates/agentkeys-chain/script/DeployAgentKeysV1.s.sol)

**Constructor wiring** (verified post-deploy):
- `AgentKeysScope.registry()` = the v2 `SidecarRegistry` ✓
- `P256AccountFactory.entryPoint()` = the v0.7 `EntryPoint` ✓, `.k11Verifier()` = the live `K11Verifier` ✓
- `K3EpochCounter.currentEpoch()` = `1`; `.signerGovernance()` = deployer (to be transferred to an M-of-N multisig)
- `SidecarRegistry.ROLE_CAP_MINT()` = `1`, `ROLE_RECOVERY()` = `2`, `ROLE_SCOPE_MGMT()` = `4` ✓

## Verifying contracts are live (read-only RPC, zero gas)

```bash
# One-shot health check across the v2 set:
AGENTKEYS_CHAIN=heima bash scripts/verify-heima-contracts.sh   # exits 0 on all-pass

# Bytecode presence (eth_getCode), e.g. the ERC-4337 EntryPoint:
cast code 0x6672E1b315332167aBA12E0B1d3532a7e9B1ADE9 --rpc-url https://rpc.heima-parachain.heima.network | head -c 12
# View call, e.g. factory wiring:
cast call 0x1ccCe65b22De81aDA4F378FeAf7503d93f5d27a3 "entryPoint()(address)" --rpc-url https://rpc.heima-parachain.heima.network
```

**Explorer note:** [`heima.statescan.io`](https://heima.statescan.io/) is Substrate-side — it indexes pallet extrinsics/events but does NOT decode EVM calls/bytecode. EVM contract verification on Heima goes via direct RPC until agentkeys-specific indexing on Litentry's `subscan-essentials` fork ships (arch.md §22a.6).
