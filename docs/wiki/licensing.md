Apache-2.0 is the default license for Agent Terrier. The full text is in [LICENSE](../../LICENSE). Rust workspace packages and the web/design-system package metadata declare that license. Contributions to those parts use the same license unless an existing file-level notice specifies otherwise.

## Existing exceptions

| Source | Existing license | Handling |
|---|---|---|
| Current Solidity files in `crates/agentkeys-chain/src`, `test` and `script` | AGPL-3.0-only | Preserve their SPDX notices; include the [license text](../../LICENSES/AGPL-3.0-only.txt). |
| Interface declarations in `crates/agentkeys-chain/src/IERC4337.sol` | File declares AGPL-3.0-only; adapted upstream interfaces declare GPL-3.0 | Preserve the file notice and upstream provenance; include [GPL terms](../../LICENSES/GPL-3.0-only.txt). |
| Historical `crates/agentkeys-chain/archived/AgentKeysScope.deployed-stage1.sol` snapshot | Existing MIT and AGPL-3.0-only notices | Preserve both notices; this historical file is outside the active contract build. |
| `crates/agentkeys-broker-server/solidity/src/AgentKeysAudit.sol` | MIT | Preserve its SPDX notice. |
| `packages/agentkeys-dsh` | MIT in package metadata | Preserve its package declaration and include [MIT terms](../../LICENSES/MIT.txt). |

The copied ERC-4337 interface provenance is recorded in the source. Upstream v0.7.0 [IAccount](https://github.com/eth-infinitism/account-abstraction/blob/v0.7.0/contracts/interfaces/IAccount.sol) and [PackedUserOperation](https://github.com/eth-infinitism/account-abstraction/blob/v0.7.0/contracts/interfaces/PackedUserOperation.sol) carry GPL-3.0 identifiers. The repository is therefore mixed-license; its default Apache-2.0 license does not replace these explicit notices. Any future relicensing needs its own provenance and rights review.

## Distribution

[NOTICE](../../NOTICE) records the source exceptions. Keep the applicable notices and license texts with distributed source and artifacts. Dependencies, base images, downloaded models and agent runtimes retain their own terms; the root license does not cover them. The final release qualification must record the actual shipped dependency/image/model inventory rather than treating a package's default license as an inventory of all bundled material.
