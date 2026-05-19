// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {SidecarRegistry} from "../src/SidecarRegistry.sol";
import {AgentKeysScope} from "../src/AgentKeysScope.sol";
import {K3EpochCounter} from "../src/K3EpochCounter.sol";
import {CredentialAudit} from "../src/CredentialAudit.sol";

/// @title DeployAgentKeysV1 — atomic deploy of the four v2 stage-1 contracts
/// @notice Called by `scripts/heima-bring-up.sh` step 5 via:
///         `forge script script/DeployAgentKeysV1.s.sol --rpc-url <url>
///          --private-key <0x...> --broadcast`
///
/// @dev    Deploy order matters: SidecarRegistry first (others reference it).
///         AgentKeysScope's constructor takes the registry address; deploy that
///         second. K3EpochCounter + CredentialAudit are independent — last.
///
///         The bring-up script parses stdout for the four "ContractName:
///         0xAddress" lines to capture addresses; the regex is:
///           grep -oE '<Name>:\s+0x[a-fA-F0-9]{40}'
///         Keep the log shape stable.
contract DeployAgentKeysV1 is Script {
    function run() external {
        // Optional override; defaults to the deployer EOA (tx.origin inside the
        // vm.startBroadcast block). Stage 2 swaps in an M-of-N multisig address.
        address signerGov = vm.envOr("SIGNER_GOVERNANCE", address(0));

        vm.startBroadcast();
        // tx.origin inside a Forge broadcast IS the --private-key signer.
        if (signerGov == address(0)) {
            signerGov = tx.origin;
        }

        SidecarRegistry registry = new SidecarRegistry();
        AgentKeysScope scope = new AgentKeysScope(address(registry));
        K3EpochCounter epoch = new K3EpochCounter(signerGov);
        CredentialAudit audit = new CredentialAudit();

        vm.stopBroadcast();

        console.log("Deployer:        ", tx.origin);
        console.log("SignerGovernance:", signerGov);
        // Stable "Name: 0xAddress" log shape parsed by heima-bring-up.sh.
        console.log("AgentKeysScope:  ", address(scope));
        console.log("SidecarRegistry: ", address(registry));
        console.log("K3EpochCounter:  ", address(epoch));
        console.log("CredentialAudit: ", address(audit));
    }
}
