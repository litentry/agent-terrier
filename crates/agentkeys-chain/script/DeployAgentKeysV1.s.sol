// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {P256Verifier} from "../src/P256Verifier.sol";
import {K11Verifier} from "../src/K11Verifier.sol";
import {SidecarRegistry} from "../src/SidecarRegistry.sol";
import {AgentKeysScope} from "../src/AgentKeysScope.sol";
import {K3EpochCounter} from "../src/K3EpochCounter.sol";
import {CredentialAudit} from "../src/CredentialAudit.sol";

/// @title DeployAgentKeysV1 — atomic deploy of the v2 stage-2 contract set
/// @notice Called by `scripts/heima-bring-up.sh` step 5 via:
///         `forge script script/DeployAgentKeysV1.s.sol --rpc-url <url>
///          --private-key <0x...> --broadcast`
///
/// @dev    Deploy order: P256Verifier → K11Verifier → SidecarRegistry →
///         AgentKeysScope → K3EpochCounter → CredentialAudit. Each downstream
///         contract takes the prior addresses via constructor.
///
///         The bring-up script parses stdout for "Name: 0xAddress" lines; regex:
///           grep -oE '<Name>:\s+0x[a-fA-F0-9]{40}'
contract DeployAgentKeysV1 is Script {
    function run() external {
        address signerGov = vm.envOr("SIGNER_GOVERNANCE", address(0));

        vm.startBroadcast();
        if (signerGov == address(0)) {
            signerGov = tx.origin;
        }

        P256Verifier p256 = new P256Verifier();
        K11Verifier k11 = new K11Verifier(address(p256));
        SidecarRegistry registry = new SidecarRegistry(address(k11));
        // #164 E3: AgentKeysScope no longer verifies K11 itself (scope writes are
        // authorized by the operator's ERC-4337 master account). Constructor takes
        // only the registry now.
        AgentKeysScope scope = new AgentKeysScope(address(registry));
        K3EpochCounter epoch = new K3EpochCounter(signerGov);
        // Audit appendRoot gates on operator-master via the registry (codex M1).
        CredentialAudit audit = new CredentialAudit(address(registry));

        vm.stopBroadcast();

        console.log("Deployer:        ", tx.origin);
        console.log("SignerGovernance:", signerGov);
        console.log("P256Verifier:    ", address(p256));
        console.log("K11Verifier:     ", address(k11));
        console.log("AgentKeysScope:  ", address(scope));
        console.log("SidecarRegistry: ", address(registry));
        console.log("K3EpochCounter:  ", address(epoch));
        console.log("CredentialAudit: ", address(audit));
    }
}
