// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {P256Verifier} from "../src/P256Verifier.sol";
import {P256Router} from "../src/P256Router.sol";
import {K11Verifier} from "../src/K11Verifier.sol";
import {SidecarRegistry} from "../src/SidecarRegistry.sol";
import {AgentKeysScope} from "../src/AgentKeysScope.sol";
import {K3EpochCounter} from "../src/K3EpochCounter.sol";
import {CredentialAudit} from "../src/CredentialAudit.sol";

import {P256AccountFactory} from "../src/P256AccountFactory.sol";
import {VerifyingPaymaster} from "../src/VerifyingPaymaster.sol";

contract DeployAgentKeysV1 is Script {
    function run() external {
        address signerGov = vm.envAddress("SIGNER_GOVERNANCE");
        address sponsorSigner = vm.envAddress("SPONSOR_SIGNER");
        uint256 slotDefault = vm.envUint("AGENTKEYS_AGENT_SLOT_DEFAULT");
        require(slotDefault <= type(uint16).max, "slot allowance exceeds uint16");
        bytes memory entryPointCreation = vm.parseBytes(vm.readFile("bytecode/entrypoint-v0.7.0-creation.hex"));
        vm.startBroadcast();
        P256Verifier p256 = new P256Verifier();
        P256Router p256router = new P256Router(address(p256));
        K11Verifier k11 = new K11Verifier(address(p256router));
        SidecarRegistry registry = new SidecarRegistry(address(k11), uint16(slotDefault));
        AgentKeysScope scope = new AgentKeysScope(address(registry));
        K3EpochCounter epoch = new K3EpochCounter(signerGov);
        CredentialAudit audit = new CredentialAudit(address(registry));

        address entryPoint;
        assembly {
            entryPoint := create(0, add(entryPointCreation, 0x20), mload(entryPointCreation))
        }
        require(entryPoint != address(0), "EntryPoint deployment failed");
        P256AccountFactory accountFactory = new P256AccountFactory(entryPoint, address(k11));
        VerifyingPaymaster paymaster = new VerifyingPaymaster(entryPoint, sponsorSigner, tx.origin);
        vm.stopBroadcast();

        string memory registryKey = "contracts";
        vm.serializeAddress(registryKey, "P256Verifier", address(p256));
        vm.serializeAddress(registryKey, "P256Router", address(p256router));
        vm.serializeAddress(registryKey, "K11Verifier", address(k11));
        vm.serializeAddress(registryKey, "SidecarRegistry", address(registry));
        vm.serializeAddress(registryKey, "AgentKeysScope", address(scope));
        vm.serializeAddress(registryKey, "K3EpochCounter", address(epoch));
        vm.serializeAddress(registryKey, "CredentialAudit", address(audit));
        vm.serializeAddress(registryKey, "EntryPoint", entryPoint);
        vm.serializeAddress(registryKey, "P256AccountFactory", address(accountFactory));
        string memory serialized = vm.serializeAddress(registryKey, "VerifyingPaymaster", address(paymaster));
        vm.writeJson(serialized, "deployment-registry.json");
    }
}
