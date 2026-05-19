// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {SidecarRegistry} from "../src/SidecarRegistry.sol";
import {AgentKeysScope} from "../src/AgentKeysScope.sol";
import {K3EpochCounter} from "../src/K3EpochCounter.sol";
import {CredentialAudit} from "../src/CredentialAudit.sol";

contract AgentKeysV1Test is Test {
    SidecarRegistry registry;
    AgentKeysScope scope;
    K3EpochCounter epoch;
    CredentialAudit audit;

    address master;
    address attacker;

    bytes32 operatorOmni = keccak256("operator-alice");
    bytes32 actorOmniMaster = operatorOmni; // arch.md §14: master's actor_omni == operatorOmni
    bytes32 actorOmniAgentA = keccak256(abi.encodePacked(operatorOmni, "//agent-A"));

    bytes32 deviceKeyHashMaster = keccak256("D_pub_master");
    bytes32 deviceKeyHashAgentA = keccak256("D_pub_agentA");
    bytes32 deviceKeyHash2ndMaster = keccak256("D_pub_master2");

    bytes32 k11CredId = keccak256("k11-cred-master");
    bytes k11Assertion = hex"deadbeef";
    bytes attestation = hex"cafe";

    function setUp() public {
        master = makeAddr("master");
        attacker = makeAddr("attacker");
        registry = new SidecarRegistry();
        scope = new AgentKeysScope(address(registry));
        epoch = new K3EpochCounter(address(this));
        audit = new CredentialAudit();
    }

    // ─── SidecarRegistry: register first master ──────────────────────────
    function test_RegisterMasterDevice_FirstCallBootstrapsOperator() public {
        // Precompute role bitfield BEFORE the prank — `registry.ROLE_*()` calls
        // would each consume a single-use `vm.prank` and the actual
        // registerMasterDevice call would then run with the default sender.
        uint8 fullRoles =
            registry.ROLE_CAP_MINT() | registry.ROLE_RECOVERY() | registry.ROLE_SCOPE_MGMT();
        uint8 masterTier = registry.TIER_MASTER();

        vm.prank(master);
        registry.registerMasterDevice(
            deviceKeyHashMaster,
            operatorOmni,
            actorOmniMaster,
            k11CredId,
            attestation,
            fullRoles,
            "" // first-call: no K11 assertion required
        );
        assertEq(registry.operatorMasterWallet(operatorOmni), master);
        SidecarRegistry.DeviceEntry memory entry = registry.getDevice(deviceKeyHashMaster);
        assertEq(entry.operatorOmni, operatorOmni);
        assertEq(entry.actorOmni, actorOmniMaster);
        assertEq(uint256(entry.tier), uint256(masterTier));
        assertFalse(entry.revoked);
    }

    function test_RegisterMasterDevice_RejectsDuplicate() public {
        vm.prank(master);
        registry.registerMasterDevice(
            deviceKeyHashMaster, operatorOmni, actorOmniMaster, k11CredId, attestation, 7, ""
        );
        vm.prank(master);
        vm.expectRevert(
            abi.encodeWithSelector(
                SidecarRegistry.DeviceAlreadyRegistered.selector, deviceKeyHashMaster
            )
        );
        registry.registerMasterDevice(
            deviceKeyHashMaster, operatorOmni, actorOmniMaster, k11CredId, attestation, 7, ""
        );
    }

    function test_RegisterSecondMaster_RequiresExistingMasterAndK11() public {
        vm.prank(master);
        registry.registerMasterDevice(
            deviceKeyHashMaster, operatorOmni, actorOmniMaster, k11CredId, attestation, 7, ""
        );
        // attacker can't add a 2nd master
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(SidecarRegistry.NotAuthorized.selector, attacker, master)
        );
        registry.registerMasterDevice(
            deviceKeyHash2ndMaster, operatorOmni, actorOmniMaster, k11CredId, attestation, 7, k11Assertion
        );
        // master can, with K11
        vm.prank(master);
        registry.registerMasterDevice(
            deviceKeyHash2ndMaster, operatorOmni, actorOmniMaster, k11CredId, attestation, 7, k11Assertion
        );
        // master can NOT without K11 (after bootstrap, K11 is required for masters)
        bytes32 thirdHash = keccak256("third");
        vm.prank(master);
        vm.expectRevert(SidecarRegistry.K11AssertionRequired.selector);
        registry.registerMasterDevice(
            thirdHash, operatorOmni, actorOmniMaster, k11CredId, attestation, 7, ""
        );
    }

    // ─── SidecarRegistry: agent registration ─────────────────────────────
    function test_RegisterAgent_RequiresMasterCaller() public {
        vm.prank(master);
        registry.registerMasterDevice(
            deviceKeyHashMaster, operatorOmni, actorOmniMaster, k11CredId, attestation, 7, ""
        );
        // attacker can't register an agent
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(SidecarRegistry.NotAuthorized.selector, attacker, master)
        );
        registry.registerAgentDevice(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"deadbeef", hex"cafe"
        );
        // master can
        vm.prank(master);
        registry.registerAgentDevice(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"deadbeef", hex"cafe"
        );
        SidecarRegistry.DeviceEntry memory entry = registry.getDevice(deviceKeyHashAgentA);
        assertEq(uint256(entry.tier), uint256(registry.TIER_AGENT()));
        assertEq(uint256(entry.roles), uint256(registry.ROLE_CAP_MINT()));
        assertEq(entry.k11CredId, bytes32(0));
    }

    function test_RegisterAgent_RejectsBeforeOperatorBootstrap() public {
        vm.expectRevert(
            abi.encodeWithSelector(SidecarRegistry.OperatorNotRegistered.selector, operatorOmni)
        );
        registry.registerAgentDevice(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"", hex""
        );
    }

    // ─── SidecarRegistry: revoke ─────────────────────────────────────────
    function test_RevokeDevice() public {
        vm.prank(master);
        registry.registerMasterDevice(
            deviceKeyHashMaster, operatorOmni, actorOmniMaster, k11CredId, attestation, 7, ""
        );
        vm.prank(master);
        registry.registerAgentDevice(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"deadbeef", hex"cafe"
        );

        // Revoke the agent — no K11 required for agent revoke
        vm.prank(master);
        registry.revokeDevice(deviceKeyHashAgentA, "");
        assertFalse(registry.isActive(deviceKeyHashAgentA));

        // Master revoke requires K11
        vm.prank(master);
        vm.expectRevert(SidecarRegistry.K11AssertionRequired.selector);
        registry.revokeDevice(deviceKeyHashMaster, "");
        vm.prank(master);
        registry.revokeDevice(deviceKeyHashMaster, k11Assertion);
        assertFalse(registry.isActive(deviceKeyHashMaster));
    }

    // ─── AgentKeysScope ──────────────────────────────────────────────────
    function test_SetScope() public {
        vm.prank(master);
        registry.registerMasterDevice(
            deviceKeyHashMaster, operatorOmni, actorOmniMaster, k11CredId, attestation, 7, ""
        );

        bytes32[] memory services = new bytes32[](2);
        services[0] = keccak256("openrouter");
        services[1] = keccak256("brave-search");

        vm.prank(master);
        scope.setScopeWithWebauthn(
            operatorOmni,
            actorOmniAgentA,
            services,
            false, // read_only
            1000, // maxPerCall
            10000, // maxPerPeriod
            100000, // maxTotal
            86400, // period: 1 day
            k11Assertion
        );

        AgentKeysScope.Scope memory s = scope.getScope(operatorOmni, actorOmniAgentA);
        assertTrue(s.exists);
        assertEq(s.services.length, 2);
        assertEq(s.services[0], keccak256("openrouter"));
        assertTrue(scope.isServiceInScope(operatorOmni, actorOmniAgentA, keccak256("openrouter")));
        assertFalse(scope.isServiceInScope(operatorOmni, actorOmniAgentA, keccak256("elevenlabs")));
    }

    function test_SetScope_RejectsAttacker() public {
        vm.prank(master);
        registry.registerMasterDevice(
            deviceKeyHashMaster, operatorOmni, actorOmniMaster, k11CredId, attestation, 7, ""
        );
        bytes32[] memory services = new bytes32[](0);

        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(AgentKeysScope.NotAuthorized.selector, attacker, master)
        );
        scope.setScopeWithWebauthn(
            operatorOmni, actorOmniAgentA, services, false, 0, 0, 0, 0, k11Assertion
        );
    }

    function test_RevokeScope() public {
        vm.prank(master);
        registry.registerMasterDevice(
            deviceKeyHashMaster, operatorOmni, actorOmniMaster, k11CredId, attestation, 7, ""
        );
        bytes32[] memory services = new bytes32[](1);
        services[0] = keccak256("openrouter");
        vm.prank(master);
        scope.setScopeWithWebauthn(
            operatorOmni, actorOmniAgentA, services, false, 0, 0, 0, 0, k11Assertion
        );
        vm.prank(master);
        scope.revokeScope(operatorOmni, actorOmniAgentA, k11Assertion);
        AgentKeysScope.Scope memory s = scope.getScope(operatorOmni, actorOmniAgentA);
        assertFalse(s.exists);
    }

    // ─── K3EpochCounter ──────────────────────────────────────────────────
    function test_K3EpochCounter_AdvanceAndTransferGovernance() public {
        assertEq(epoch.currentEpoch(), 1);
        epoch.advanceEpoch();
        assertEq(epoch.currentEpoch(), 2);

        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(
                K3EpochCounter.NotSignerGovernance.selector, attacker, address(this)
            )
        );
        epoch.advanceEpoch();

        epoch.setSignerGovernance(master);
        assertEq(epoch.signerGovernance(), master);

        vm.prank(master);
        epoch.advanceEpoch();
        assertEq(epoch.currentEpoch(), 3);
    }

    // ─── CredentialAudit ─────────────────────────────────────────────────
    function test_CredentialAudit_AppendAndRead() public {
        bytes32 svc = keccak256("openrouter");
        bytes32 payload = keccak256("blob-1");
        audit.append(operatorOmni, actorOmniAgentA, svc, audit.OP_STORE(), payload);
        audit.append(operatorOmni, actorOmniAgentA, svc, audit.OP_READ(), payload);
        assertEq(audit.entryCount(operatorOmni), 2);

        CredentialAudit.AuditEntry[] memory page = audit.getEntries(operatorOmni, 0, 10);
        assertEq(page.length, 2);
        assertEq(page[0].opType, audit.OP_STORE());
        assertEq(page[1].opType, audit.OP_READ());
    }
}
