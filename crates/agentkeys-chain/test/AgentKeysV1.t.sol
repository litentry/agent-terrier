// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {P256Verifier} from "../src/P256Verifier.sol";
import {K11Verifier} from "../src/K11Verifier.sol";
import {SidecarRegistry} from "../src/SidecarRegistry.sol";
import {AgentKeysScope} from "../src/AgentKeysScope.sol";
import {K3EpochCounter} from "../src/K3EpochCounter.sol";
import {CredentialAudit} from "../src/CredentialAudit.sol";

/// @title AgentKeysV1Test — sanity tests for the v2 stage-2 contract set.
/// @dev   K11-gated flows are tested with EMPTY/INVALID assertions to verify
///        the guard logic rejects them — they SHOULD revert. End-to-end with
///        a real valid K11 assertion is tested in the CLI integration tests
///        (Rust side), where we have a software P-256 authenticator that can
///        produce the full (authData || clientDataJSON || r, s) chain bound
///        to a contract-computed challenge.
contract AgentKeysV1Test is Test {
    P256Verifier p256;
    K11Verifier k11;
    SidecarRegistry registry;
    AgentKeysScope scope;
    K3EpochCounter epoch;
    CredentialAudit audit;

    address master;
    address attacker;

    bytes32 operatorOmni = keccak256("operator-alice");
    bytes32 actorOmniMaster = operatorOmni;
    bytes32 actorOmniAgentA = keccak256(abi.encodePacked(operatorOmni, "//agent-A"));

    bytes32 deviceKeyHashMaster = keccak256("D_pub_master");
    bytes32 deviceKeyHashAgentA = keccak256("D_pub_agentA");
    bytes32 deviceKeyHash2ndMaster = keccak256("D_pub_master2");

    bytes32 k11CredId = keccak256("k11-cred-master");
    bytes32 k11RpIdHash = keccak256("localhost"); // codex H1: bound at register time

    // Stub pubkey coords. Bogus values — the contracts only check liveness
    // semantics in this test file; signature verification with real P-256
    // numbers is covered by P256Verifier.t.sol + K11Verifier.t.sol and the
    // Rust-side CLI integration tests.
    uint256 k11PubX = uint256(keccak256("stub-k11-pubX"));
    uint256 k11PubY = uint256(keccak256("stub-k11-pubY"));

    function setUp() public {
        master = makeAddr("master");
        attacker = makeAddr("attacker");
        p256 = new P256Verifier();
        k11 = new K11Verifier(address(p256));
        registry = new SidecarRegistry(address(k11));
        scope = new AgentKeysScope(address(registry), address(k11));
        epoch = new K3EpochCounter(address(this));
        audit = new CredentialAudit(address(registry));
    }

    // ─── SidecarRegistry: first-master bootstrap ─────────────────────────
    function test_RegisterFirstMasterDevice_BootstrapsOperator() public {
        uint8 fullRoles =
            registry.ROLE_CAP_MINT() | registry.ROLE_RECOVERY() | registry.ROLE_SCOPE_MGMT();

        vm.prank(master);
        registry.registerFirstMasterDevice(
            deviceKeyHashMaster,
            operatorOmni,
            actorOmniMaster,
            k11CredId,
            k11RpIdHash,
            k11PubX,
            k11PubY,
            hex"cafe",
            fullRoles
        );
        assertEq(registry.operatorMasterWallet(operatorOmni), master);
        assertEq(uint256(registry.recoveryThreshold(operatorOmni)), 1);
        SidecarRegistry.DeviceEntry memory entry = registry.getDevice(deviceKeyHashMaster);
        assertEq(entry.operatorOmni, operatorOmni);
        assertEq(uint256(entry.tier), uint256(registry.TIER_MASTER()));
        assertFalse(entry.revoked);
        assertEq(entry.k11PubX, k11PubX);
        assertEq(entry.k11PubY, k11PubY);
    }

    function test_RegisterFirstMaster_RejectsDuplicateBootstrap() public {
        vm.prank(master);
        registry.registerFirstMasterDevice(
            deviceKeyHashMaster, operatorOmni, actorOmniMaster, k11CredId, k11RpIdHash, k11PubX, k11PubY, "", 7
        );
        // Second bootstrap with a different device hash → rejected because
        // operatorMasterWallet is now set.
        vm.prank(master);
        vm.expectRevert(
            abi.encodeWithSelector(
                SidecarRegistry.DeviceAlreadyRegistered.selector, deviceKeyHash2ndMaster
            )
        );
        registry.registerFirstMasterDevice(
            deviceKeyHash2ndMaster,
            operatorOmni,
            actorOmniMaster,
            k11CredId,
            k11RpIdHash,
            k11PubX,
            k11PubY,
            "",
            7
        );
    }

    // ─── SidecarRegistry: 2nd master device requires K11 ────────────────
    function test_RegisterAdditionalMaster_RejectsAttacker() public {
        _registerFirstMaster();
        SidecarRegistry.K11Assertion memory bogusK11 = _bogusAssertion(deviceKeyHashMaster);
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(SidecarRegistry.NotAuthorized.selector, attacker, master)
        );
        registry.registerAdditionalMasterDevice(
            deviceKeyHash2ndMaster,
            operatorOmni,
            actorOmniMaster,
            k11CredId,
            k11RpIdHash,
            k11PubX,
            k11PubY,
            hex"cafe",
            3,
            bogusK11
        );
    }

    function test_RegisterAdditionalMaster_RejectsInvalidK11() public {
        _registerFirstMaster();
        SidecarRegistry.K11Assertion memory bogusK11 = _bogusAssertion(deviceKeyHashMaster);
        // Master submits with bogus K11 → fails challenge match (or P-256
        // verify). Exact revert: either ChallengeMismatch (caller's bogus
        // clientDataJSON is wrong) or K11VerificationFailed. We accept any
        // revert.
        vm.prank(master);
        vm.expectRevert();
        registry.registerAdditionalMasterDevice(
            deviceKeyHash2ndMaster,
            operatorOmni,
            actorOmniMaster,
            k11CredId,
            k11RpIdHash,
            k11PubX,
            k11PubY,
            hex"cafe",
            3,
            bogusK11
        );
    }

    // ─── SidecarRegistry: agent ──────────────────────────────────────────
    function test_RegisterAgent_RequiresMasterCaller() public {
        _registerFirstMaster();
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(SidecarRegistry.NotAuthorized.selector, attacker, master)
        );
        registry.registerAgentDevice(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"deadbeef", hex"cafe"
        );
        vm.prank(master);
        registry.registerAgentDevice(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"deadbeef", hex"cafe"
        );
        SidecarRegistry.DeviceEntry memory entry = registry.getDevice(deviceKeyHashAgentA);
        assertEq(uint256(entry.tier), uint256(registry.TIER_AGENT()));
        assertEq(uint256(entry.roles), uint256(registry.ROLE_CAP_MINT()));
        assertEq(entry.k11CredId, bytes32(0));
        assertEq(entry.k11PubX, 0);
        assertEq(entry.k11PubY, 0);
    }

    function test_RegisterAgent_RejectsBeforeOperatorBootstrap() public {
        vm.expectRevert(
            abi.encodeWithSelector(SidecarRegistry.OperatorNotRegistered.selector, operatorOmni)
        );
        registry.registerAgentDevice(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"", hex""
        );
    }

    function test_RevokeAgent() public {
        _registerFirstMaster();
        vm.prank(master);
        registry.registerAgentDevice(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"deadbeef", hex"cafe"
        );
        vm.prank(master);
        registry.revokeAgentDevice(deviceKeyHashAgentA);
        assertFalse(registry.isActive(deviceKeyHashAgentA));
    }

    function test_RevokeAgent_RejectsRevokingMaster() public {
        _registerFirstMaster();
        vm.prank(master);
        vm.expectRevert();
        registry.revokeAgentDevice(deviceKeyHashMaster);
    }

    // ─── SidecarRegistry: master revoke requires quorum ──────────────────
    function test_RevokeMaster_RejectsInsufficientQuorum() public {
        _registerFirstMaster();
        SidecarRegistry.K11Assertion[] memory empty = new SidecarRegistry.K11Assertion[](0);
        vm.prank(master);
        vm.expectRevert(
            abi.encodeWithSelector(SidecarRegistry.InsufficientQuorum.selector, uint8(0), uint8(1))
        );
        registry.revokeMasterDevice(deviceKeyHashMaster, empty);
    }

    function test_RevokeMaster_RejectsInvalidAssertion() public {
        _registerFirstMaster();
        SidecarRegistry.K11Assertion[] memory bogus = new SidecarRegistry.K11Assertion[](1);
        bogus[0] = _bogusAssertion(deviceKeyHashMaster);
        vm.prank(master);
        vm.expectRevert();
        registry.revokeMasterDevice(deviceKeyHashMaster, bogus);
    }

    // ─── AgentKeysScope: rejects without K11 ─────────────────────────────
    function test_SetScope_RejectsAttacker() public {
        _registerFirstMaster();
        bytes32[] memory services = new bytes32[](0);
        AgentKeysScope.K11Assertion memory bogus = _bogusScopeAssertion(deviceKeyHashMaster);
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(AgentKeysScope.NotAuthorized.selector, attacker, master)
        );
        scope.setScopeWithWebauthn(
            operatorOmni, actorOmniAgentA, services, false, 0, 0, 0, 0, bogus
        );
    }

    function test_SetScope_RejectsInvalidK11() public {
        _registerFirstMaster();
        bytes32[] memory services = new bytes32[](0);
        AgentKeysScope.K11Assertion memory bogus = _bogusScopeAssertion(deviceKeyHashMaster);
        vm.prank(master);
        vm.expectRevert();
        scope.setScopeWithWebauthn(
            operatorOmni, actorOmniAgentA, services, false, 0, 0, 0, 0, bogus
        );
    }

    // ─── K3EpochCounter (unchanged from PR #87) ──────────────────────────
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

    // ─── CredentialAudit (unchanged from PR #87) ─────────────────────────
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

    // ─── CredentialAudit tier-A Merkle root path (#90 follow-up) ────────
    function test_CredentialAudit_AppendRoot_AndVerifyMembership() public {
        _registerFirstMaster(); // operatorMasterWallet must be set for appendRoot auth (codex M1).

        // Build a 4-leaf Merkle tree of audit events with domain separation
        // (codex M2): 0x00 prefix on leaves, 0x01 on internal nodes.
        bytes32 raw0 = keccak256("audit-event-0");
        bytes32 raw1 = keccak256("audit-event-1");
        bytes32 raw2 = keccak256("audit-event-2");
        bytes32 raw3 = keccak256("audit-event-3");
        bytes32 leaf0 = _leafPrefix(raw0);
        bytes32 leaf1 = _leafPrefix(raw1);
        bytes32 leaf2 = _leafPrefix(raw2);
        bytes32 leaf3 = _leafPrefix(raw3);
        bytes32 h01 = _hashPair(leaf0, leaf1);
        bytes32 h23 = _hashPair(leaf2, leaf3);
        bytes32 root = _hashPair(h01, h23);

        vm.prank(master);
        audit.appendRoot(operatorOmni, root, 4);
        assertEq(audit.rootCount(operatorOmni), 1);

        // Verify leaf2 is in the root via proof [leaf3, h01].
        // Note: pass the RAW leaf to verifyEntryInRoot — the contract
        // applies the prefix internally.
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = leaf3;
        proof[1] = h01;
        assertTrue(audit.verifyEntryInRoot(operatorOmni, 0, proof, raw2));

        // Reject a tampered leaf.
        assertFalse(audit.verifyEntryInRoot(operatorOmni, 0, proof, keccak256("nope")));

        // Reject out-of-range root index.
        bytes32[] memory emptyProof = new bytes32[](0);
        assertFalse(audit.verifyEntryInRoot(operatorOmni, 99, emptyProof, raw0));

        // Attacker tries to pass an internal-node digest as a leaf — the
        // domain prefix makes it impossible. Codex M2 fix.
        bytes32[] memory shortProof = new bytes32[](1);
        shortProof[0] = h23;
        // Try: claim h01 (internal node) is a leaf. verifyEntryInRoot
        // prefixes it with 0x00 → keccak(0x00 || h01) ≠ h01.
        assertFalse(audit.verifyEntryInRoot(operatorOmni, 0, shortProof, h01));
    }

    function test_CredentialAudit_AppendRoot_RejectsNonMaster() public {
        _registerFirstMaster();
        bytes32 root = keccak256("dummy");
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(CredentialAudit.NotOperatorMaster.selector, attacker, master)
        );
        audit.appendRoot(operatorOmni, root, 1);
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        // Internal-node prefix per codex M2.
        return a < b
            ? keccak256(abi.encodePacked(bytes1(0x01), a, b))
            : keccak256(abi.encodePacked(bytes1(0x01), b, a));
    }

    function _leafPrefix(bytes32 raw) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x00), raw));
    }

    // ─── Helpers ─────────────────────────────────────────────────────────
    function _registerFirstMaster() internal {
        uint8 fullRoles =
            registry.ROLE_CAP_MINT() | registry.ROLE_RECOVERY() | registry.ROLE_SCOPE_MGMT();
        vm.prank(master);
        registry.registerFirstMasterDevice(
            deviceKeyHashMaster,
            operatorOmni,
            actorOmniMaster,
            k11CredId,
            k11RpIdHash,
            k11PubX,
            k11PubY,
            "",
            fullRoles
        );
    }

    /// @dev Bogus assertion for SidecarRegistry — fails challenge or P-256
    ///      verify by construction; used to exercise the revert paths.
    function _bogusAssertion(bytes32 attestingDevice)
        internal
        pure
        returns (SidecarRegistry.K11Assertion memory)
    {
        bytes memory authData = new bytes(37);
        bytes memory cdj = bytes(
            '{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"https://localhost"}'
        );
        return SidecarRegistry.K11Assertion({
            attestingDeviceKeyHash: attestingDevice,
            authenticatorData: authData,
            clientDataJSON: cdj,
            challengeLocation: 36,
            r: 1,
            s: 1
        });
    }

    function _bogusScopeAssertion(bytes32 attestingDevice)
        internal
        pure
        returns (AgentKeysScope.K11Assertion memory)
    {
        bytes memory authData = new bytes(37);
        bytes memory cdj = bytes(
            '{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"https://localhost"}'
        );
        return AgentKeysScope.K11Assertion({
            attestingDeviceKeyHash: attestingDevice,
            authenticatorData: authData,
            clientDataJSON: cdj,
            challengeLocation: 36,
            r: 1,
            s: 1
        });
    }
}
