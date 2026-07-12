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
    // Local copies of CredentialAudit V2 events so `vm.expectEmit` can
    // match by topic+data. The event signatures MUST match
    // `CredentialAudit.sol` exactly — drift caught by `expectEmit`.
    event AuditAppendedV2(
        bytes32 indexed operatorOmni,
        bytes32 indexed actorOmni,
        uint8   indexed opKind,
        bytes32 envelopeHash
    );
    event AuditRootAppendedV2(
        bytes32 indexed operatorOmni,
        bytes32 indexed merkleRoot,
        bytes32 opKindBitmap,
        uint64  entryCount
    );

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

    // #427: the test-deploy default agent-slot allowance (delegates per operator).
    uint16 constant DEFAULT_SLOTS = 3;

    function setUp() public {
        master = makeAddr("master");
        // Account model (#164 E7): the master is the operator's P256Account — a
        // contract. Give `master` code so the registry's account guard
        // (msg.sender.code.length > 0) passes; the registry never calls into it,
        // so a stub byte suffices. `attacker` stays an EOA (no code).
        vm.etch(master, hex"00");
        attacker = makeAddr("attacker");
        p256 = new P256Verifier();
        k11 = new K11Verifier(address(p256));
        registry = new SidecarRegistry(address(k11), DEFAULT_SLOTS);
        scope = new AgentKeysScope(address(registry));
        epoch = new K3EpochCounter(address(this));
        audit = new CredentialAudit(address(registry));
    }

    // ─── SidecarRegistry: first-master bootstrap ─────────────────────────
    function test_RegisterFirstMasterDevice_BootstrapsOperator() public {
        _registerFirstMaster();
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
        _registerFirstMaster();
        // Second bootstrap with a different device hash → rejected because
        // operatorMasterWallet is now set (checked before the K11 verify, so no
        // mock needed here).
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
            7
        );
    }

    /// @notice Account model (#164 E7): the master MUST be a smart-contract account
    ///         (the operator's P256Account), never an EOA. An EOA `msg.sender` has
    ///         no `validateUserOp`, so it could never sign the downstream ERC-4337
    ///         master mutations — the registry rejects it at bootstrap. `attacker`
    ///         is an EOA (no code). This structurally retires the EOA-master class
    ///         of bug (an EOA master made the #225 accept's handleOps revert).
    function test_RegisterFirstMaster_RejectsEoaMaster() public {
        vm.prank(attacker); // EOA — no code
        vm.expectRevert(
            abi.encodeWithSelector(SidecarRegistry.MasterMustBeAccount.selector, attacker)
        );
        registry.registerFirstMasterDevice(
            deviceKeyHashMaster,
            operatorOmni,
            actorOmniMaster,
            k11CredId,
            k11RpIdHash,
            k11PubX,
            k11PubY,
            7
        );
        assertEq(registry.operatorMasterWallet(operatorOmni), address(0));
    }

    // NOTE: the former `test_RegisterFirstMaster_RejectsFrontRunWithDifferentSender`
    // (#165 self-attestation front-run) was REMOVED — E7 subsumes the explicit
    // self-attestation into the account model (the master is a passkey-controlled
    // P256Account; the UserOp signature is the passkey proof). The first-master
    // front-run binding is a documented production-hardening follow-up — see
    // docs/plan/web-flow/onboarding-p256account-master.md §8.

    // ─── SidecarRegistry: resetMaster (dev/recovery escape hatch, #225 E7) ─
    /// @notice resetMaster is OWNER-ONLY (the deployer). An attacker cannot wipe
    ///         another operator's binding; the binding stays put.
    function test_ResetMaster_RejectsNonOwner() public {
        _registerFirstMaster();
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(SidecarRegistry.NotOwner.selector, attacker));
        registry.resetMaster(operatorOmni);
        assertEq(registry.operatorMasterWallet(operatorOmni), master);
    }

    /// @notice The deployer unbinds a stranded operator (lost/deleted master
    ///         passkey) so a FRESH first-master registration re-binds — without
    ///         redeploying the contract set. This is what the daemon's
    ///         `POST /v1/master/reset` does via the deployer key (#225 E7). The
    ///         reset wipes the WHOLE device list (master + agents) and clears
    ///         wallet/threshold/nonce, so a fresh passkey → fresh P256Account →
    ///         fresh deviceKeyHash re-onboards from scratch.
    function test_ResetMaster_ClearsBindingAndAllowsReRegister() public {
        _registerFirstMaster();
        vm.prank(master);
        registry.registerAgentDevice(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"deadbeef", hex"cafe"
        );
        assertEq(registry.getOperatorDevices(operatorOmni).length, 2);

        // The test contract deployed the registry in setUp → it IS `owner`, so a
        // direct (un-pranked) call passes the owner gate.
        registry.resetMaster(operatorOmni);
        assertEq(registry.operatorMasterWallet(operatorOmni), address(0));
        assertEq(uint256(registry.recoveryThreshold(operatorOmni)), 0);
        assertEq(uint256(registry.operatorNonce(operatorOmni)), 0);
        assertEq(registry.getOperatorDevices(operatorOmni).length, 0);
        // devices deleted → registeredAt 0 → the re-register guard passes.
        assertEq(uint256(registry.getDevice(deviceKeyHashMaster).registeredAt), 0);
        assertFalse(registry.isActive(deviceKeyHashAgentA));

        // A fresh passkey → fresh P256Account → fresh device re-binds cleanly.
        address freshMaster = makeAddr("fresh-master");
        vm.etch(freshMaster, hex"00");
        bytes32 freshDeviceHash = keccak256("D_pub_master_fresh");
        uint8 fullRoles =
            registry.ROLE_CAP_MINT() | registry.ROLE_RECOVERY() | registry.ROLE_SCOPE_MGMT();
        vm.prank(freshMaster);
        registry.registerFirstMasterDevice(
            freshDeviceHash,
            operatorOmni,
            actorOmniMaster,
            k11CredId,
            k11RpIdHash,
            k11PubX,
            k11PubY,
            fullRoles
        );
        assertEq(registry.operatorMasterWallet(operatorOmni), freshMaster);
        assertEq(uint256(registry.recoveryThreshold(operatorOmni)), 1);
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

    // ─── SidecarRegistry: K10 actors (device + delegate, #427 kind split) ─
    function test_RegisterAgentDevice_RequiresMasterCaller_AndIsDeviceTier() public {
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
        assertEq(uint256(entry.tier), uint256(registry.TIER_DEVICE()));
        assertEq(uint256(entry.roles), uint256(registry.ROLE_CAP_MINT()));
        assertEq(entry.k11CredId, bytes32(0));
        assertEq(entry.k11PubX, 0);
        assertEq(entry.k11PubY, 0);
        // Devices never consume an agent slot (D9: devices only attach channels).
        (uint16 used,) = registry.agentSlots(operatorOmni);
        assertEq(uint256(used), 0);
    }

    function test_RegisterDelegate_RequiresMasterCaller_ConsumesSlot() public {
        _registerFirstMaster();
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(SidecarRegistry.NotAuthorized.selector, attacker, master)
        );
        registry.registerDelegate(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"deadbeef", hex"cafe"
        );
        vm.prank(master);
        registry.registerDelegate(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"deadbeef", hex"cafe"
        );
        SidecarRegistry.DeviceEntry memory entry = registry.getDevice(deviceKeyHashAgentA);
        assertEq(uint256(entry.tier), uint256(registry.TIER_AGENT()));
        assertEq(uint256(entry.roles), uint256(registry.ROLE_CAP_MINT()));
        (uint16 used, uint16 total) = registry.agentSlots(operatorOmni);
        assertEq(uint256(used), 1);
        assertEq(uint256(total), DEFAULT_SLOTS);
    }

    function test_RegisterDelegate_RevertsWhenAllowanceExhausted() public {
        _registerFirstMaster();
        for (uint256 i = 0; i < DEFAULT_SLOTS; ++i) {
            vm.prank(master);
            registry.registerDelegate(
                keccak256(abi.encodePacked("D_pub_delegate", i)),
                operatorOmni,
                keccak256(abi.encodePacked(operatorOmni, "//delegate", i)),
                hex"",
                hex""
            );
        }
        // The business gate: loud, actionable, names the quota.
        vm.prank(master);
        vm.expectRevert(
            abi.encodeWithSelector(
                SidecarRegistry.AgentSlotAllowanceExhausted.selector,
                operatorOmni,
                DEFAULT_SLOTS,
                DEFAULT_SLOTS
            )
        );
        registry.registerDelegate(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"", hex""
        );
    }

    function test_RevokeDelegate_FreesSlot_SuccessorCanSpawn() public {
        _registerFirstMaster();
        for (uint256 i = 0; i < DEFAULT_SLOTS; ++i) {
            vm.prank(master);
            registry.registerDelegate(
                keccak256(abi.encodePacked("D_pub_delegate", i)),
                operatorOmni,
                keccak256(abi.encodePacked(operatorOmni, "//delegate", i)),
                hex"",
                hex""
            );
        }
        // Archive one → slot returns → a successor spawn fits again.
        vm.prank(master);
        registry.revokeAgentDevice(keccak256(abi.encodePacked("D_pub_delegate", uint256(0))));
        (uint16 used,) = registry.agentSlots(operatorOmni);
        assertEq(uint256(used), DEFAULT_SLOTS - 1);
        vm.prank(master);
        registry.registerDelegate(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"", hex""
        );
        (used,) = registry.agentSlots(operatorOmni);
        assertEq(uint256(used), DEFAULT_SLOTS);
    }

    function test_RevokeDevice_DoesNotTouchSlots() public {
        _registerFirstMaster();
        vm.prank(master);
        registry.registerDelegate(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"", hex""
        );
        bytes32 deviceHash = keccak256("D_pub_camera");
        vm.prank(master);
        registry.registerAgentDevice(
            deviceHash, operatorOmni, keccak256("camera-actor"), hex"", hex""
        );
        vm.prank(master);
        registry.revokeAgentDevice(deviceHash);
        (uint16 used,) = registry.agentSlots(operatorOmni);
        assertEq(uint256(used), 1); // the delegate's slot is untouched
    }

    function test_AgentSlotAllowance_OwnerSettersAndOverride() public {
        _registerFirstMaster();
        // Non-owner (the operator's master!) must NOT be able to raise its own quota.
        vm.prank(master);
        vm.expectRevert(abi.encodeWithSelector(SidecarRegistry.NotOwner.selector, master));
        registry.setAgentSlotAllowance(operatorOmni, 100);
        vm.prank(master);
        vm.expectRevert(abi.encodeWithSelector(SidecarRegistry.NotOwner.selector, master));
        registry.setDefaultAgentSlotAllowance(100);

        // Owner (this test contract deployed the registry) sets the override.
        registry.setAgentSlotAllowance(operatorOmni, 1);
        (, uint16 total) = registry.agentSlots(operatorOmni);
        assertEq(uint256(total), 1);
        vm.prank(master);
        registry.registerDelegate(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"", hex""
        );
        vm.prank(master);
        vm.expectRevert(
            abi.encodeWithSelector(
                SidecarRegistry.AgentSlotAllowanceExhausted.selector, operatorOmni, 1, 1
            )
        );
        registry.registerDelegate(
            keccak256("D_pub_delegate_extra"), operatorOmni, keccak256("extra"), hex"", hex""
        );

        // Clear → back to the platform default.
        registry.clearAgentSlotAllowance(operatorOmni);
        (, total) = registry.agentSlots(operatorOmni);
        assertEq(uint256(total), DEFAULT_SLOTS);

        // Default retune applies to operators without an override.
        registry.setDefaultAgentSlotAllowance(7);
        (, total) = registry.agentSlots(operatorOmni);
        assertEq(uint256(total), 7);
    }

    function test_ResetMaster_ZeroesSlotsAndOverride() public {
        _registerFirstMaster();
        registry.setAgentSlotAllowance(operatorOmni, 5);
        vm.prank(master);
        registry.registerDelegate(
            deviceKeyHashAgentA, operatorOmni, actorOmniAgentA, hex"", hex""
        );
        registry.resetMaster(operatorOmni);
        (uint16 used, uint16 total) = registry.agentSlots(operatorOmni);
        assertEq(uint256(used), 0);
        assertEq(uint256(total), DEFAULT_SLOTS); // override cleared with the wipe
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

    // ─── AgentKeysScope (#164 E3: account-authorized, K11 retired) ───────
    function test_SetScope_RejectsNonMaster() public {
        _registerFirstMaster();
        bytes32[] memory services = new bytes32[](0);
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(AgentKeysScope.NotAuthorized.selector, attacker, master)
        );
        scope.setScope(operatorOmni, actorOmniAgentA, services, false, 0, 0, 0, 0);
    }

    /// @notice #164 E3: scope writes are authorized by `msg.sender == master
    ///         account` (the passkey check happened upstream in the account's
    ///         validateUserOp). The master sets + revokes scope directly.
    function test_SetScope_MasterSucceedsAndRevokes() public {
        _registerFirstMaster();
        bytes32 svc = keccak256("memory");
        bytes32[] memory services = new bytes32[](1);
        services[0] = svc;

        vm.prank(master);
        scope.setScope(operatorOmni, actorOmniAgentA, services, false, 100, 1000, 10000, 86400);
        assertTrue(scope.isServiceInScope(operatorOmni, actorOmniAgentA, svc));

        vm.prank(master);
        scope.revokeScope(operatorOmni, actorOmniAgentA);
        assertFalse(scope.isServiceInScope(operatorOmni, actorOmniAgentA, svc));
    }

    function test_RevokeScope_RejectsWhenUnset() public {
        _registerFirstMaster();
        vm.prank(master);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgentKeysScope.ScopeNotSet.selector, operatorOmni, actorOmniAgentA
            )
        );
        scope.revokeScope(operatorOmni, actorOmniAgentA);
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

    // ─── V2 envelope path (arch.md §15.3a, issue #97 phase C) ─────────────

    function test_CredentialAudit_AppendV2_EmitsEvent() public {
        bytes32 envelopeHash = keccak256("test-envelope");
        uint8 opKind = 21; // SignEip712

        // The event topics MUST carry operator, actor, and opKind so
        // explorers can filter `eth_getLogs` by any of the three.
        vm.expectEmit(true, true, true, true);
        emit AuditAppendedV2(operatorOmni, actorOmniAgentA, opKind, envelopeHash);
        audit.appendV2(operatorOmni, actorOmniAgentA, opKind, envelopeHash);
    }

    function test_CredentialAudit_AppendV2_AcceptsAnyOpKind() public {
        // Per non-break invariant #1, the contract is op-kind-agnostic —
        // any byte 0..255 must be accepted. Adding a new op_kind needs
        // ZERO contract redeploys.
        bytes32 envelopeHash = keccak256("future");
        vm.expectEmit(true, true, true, true);
        emit AuditAppendedV2(operatorOmni, actorOmniAgentA, 250, envelopeHash);
        audit.appendV2(operatorOmni, actorOmniAgentA, 250, envelopeHash);
    }

    function test_CredentialAudit_AppendV2_OpenToAnyCaller() public {
        // V2 `appendV2` is gated only by chain ordering + gas (same as
        // V1 `append`). Attacker can append, but the operator can prove
        // forgery via the indexer's view of canonical envelope hashes.
        bytes32 envelopeHash = keccak256("attacker-claim");
        vm.prank(attacker);
        audit.appendV2(operatorOmni, actorOmniAgentA, 0, envelopeHash);
        // No revert — the attacker emit is just noise the indexer filters.
    }

    function test_CredentialAudit_AppendRootV2_EmitsEvent() public {
        _registerFirstMaster();
        bytes32 root = keccak256("v2-root");
        // bit 0 (CredStore) + bit 21 (SignEip712) + bit 40 (ScopeGrant)
        bytes32 bitmap = bytes32(uint256((1 << 0) | (1 << 21) | (uint256(1) << 40)));

        vm.expectEmit(true, true, true, true);
        emit AuditRootAppendedV2(operatorOmni, root, bitmap, 3);
        vm.prank(master);
        audit.appendRootV2(operatorOmni, root, bitmap, 3);
    }

    function test_CredentialAudit_AppendRootV2_RejectsNonMaster() public {
        _registerFirstMaster();
        bytes32 root = keccak256("dummy");
        bytes32 bitmap = bytes32(uint256(1));
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(CredentialAudit.NotOperatorMaster.selector, attacker, master)
        );
        audit.appendRootV2(operatorOmni, root, bitmap, 1);
    }

    function test_CredentialAudit_V1_And_V2_Coexist() public {
        // Both surfaces stay live during the migration cycle. The V1 emit
        // path is observed today by the existing tier-A worker; V2 is
        // what new emitters use. Confirm neither breaks the other.
        bytes32 svc = keccak256("openrouter");
        bytes32 payload = keccak256("blob-1");
        audit.append(operatorOmni, actorOmniAgentA, svc, audit.OP_STORE(), payload);
        assertEq(audit.entryCount(operatorOmni), 1);

        bytes32 envHash = keccak256("v2-envelope");
        audit.appendV2(operatorOmni, actorOmniAgentA, 0, envHash);
        // V1 storage is untouched by V2 emits.
        assertEq(audit.entryCount(operatorOmni), 1);
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
        // Account model (#164 E7): no self-attestation — the master is the
        // operator's P256Account (a contract; `master` is etched in setUp), and the
        // call records operatorMasterWallet = msg.sender. Real passkey verification
        // is the account's validateUserOp (EntryPoint), exercised in the Rust/CLI
        // integration tests; the registry only gates on msg.sender being a contract.
        vm.prank(master);
        registry.registerFirstMasterDevice(
            deviceKeyHashMaster,
            operatorOmni,
            actorOmniMaster,
            k11CredId,
            k11RpIdHash,
            k11PubX,
            k11PubY,
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

}
