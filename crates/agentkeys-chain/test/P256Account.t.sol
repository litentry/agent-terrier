// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {P256Account} from "../src/P256Account.sol";
import {P256AccountFactory} from "../src/P256AccountFactory.sol";
import {PackedUserOperation} from "../src/IERC4337.sol";

contract Counter {
    uint256 public number;

    function increment() external {
        number += 1;
    }
}

/// @dev Stand-in for the deployed K11Verifier. Real WebAuthn/P-256 verification
///      is covered by K11Verifier.t.sol / P256Verifier.t.sol and the Heima
///      mainnet spike (#164 plan §1); here we exercise the account's LOGIC.
contract MockK11Verifier {
    bool public result = true;
    bool public doRevert;

    function setResult(bool r) external {
        result = r;
    }

    function setRevert(bool r) external {
        doRevert = r;
    }

    function verifyAssertion(
        bytes32,
        bytes32,
        bytes memory,
        bytes memory,
        uint256,
        uint256,
        uint256,
        uint256,
        uint256
    ) external view returns (bool) {
        // The real K11Verifier reverts on malformed/mismatched assertions; mimic it.
        require(!doRevert, "K11: malformed/mismatched");
        return result;
    }
}

contract P256AccountTest is Test {
    address constant ENTRYPOINT = address(0xE427);
    MockK11Verifier k11;
    P256AccountFactory factory;
    Counter counter;

    bytes32 constant CRED = keccak256("cred-1");
    bytes32 constant CRED2 = keccak256("cred-2");
    uint256 constant PUBX = uint256(keccak256("pubx"));
    uint256 constant PUBY = uint256(keccak256("puby"));
    // #317: frozen WebAuthn-RPID test vector — NOT a deployment domain. The
    // keccak256 hash is baked into this test's expected signatures, so this
    // literal is content-filter-allowlisted and must never be scrubbed.
    bytes32 constant RPID = keccak256("litentry.org");

    function setUp() public {
        k11 = new MockK11Verifier();
        factory = new P256AccountFactory(ENTRYPOINT, address(k11));
        counter = new Counter();
    }

    function _deploy() internal returns (P256Account) {
        return P256Account(payable(factory.createAccount(CRED, PUBX, PUBY, RPID, bytes32(0))));
    }

    function _op(bytes32 cred) internal pure returns (PackedUserOperation memory op) {
        op.signature = abi.encode(cred, hex"aa", hex"bb", uint256(0), uint256(1), uint256(2));
    }

    function test_FactoryDeterministicAndIdempotent() public {
        address predicted = factory.getAddress(CRED, PUBX, PUBY, RPID, bytes32(0));
        address a = factory.createAccount(CRED, PUBX, PUBY, RPID, bytes32(0));
        assertEq(a, predicted, "address must match prediction");
        assertEq(factory.createAccount(CRED, PUBX, PUBY, RPID, bytes32(0)), a, "idempotent");
        assertGt(a.code.length, 0, "deployed");
    }

    function test_FactoryAddressDependsOnPasskey() public view {
        assertTrue(
            factory.getAddress(CRED, PUBX, PUBY, RPID, bytes32(0))
                != factory.getAddress(CRED, PUBX + 1, PUBY, RPID, bytes32(0)),
            "different passkey -> different address"
        );
    }

    function test_InitialSigner() public {
        P256Account acct = _deploy();
        assertEq(acct.activeSignerCount(), 1);
        (uint256 x, uint256 y, bytes32 rp, bool active, uint64 gen) = acct.signers(CRED);
        assertEq(x, PUBX);
        assertEq(y, PUBY);
        assertEq(rp, RPID);
        assertTrue(active);
        assertEq(gen, 0);
    }

    function test_ValidateUserOp_Success() public {
        P256Account acct = _deploy();
        k11.setResult(true);
        vm.prank(ENTRYPOINT);
        assertEq(acct.validateUserOp(_op(CRED), bytes32(uint256(0x1234)), 0), 0);
    }

    function test_ValidateUserOp_BadSig() public {
        P256Account acct = _deploy();
        k11.setResult(false);
        vm.prank(ENTRYPOINT);
        assertEq(acct.validateUserOp(_op(CRED), bytes32(uint256(0x1234)), 0), 1);
    }

    function test_ValidateUserOp_UnknownSigner() public {
        P256Account acct = _deploy();
        vm.prank(ENTRYPOINT);
        assertEq(acct.validateUserOp(_op(CRED2), bytes32(uint256(0x1234)), 0), 1);
    }

    function test_ValidateUserOp_OnlyEntryPoint() public {
        P256Account acct = _deploy();
        vm.expectRevert(P256Account.NotEntryPoint.selector);
        acct.validateUserOp(_op(CRED), bytes32(uint256(0x1234)), 0);
    }

    // codex P2: a reverting verifier (malformed/mismatched assertion) must map
    // to SIG_VALIDATION_FAILED, not bubble a revert out of validateUserOp.
    function test_ValidateUserOp_VerifierRevert_MapsToFail() public {
        P256Account acct = _deploy();
        k11.setRevert(true);
        vm.prank(ENTRYPOINT);
        assertEq(acct.validateUserOp(_op(CRED), bytes32(uint256(1)), 0), 1, "verifier revert -> SIG_FAIL");
    }

    function test_ValidateUserOp_MalformedSig_MapsToFail() public {
        P256Account acct = _deploy();
        PackedUserOperation memory op;
        op.signature = hex"1234"; // not a valid abi.encode tuple -> decode reverts
        vm.prank(ENTRYPOINT);
        assertEq(acct.validateUserOp(op, bytes32(uint256(1)), 0), 1, "malformed sig -> SIG_FAIL");
    }

    function test_CheckUserOpSignature_OnlySelf() public {
        P256Account acct = _deploy();
        vm.expectRevert(P256Account.NotSelf.selector);
        acct.checkUserOpSignature(_op(CRED).signature, bytes32(uint256(1)));
    }

    function test_Execute_FromEntryPoint() public {
        P256Account acct = _deploy();
        vm.prank(ENTRYPOINT);
        acct.execute(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector));
        assertEq(counter.number(), 1);
    }

    function test_Execute_Unauthorized() public {
        P256Account acct = _deploy();
        vm.expectRevert(P256Account.NotEntryPointOrSelf.selector);
        acct.execute(address(counter), 0, abi.encodeWithSelector(Counter.increment.selector));
    }

    function test_ExecuteBatch() public {
        P256Account acct = _deploy();
        address[] memory dest = new address[](2);
        uint256[] memory val = new uint256[](2);
        bytes[] memory fn = new bytes[](2);
        dest[0] = address(counter);
        dest[1] = address(counter);
        fn[0] = abi.encodeWithSelector(Counter.increment.selector);
        fn[1] = abi.encodeWithSelector(Counter.increment.selector);
        vm.prank(ENTRYPOINT);
        acct.executeBatch(dest, val, fn);
        assertEq(counter.number(), 2);
    }

    function test_AddSigner_GatedAndUsable() public {
        P256Account acct = _deploy();
        vm.expectRevert(P256Account.NotEntryPointOrSelf.selector);
        acct.addSigner(CRED2, PUBX, PUBY, RPID);

        vm.prank(ENTRYPOINT);
        acct.addSigner(CRED2, PUBX, PUBY, RPID);
        assertEq(acct.activeSignerCount(), 2);

        k11.setResult(true);
        vm.prank(ENTRYPOINT);
        assertEq(acct.validateUserOp(_op(CRED2), bytes32(uint256(1)), 0), 0, "new passkey validates");
    }

    function test_RemoveSigner_LockoutProtection() public {
        P256Account acct = _deploy();
        vm.prank(ENTRYPOINT);
        vm.expectRevert(P256Account.LastSigner.selector);
        acct.removeSigner(CRED);
    }

    function test_RemoveSigner_Works() public {
        P256Account acct = _deploy();
        vm.startPrank(ENTRYPOINT);
        acct.addSigner(CRED2, PUBX, PUBY, RPID);
        acct.removeSigner(CRED);
        vm.stopPrank();
        assertEq(acct.activeSignerCount(), 1);
        vm.prank(ENTRYPOINT);
        assertEq(acct.validateUserOp(_op(CRED), bytes32(uint256(1)), 0), 1, "removed signer rejected");
    }

    function test_PayPrefund() public {
        P256Account acct = _deploy();
        vm.deal(address(acct), 1 ether);
        k11.setResult(true);
        uint256 epBefore = ENTRYPOINT.balance;
        vm.prank(ENTRYPOINT);
        acct.validateUserOp(_op(CRED), bytes32(uint256(1)), 0.1 ether);
        assertEq(ENTRYPOINT.balance, epBefore + 0.1 ether, "prefund forwarded to EntryPoint");
    }

    // ─── E5: guardian social recovery ────────────────────────────────────
    bytes32 constant GCRED = keccak256("guardian-1");
    bytes32 constant GCRED2 = keccak256("guardian-2");
    bytes32 constant NEWCRED = keccak256("recovered-signer");

    function _gAssertion(bytes32 gid) internal pure returns (P256Account.GuardianAssertion memory a) {
        a.guardianCredIdHash = gid;
        a.authenticatorData = hex"aa";
        a.clientDataJSON = hex"bb";
        a.challengeLocation = 0;
        a.r = 1;
        a.s = 2;
    }

    function test_Guardian_Gating() public {
        P256Account acct = _deploy();
        vm.expectRevert(P256Account.NotEntryPointOrSelf.selector);
        acct.addGuardian(GCRED, PUBX, PUBY, RPID);
        vm.prank(ENTRYPOINT);
        acct.addGuardian(GCRED, PUBX, PUBY, RPID);
        assertEq(acct.activeGuardianCount(), 1);
    }

    function test_SetRecoveryThreshold_RejectsTooHigh() public {
        P256Account acct = _deploy();
        vm.prank(ENTRYPOINT);
        vm.expectRevert(abi.encodeWithSelector(P256Account.ThresholdTooHigh.selector, 1, 0));
        acct.setRecoveryThreshold(1);
    }

    function test_Recover_RejectsWhenDisabled() public {
        P256Account acct = _deploy();
        P256Account.GuardianAssertion[] memory a = new P256Account.GuardianAssertion[](0);
        vm.expectRevert(P256Account.RecoveryDisabled.selector);
        acct.recover(NEWCRED, PUBX, PUBY, RPID, a);
    }

    function test_Recover_RotatesAndInvalidatesOld() public {
        P256Account acct = _deploy();
        vm.startPrank(ENTRYPOINT);
        acct.addGuardian(GCRED, PUBX, PUBY, RPID);
        acct.setRecoveryThreshold(1);
        vm.stopPrank();

        k11.setResult(true); // guardian assertion verifies
        P256Account.GuardianAssertion[] memory a = new P256Account.GuardianAssertion[](1);
        a[0] = _gAssertion(GCRED);
        acct.recover(NEWCRED, PUBX, PUBY, RPID, a); // permissionless submit

        assertEq(acct.signerGeneration(), 1);
        assertEq(acct.activeSignerCount(), 1);
        // new signer validates; the old one is invalidated by the generation bump
        vm.prank(ENTRYPOINT);
        assertEq(acct.validateUserOp(_op(NEWCRED), bytes32(uint256(1)), 0), 0, "new signer live");
        vm.prank(ENTRYPOINT);
        assertEq(acct.validateUserOp(_op(CRED), bytes32(uint256(1)), 0), 1, "old signer dead");
    }

    function test_Recover_RejectsBelowThreshold() public {
        P256Account acct = _deploy();
        vm.startPrank(ENTRYPOINT);
        acct.addGuardian(GCRED, PUBX, PUBY, RPID);
        acct.addGuardian(GCRED2, PUBX, PUBY, RPID);
        acct.setRecoveryThreshold(2);
        vm.stopPrank();
        P256Account.GuardianAssertion[] memory a = new P256Account.GuardianAssertion[](1);
        a[0] = _gAssertion(GCRED);
        vm.expectRevert(abi.encodeWithSelector(P256Account.InsufficientGuardians.selector, 1, 2));
        acct.recover(NEWCRED, PUBX, PUBY, RPID, a);
    }

    function test_Recover_RejectsDuplicateGuardian() public {
        P256Account acct = _deploy();
        vm.startPrank(ENTRYPOINT);
        acct.addGuardian(GCRED, PUBX, PUBY, RPID);
        acct.setRecoveryThreshold(1);
        vm.stopPrank();
        k11.setResult(true);
        P256Account.GuardianAssertion[] memory a = new P256Account.GuardianAssertion[](2);
        a[0] = _gAssertion(GCRED);
        a[1] = _gAssertion(GCRED);
        vm.expectRevert(abi.encodeWithSelector(P256Account.DuplicateGuardian.selector, GCRED));
        acct.recover(NEWCRED, PUBX, PUBY, RPID, a);
    }

    // codex #3: the same physical key registered under two credIds must not satisfy
    // an M>=2 quorum — recover() dedups by (pubX,pubY), not just credIdHash.
    function test_Recover_RejectsDuplicateGuardianPubkey() public {
        P256Account acct = _deploy();
        vm.startPrank(ENTRYPOINT);
        acct.addGuardian(GCRED, PUBX, PUBY, RPID);
        acct.addGuardian(GCRED2, PUBX, PUBY, RPID); // distinct credId, SAME physical key
        acct.setRecoveryThreshold(2);
        vm.stopPrank();
        k11.setResult(true);
        P256Account.GuardianAssertion[] memory a = new P256Account.GuardianAssertion[](2);
        a[0] = _gAssertion(GCRED);
        a[1] = _gAssertion(GCRED2);
        vm.expectRevert(abi.encodeWithSelector(P256Account.DuplicateGuardian.selector, GCRED2));
        acct.recover(NEWCRED, PUBX, PUBY, RPID, a);
    }
}
