// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VerifyingPaymaster} from "../src/VerifyingPaymaster.sol";
import {PackedUserOperation} from "../src/IERC4337.sol";

contract VerifyingPaymasterTest is Test {
    address constant ENTRYPOINT = address(0xE427);
    VerifyingPaymaster pm;

    uint256 brokerPk = 0xB0B;
    address broker;
    address owner = address(0xABCD);

    uint48 constant VALID_UNTIL = 4_000_000_000;
    uint48 constant VALID_AFTER = 0;

    function setUp() public {
        broker = vm.addr(brokerPk);
        pm = new VerifyingPaymaster(ENTRYPOINT, broker, owner);
    }

    function _op() internal pure returns (PackedUserOperation memory op) {
        op.sender = address(0xACC7);
        op.nonce = 1;
        op.callData = hex"deadbeef";
        op.accountGasLimits = bytes32(uint256(1));
        op.preVerificationGas = 50_000;
        op.gasFees = bytes32(uint256(2));
    }

    uint128 constant PM_VER_GAS = 1_000_000;
    uint128 constant PM_POST_GAS = 50_000;

    function _sign(uint256 pk, PackedUserOperation memory op) internal view returns (bytes memory pad) {
        // getHash now binds paymasterAndData[20:52] (the gas limits), so set them
        // before hashing (placeholder 65-byte sig — getHash ignores the sig bytes).
        op.paymasterAndData = abi.encodePacked(
            address(pm), PM_VER_GAS, PM_POST_GAS, VALID_UNTIL, VALID_AFTER, new bytes(65)
        );
        bytes32 ethH = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32", pm.getHash(op, VALID_UNTIL, VALID_AFTER)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethH);
        pad = abi.encodePacked(
            address(pm), PM_VER_GAS, PM_POST_GAS, VALID_UNTIL, VALID_AFTER, abi.encodePacked(r, s, v)
        );
    }

    function test_ValidSponsorship() public {
        PackedUserOperation memory op = _op();
        op.paymasterAndData = _sign(brokerPk, op);
        vm.prank(ENTRYPOINT);
        (, uint256 validationData) = pm.validatePaymasterUserOp(op, bytes32(0), 1 ether);
        assertEq(validationData & 1, 0, "broker-signed -> sponsored (sigFailed bit clear)");
        assertEq((validationData >> 160) & ((1 << 48) - 1), VALID_UNTIL, "validUntil packed");
    }

    function test_RejectsWrongSigner() public {
        PackedUserOperation memory op = _op();
        op.paymasterAndData = _sign(0xBADBAD, op); // not the broker key
        vm.prank(ENTRYPOINT);
        (, uint256 validationData) = pm.validatePaymasterUserOp(op, bytes32(0), 1 ether);
        assertEq(validationData & 1, 1, "wrong signer -> sigFailed bit set");
    }

    function test_RejectsTamperedOp() public {
        PackedUserOperation memory op = _op();
        op.paymasterAndData = _sign(brokerPk, op);
        op.callData = hex"c0ffee"; // tamper after signing → hash mismatch
        vm.prank(ENTRYPOINT);
        (, uint256 validationData) = pm.validatePaymasterUserOp(op, bytes32(0), 1 ether);
        assertEq(validationData & 1, 1, "tampered op -> sigFailed");
    }

    function test_OnlyEntryPoint() public {
        PackedUserOperation memory op = _op();
        op.paymasterAndData = _sign(brokerPk, op);
        vm.expectRevert(VerifyingPaymaster.NotEntryPoint.selector);
        pm.validatePaymasterUserOp(op, bytes32(0), 1 ether);
    }

    function test_SetBrokerSigner_OnlyOwner() public {
        vm.expectRevert(VerifyingPaymaster.NotOwner.selector);
        pm.setBrokerSigner(address(0x1234));

        vm.prank(owner);
        pm.setBrokerSigner(address(0x1234));
        assertEq(pm.brokerSigner(), address(0x1234));
    }

    function test_RejectsShortPaymasterData() public {
        PackedUserOperation memory op = _op();
        op.paymasterAndData = abi.encodePacked(address(pm), uint128(0), uint128(0)); // no vu/va/sig
        vm.prank(ENTRYPOINT);
        vm.expectRevert(VerifyingPaymaster.BadPaymasterDataLength.selector);
        pm.validatePaymasterUserOp(op, bytes32(0), 1 ether);
    }

    // codex #1: a bundler/attacker inflates the paymaster gas limits ([20:52]) while
    // reusing a valid broker signature → must be rejected (the limits are now signed).
    function test_RejectsTamperedGasLimits() public {
        PackedUserOperation memory op = _op();
        bytes memory pad = _sign(brokerPk, op); // signed over PM_VER_GAS / PM_POST_GAS
        bytes memory sig = new bytes(65);
        for (uint256 i = 0; i < 65; ++i) {
            sig[i] = pad[64 + i];
        }
        // same sig, inflated gas limits:
        op.paymasterAndData = abi.encodePacked(
            address(pm), uint128(9_000_000), uint128(9_000_000), VALID_UNTIL, VALID_AFTER, sig
        );
        vm.prank(ENTRYPOINT);
        (, uint256 vd) = pm.validatePaymasterUserOp(op, bytes32(0), 1 ether);
        assertEq(vd & 1, 1, "inflated paymaster gas limits -> sigFailed");
    }
}
