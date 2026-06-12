// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { P256Verifier } from "../src/P256Verifier.sol";
import { P256Router } from "../src/P256Router.sol";

/// P256Router routing semantics. The local forge EVM (evm_version=london, no
/// RIP-7212) has NO code at 0x100, so the bare-router tests exercise the
/// fallback path; the precompile-present paths are simulated by vm.etch-ing
/// minimal stubs at 0x100 (always-return-1 / always-return-empty).
contract P256RouterTest is Test {
    address private constant P256VERIFY = address(0x100);

    // PUSH1 1, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN → always uint256(1)
    bytes private constant STUB_ALWAYS_VALID = hex"600160005260206000f3";
    // PUSH1 0, PUSH1 0, RETURN → always empty success (RIP-7212 "invalid" shape)
    bytes private constant STUB_ALWAYS_EMPTY = hex"60006000f3";

    P256Verifier private fallbackVerifier;
    P256Router private router;

    // Known-good vector (same as P256Verifier.t.sol).
    bytes32 private constant MSG_HASH =
        0xaf2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf;
    uint256 private constant PUB_X =
        0x60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6;
    uint256 private constant PUB_Y =
        0x7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299;
    uint256 private constant SIG_R =
        0xefd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716;
    uint256 private constant SIG_S =
        0xf7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8;

    function setUp() public {
        fallbackVerifier = new P256Verifier();
        router = new P256Router(address(fallbackVerifier));
    }

    function test_constructor_rejects_zero_fallback() public {
        vm.expectRevert(P256Router.ZeroFallbackVerifier.selector);
        new P256Router(address(0));
    }

    function test_no_precompile_valid_sig_verifies_via_fallback() public view {
        assertEq(address(P256VERIFY).code.length, 0, "test EVM must have no 0x100 code");
        assertTrue(router.verify(MSG_HASH, SIG_R, SIG_S, PUB_X, PUB_Y));
    }

    function test_no_precompile_invalid_sig_rejected_via_fallback() public view {
        bytes32 tampered = bytes32(uint256(MSG_HASH) ^ 1);
        assertFalse(router.verify(tampered, SIG_R, SIG_S, PUB_X, PUB_Y));
    }

    function test_precompile_affirmative_short_circuits() public {
        vm.etch(P256VERIFY, STUB_ALWAYS_VALID);
        // Deliberately INVALID sig: the fallback would reject it, so a `true`
        // here proves the precompile answer won (real chains run an honest
        // implementation at 0x100; the stub isolates the routing logic).
        bytes32 tampered = bytes32(uint256(MSG_HASH) ^ 1);
        assertTrue(router.verify(tampered, SIG_R, SIG_S, PUB_X, PUB_Y));
    }

    function test_precompile_empty_answer_falls_back_valid() public {
        vm.etch(P256VERIFY, STUB_ALWAYS_EMPTY);
        assertTrue(router.verify(MSG_HASH, SIG_R, SIG_S, PUB_X, PUB_Y));
    }

    function test_precompile_empty_answer_falls_back_invalid() public {
        vm.etch(P256VERIFY, STUB_ALWAYS_EMPTY);
        bytes32 tampered = bytes32(uint256(MSG_HASH) ^ 1);
        assertFalse(router.verify(tampered, SIG_R, SIG_S, PUB_X, PUB_Y));
    }
}
