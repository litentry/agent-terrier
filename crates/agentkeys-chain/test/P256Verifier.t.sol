// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {P256Verifier} from "../src/P256Verifier.sol";

/// @title P256VerifierTest — cross-check against known good test vectors.
/// @dev Test vectors are from RFC 6979 §A.2.5 (P-256 / SHA-256, msg="sample")
///      and a synthetic "test" vector (msg="test"). Both are deterministic
///      ECDSA so r/s match across implementations.
contract P256VerifierTest is Test {
    P256Verifier verifier;

    function setUp() public {
        verifier = new P256Verifier();
    }

    // ─── RFC 6979 §A.2.5 — P-256 / SHA-256 — msg = "sample" ──────────────
    // Private key: c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721
    function test_verify_rfc6979_sample() public view {
        bytes32 msgHash = 0xaf2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf;
        uint256 pubX = 0x60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6;
        uint256 pubY = 0x7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299;
        uint256 r = 0xefd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716;
        uint256 s = 0xf7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8;
        assertTrue(verifier.verify(msgHash, r, s, pubX, pubY), "RFC 6979 sample should verify");
    }

    // ─── RFC 6979 §A.2.5 — P-256 / SHA-256 — msg = "test" ────────────────
    function test_verify_rfc6979_test() public view {
        bytes32 msgHash = 0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08;
        uint256 pubX = 0x60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6;
        uint256 pubY = 0x7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299;
        uint256 r = 0xf1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367;
        uint256 s = 0x019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083;
        assertTrue(verifier.verify(msgHash, r, s, pubX, pubY), "RFC 6979 test should verify");
    }

    // ─── Mutation rejections ─────────────────────────────────────────────
    function test_verify_rejects_tampered_msg() public view {
        bytes32 msgHash = 0xaf2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf;
        uint256 pubX = 0x60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6;
        uint256 pubY = 0x7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299;
        uint256 r = 0xefd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716;
        uint256 s = 0xf7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8;

        // Flip a byte in msgHash → must fail.
        bytes32 tampered = bytes32(uint256(msgHash) ^ uint256(0x1));
        assertFalse(verifier.verify(tampered, r, s, pubX, pubY));
    }

    function test_verify_rejects_zero_r() public view {
        bytes32 msgHash = bytes32(uint256(1));
        uint256 pubX = 0x60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6;
        uint256 pubY = 0x7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299;
        assertFalse(verifier.verify(msgHash, 0, 1, pubX, pubY));
    }

    function test_verify_rejects_zero_s() public view {
        bytes32 msgHash = bytes32(uint256(1));
        uint256 pubX = 0x60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6;
        uint256 pubY = 0x7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299;
        assertFalse(verifier.verify(msgHash, 1, 0, pubX, pubY));
    }

    function test_verify_rejects_pubkey_not_on_curve() public view {
        bytes32 msgHash = bytes32(uint256(1));
        // pubX changed by 1 — definitely off-curve.
        uint256 pubX = 0x60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb7;
        uint256 pubY = 0x7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299;
        assertFalse(verifier.verify(msgHash, 1, 1, pubX, pubY));
    }

    function test_verify_rejects_point_at_infinity() public view {
        assertFalse(verifier.verify(bytes32(uint256(1)), 1, 1, 0, 0));
    }

    // ─── Gas measurement ─────────────────────────────────────────────────
    function test_gas_singleVerify() public view {
        bytes32 msgHash = 0xaf2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf;
        uint256 pubX = 0x60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6;
        uint256 pubY = 0x7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299;
        uint256 r = 0xefd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716;
        uint256 s = 0xf7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8;

        uint256 gasBefore = gasleft();
        bool ok = verifier.verify(msgHash, r, s, pubX, pubY);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("P256 verify gas:", gasUsed);
        assertTrue(ok);
        // London EVM block gas limit is ~30M; we want comfortably under that.
        assertLt(gasUsed, 2_000_000, "verify must fit under 2M gas");
    }
}
