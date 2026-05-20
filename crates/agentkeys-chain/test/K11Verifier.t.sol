// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {P256Verifier} from "../src/P256Verifier.sol";
import {K11Verifier} from "../src/K11Verifier.sol";

/// @title K11VerifierTest — smoke tests for challenge-binding + WebAuthn
///        envelope checks (rpIdHash, UP|UV flags, type prefix).
contract K11VerifierTest is Test {
    K11Verifier verifier;

    /// Test fixtures used across the suite. authData has the right layout so
    /// each test only changes the bit it's exercising.
    bytes32 constant RP_ID_HASH = keccak256("localhost");
    uint8 constant FLAGS_OK = 0x05; // UP=0x01 | UV=0x04

    function setUp() public {
        P256Verifier p256 = new P256Verifier();
        verifier = new K11Verifier(address(p256));
    }

    /// Build a 37-byte authData with the right rpIdHash + flags + zero counter.
    function _authData(bytes32 rpIdHash, uint8 flags) internal pure returns (bytes memory) {
        bytes memory ad = new bytes(37);
        for (uint256 i = 0; i < 32; ++i) ad[i] = rpIdHash[i];
        ad[32] = bytes1(flags);
        // bytes 33..37 = sign count (zero)
        return ad;
    }

    function test_challenge_mismatch_reverts() public {
        bytes32 expectedChallenge = keccak256("op:1");
        bytes memory authData = _authData(RP_ID_HASH, FLAGS_OK);
        string memory wrongJSON =
            '{"type":"webauthn.get","challenge":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz","origin":"https://localhost"}';
        uint256 challengeLocation = 36;

        vm.expectRevert(K11Verifier.ChallengeMismatch.selector);
        verifier.verifyAssertion(
            expectedChallenge, RP_ID_HASH, authData, bytes(wrongJSON),
            challengeLocation, 1, 1, 1, 1
        );
    }

    function test_short_authData_reverts() public {
        bytes32 expectedChallenge = keccak256("op:1");
        bytes memory shortAuthData = new bytes(36);
        string memory json =
            '{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"https://localhost"}';
        vm.expectRevert(K11Verifier.MalformedAuthenticatorData.selector);
        verifier.verifyAssertion(
            expectedChallenge, RP_ID_HASH, shortAuthData, bytes(json), 36, 1, 1, 1, 1
        );
    }

    function test_clientDataJSON_too_short_reverts() public {
        bytes32 expectedChallenge = keccak256("op:1");
        bytes memory authData = _authData(RP_ID_HASH, FLAGS_OK);
        string memory tooShort = "0123456789";
        vm.expectRevert(K11Verifier.MalformedClientDataJSON.selector);
        verifier.verifyAssertion(
            expectedChallenge, RP_ID_HASH, authData, bytes(tooShort), 0, 1, 1, 1, 1
        );
    }

    function test_rpIdHash_mismatch_reverts() public {
        bytes32 expectedChallenge = bytes32(0);
        // authData has rpIdHash = sha256("evil.localhost") (wrong)
        bytes memory authData = _authData(keccak256("evil.localhost"), FLAGS_OK);
        string memory goodJSON =
            '{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"https://localhost"}';
        vm.expectRevert(K11Verifier.RpIdHashMismatch.selector);
        verifier.verifyAssertion(
            expectedChallenge, RP_ID_HASH, authData, bytes(goodJSON), 36, 1, 1, 1, 1
        );
    }

    function test_missing_user_presence_reverts() public {
        bytes32 expectedChallenge = bytes32(0);
        // authData has rpIdHash OK but flags=0 (no UP, no UV)
        bytes memory authData = _authData(RP_ID_HASH, 0x00);
        string memory goodJSON =
            '{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"https://localhost"}';
        vm.expectRevert(K11Verifier.UserPresenceMissing.selector);
        verifier.verifyAssertion(
            expectedChallenge, RP_ID_HASH, authData, bytes(goodJSON), 36, 1, 1, 1, 1
        );

        // UP only (no UV) still reverts.
        authData = _authData(RP_ID_HASH, 0x01);
        vm.expectRevert(K11Verifier.UserPresenceMissing.selector);
        verifier.verifyAssertion(
            expectedChallenge, RP_ID_HASH, authData, bytes(goodJSON), 36, 1, 1, 1, 1
        );
    }

    function test_wrong_clientData_type_reverts() public {
        bytes32 expectedChallenge = bytes32(0);
        bytes memory authData = _authData(RP_ID_HASH, FLAGS_OK);
        // type = webauthn.create (enrollment) → should be rejected when used
        // for assertion verification (replay-across-mode attack).
        string memory createJSON =
            '{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"https://localhost"}';
        vm.expectRevert(K11Verifier.WrongClientDataType.selector);
        verifier.verifyAssertion(
            expectedChallenge, RP_ID_HASH, authData, bytes(createJSON), 39, 1, 1, 1, 1
        );
    }

    function test_readSignCount() public view {
        bytes memory authData = _authData(RP_ID_HASH, FLAGS_OK);
        authData[33] = 0x12;
        authData[34] = 0x34;
        authData[35] = 0x56;
        authData[36] = 0x78;
        uint32 count = verifier.readSignCount(authData);
        assertEq(count, 0x12345678);
    }

    function test_readSignCount_zero() public view {
        bytes memory authData = new bytes(37);
        uint32 count = verifier.readSignCount(authData);
        assertEq(count, 0);
    }

    function test_base64_encoding_of_zero_challenge() public {
        // All-zero challenge → 43 'A's in base64url. All envelope checks
        // pass; P-256 verify returns false on bogus r/s/pubkey.
        bytes32 expectedChallenge = bytes32(0);
        bytes memory authData = _authData(RP_ID_HASH, FLAGS_OK);
        string memory goodJSON =
            '{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"https://localhost"}';
        uint256 challengeLocation = 36;
        bool ok = verifier.verifyAssertion(
            expectedChallenge, RP_ID_HASH, authData, bytes(goodJSON),
            challengeLocation, 1, 1, 1, 1
        );
        assertFalse(ok);
    }
}
