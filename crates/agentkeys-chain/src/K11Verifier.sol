// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {P256Verifier} from "./P256Verifier.sol";

/// @title K11Verifier — WebAuthn-aware on-chain assertion verifier
/// @notice Verifies a WebAuthn navigator.credentials.get() assertion ON CHAIN
///         by binding the authenticator's signature to an expected challenge
///         (computed from the operation params + per-operator nonce) and
///         calling the pure-Solidity P-256 verifier.
///
/// @dev    Standard WebAuthn signs `sha256(authData || sha256(clientDataJSON))`
///         where `clientDataJSON.challenge = base64url(our_challenge)`.
///
///         On-chain flow:
///           1. Caller computes the expected 32-byte challenge from the
///              operation context (e.g. `keccak256("agentkeys:device-revoke" ||
///              operator_omni || target || chainid || nonce)`).
///           2. CLI invokes WebAuthn with `challenge = our_challenge`; receives
///              `authenticatorData`, `clientDataJSON`, `r`, `s`.
///           3. CLI submits to chain: (authData, clientDataJSON, challengeLocation,
///              r, s) plus the operation params.
///           4. Contract computes `expectedB64 = base64url(our_challenge)` (43 chars,
///              no padding — WebAuthn spec).
///           5. Contract reads `clientDataJSON[challengeLocation..+43]` and compares
///              to `expectedB64`. Since K11 sig commits to the full clientDataJSON
///              via the inner sha256, the attacker cannot lie about the substring
///              while keeping the sig valid.
///           6. Contract computes `msgHash = sha256(authData || sha256(clientDataJSON))`
///              and calls `P256Verifier.verify(...)`.
///
///         Anti-replay: the challenge commits to a per-operator monotonic nonce
///         (`SidecarRegistry.operatorNonce[op]`). Contract increments the nonce
///         after each successful master mutation, so captured K11 sigs from a
///         previous tx don't validate.
///
///         This is the daimo-style pattern (cf. https://github.com/daimo-eth/p256-verifier),
///         minus the wider "WebAuthn options" surface — we only support the
///         fixed-shape challenge binding.
contract K11Verifier {
    P256Verifier public immutable p256;

    /// @notice Length of base64url-encoded 32-byte challenge (no padding).
    uint256 internal constant CHALLENGE_B64_LEN = 43;

    /// @notice authData flag bits (per WebAuthn spec).
    uint8 internal constant FLAG_UP = 0x01; // User Present
    uint8 internal constant FLAG_UV = 0x04; // User Verified

    /// @notice Bytes 1..21 of a canonical webauthn.get clientDataJSON:
    ///         `"type":"webauthn.get"` — used as a prefix-anchor for the
    ///         on-chain type check. The opening `{` is byte 0; this string
    ///         starts at byte 1. We compare byte-by-byte to reject
    ///         `webauthn.create` assertions being replayed as `.get`.
    bytes internal constant TYPE_FIELD_WEBAUTHN_GET =
        bytes('"type":"webauthn.get"');

    error ChallengeMismatch();
    error MalformedAuthenticatorData();
    error MalformedClientDataJSON();
    error RpIdHashMismatch();
    error UserPresenceMissing();
    error WrongClientDataType();

    constructor(address p256Addr) {
        p256 = P256Verifier(p256Addr);
    }

    /// @notice Verify a WebAuthn assertion is valid + bound to expectedChallenge.
    /// @param expectedChallenge 32-byte hash the caller wants K11 to commit to
    ///        (operation context + nonce). MUST be reconstructable by the contract
    ///        from operation params so the caller cannot lie.
    /// @param authenticatorData  Raw 37+ bytes from the authenticator.
    /// @param clientDataJSON     Raw JSON string from the authenticator.
    /// @param challengeLocation  Byte offset in clientDataJSON where the
    ///        base64url-encoded challenge value starts.
    /// @param r,s                ECDSA signature.
    /// @param pubX,pubY          P-256 public key for the credential.
    function verifyAssertion(
        bytes32 expectedChallenge,
        bytes32 expectedRpIdHash,
        bytes calldata authenticatorData,
        bytes calldata clientDataJSON,
        uint256 challengeLocation,
        uint256 r,
        uint256 s,
        uint256 pubX,
        uint256 pubY
    ) external view returns (bool) {
        if (authenticatorData.length < 37) revert MalformedAuthenticatorData();
        // clientDataJSON must hold at least: `{"type":"webauthn.get","challenge":"<43>"`.
        // That's 1 (opening `{`) + 21 (TYPE_FIELD_WEBAUTHN_GET) + 1 (`,`) +
        // 14 (`"challenge":"`) + 43 (challenge) = 80 bytes minimum.
        if (clientDataJSON.length < 80) revert MalformedClientDataJSON();
        if (challengeLocation + CHALLENGE_B64_LEN > clientDataJSON.length) {
            revert MalformedClientDataJSON();
        }

        // Codex H1 step A: authData[0:32] must equal expectedRpIdHash.
        // Without this, an assertion signed under a different RP (e.g.
        // attacker-controlled `evil.localhost`) could pass as `localhost`.
        for (uint256 i = 0; i < 32; ++i) {
            if (authenticatorData[i] != expectedRpIdHash[i]) revert RpIdHashMismatch();
        }

        // Codex H1 step B: authData[32] flags must include UP (user-present)
        // and UV (user-verified). Otherwise a stolen K11 device without
        // biometric/PIN proof could mint assertions silently.
        uint8 flags = uint8(authenticatorData[32]);
        if ((flags & (FLAG_UP | FLAG_UV)) != (FLAG_UP | FLAG_UV)) revert UserPresenceMissing();

        // Codex H1 step C: clientDataJSON must start with `{"type":"webauthn.get"`.
        // Rejects `webauthn.create` (enrollment) assertions being replayed
        // as `.get` (authentication). Byte 0 is `{`; the type field begins
        // at byte 1.
        bytes memory expectedType = TYPE_FIELD_WEBAUTHN_GET;
        for (uint256 i = 0; i < expectedType.length; ++i) {
            if (clientDataJSON[i + 1] != expectedType[i]) revert WrongClientDataType();
        }

        // Step 1: encode expectedChallenge to base64url (43 chars, no padding).
        bytes memory expectedB64 = _base64UrlEncode32(expectedChallenge);

        // Step 2: compare to clientDataJSON[challengeLocation..+43].
        for (uint256 i = 0; i < CHALLENGE_B64_LEN; ++i) {
            if (clientDataJSON[challengeLocation + i] != expectedB64[i]) {
                revert ChallengeMismatch();
            }
        }

        // Step 3: compute msgHash = sha256(authData || sha256(clientDataJSON))
        bytes32 cdjHash = sha256(clientDataJSON);
        bytes32 msgHash = sha256(abi.encodePacked(authenticatorData, cdjHash));

        // Step 4: P-256 verify.
        return p256.verify(msgHash, r, s, pubX, pubY);
    }

    /// @notice Extract the 4-byte signCount (big-endian) from authenticatorData.
    /// @dev    authData layout: rpIdHash(32) || flags(1) || signCount(4) || ...
    function readSignCount(bytes calldata authenticatorData)
        external
        pure
        returns (uint32)
    {
        if (authenticatorData.length < 37) revert MalformedAuthenticatorData();
        return uint32(bytes4(authenticatorData[33:37]));
    }

    /// @dev Encode 32 bytes → 43-char base64url (no padding) per RFC 4648 §5.
    function _base64UrlEncode32(bytes32 input) internal pure returns (bytes memory) {
        bytes memory alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        bytes memory out = new bytes(CHALLENGE_B64_LEN);

        // Process 30 bytes in 10 groups of 3 bytes → 4 chars each = 40 chars.
        for (uint256 g = 0; g < 10; ++g) {
            uint256 i = g * 3;
            uint256 b0 = uint256(uint8(input[i]));
            uint256 b1 = uint256(uint8(input[i + 1]));
            uint256 b2 = uint256(uint8(input[i + 2]));
            uint256 o = g * 4;
            out[o] = alphabet[b0 >> 2];
            out[o + 1] = alphabet[((b0 & 0x3) << 4) | (b1 >> 4)];
            out[o + 2] = alphabet[((b1 & 0xf) << 2) | (b2 >> 6)];
            out[o + 3] = alphabet[b2 & 0x3f];
        }

        // Remaining 2 bytes (index 30, 31) → 3 chars (43 total).
        uint256 b30 = uint256(uint8(input[30]));
        uint256 b31 = uint256(uint8(input[31]));
        out[40] = alphabet[b30 >> 2];
        out[41] = alphabet[((b30 & 0x3) << 4) | (b31 >> 4)];
        out[42] = alphabet[(b31 & 0xf) << 2];

        return out;
    }
}
