// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import { P256Verifier } from "./P256Verifier.sol";

/// @title P256Router — precompile-first P-256 verifier with pure-Solidity fallback
/// @notice ABI-compatible with [P256Verifier.verify]. Tries the RIP-7212 / EIP-7951
///         `P256VERIFY` precompile at address 0x…0100 first (flat 3450 gas — live on
///         Base since Fjord, Ethereum L1 since Fusaka, and on Heima since runtime
///         9261, litentry/heima#4030, activated 2026-06-12). Falls back to the
///         embedded pure-Solidity verifier whenever the precompile gives no
///         affirmative answer.
///
/// @dev    RIP-7212 returns EMPTY output both for "invalid signature" and (trivially,
///         as a call to an empty account) for "precompile not present" — the two are
///         indistinguishable by design. The router therefore treats anything other
///         than a 32-byte uint256(1) as "not proven valid" and re-verifies in
///         Solidity. Consequences:
///         - chains WITH the precompile: valid sigs cost ~3.45k gas; INVALID sigs pay
///           the fallback (~700k) before returning false — same outcome, gas only.
///         - chains WITHOUT it (Heima today): every call falls back — identical
///           behaviour to calling P256Verifier directly.
///         - the SAME deployment auto-flips to the cheap path the moment a runtime
///           upgrade activates the precompile (issue #170) — no redeploy needed.
///
///         Wired as `K11Verifier`'s `p256Addr` constructor arg by
///         `script/DeployAgentKeysV1.s.sol`; every WebAuthn verify (registry
///         mutations, P256Account UserOp validation) routes through here.
contract P256Router {
    /// @dev RIP-7212 / EIP-7951 standard precompile address.
    address private constant P256VERIFY = address(0x100);

    /// @notice The pure-Solidity verifier used when the precompile is absent
    ///         or answers non-affirmatively.
    P256Verifier public immutable fallbackVerifier;

    error ZeroFallbackVerifier();

    constructor(address fallbackVerifierAddr) {
        if (fallbackVerifierAddr == address(0)) revert ZeroFallbackVerifier();
        fallbackVerifier = P256Verifier(fallbackVerifierAddr);
    }

    /// @notice Verify a P-256 (secp256r1) ECDSA signature over `msgHash`.
    ///         Same signature + semantics as [P256Verifier.verify] (low-s NOT
    ///         enforced, per FIPS-186-5 / WebAuthn).
    function verify(bytes32 msgHash, uint256 r, uint256 s, uint256 pubX, uint256 pubY)
        external
        view
        returns (bool valid)
    {
        (bool callOk, bytes memory ret) =
            P256VERIFY.staticcall(abi.encodePacked(msgHash, r, s, pubX, pubY));
        if (callOk && ret.length == 32 && abi.decode(ret, (uint256)) == 1) {
            return true;
        }
        return fallbackVerifier.verify(msgHash, r, s, pubX, pubY);
    }
}
