// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

/// @title P256Verifier — pure-Solidity NIST P-256 ECDSA signature verifier
/// @notice Verifies WebAuthn / FIDO2 authenticator (K11) assertions on chain
///         until Heima ships an EIP-7212 / RIP-7212 P-256 precompile.
///
/// @dev    Heima is at London EVM level (verified 2026-05-19: mixHash=null,
///         withdrawalsRoot=null, blobGasUsed=null) — no native P-256
///         precompile at 0x100 or 0x0b. This contract performs the verify
///         in pure Solidity using Jacobian coordinates + Shamir's trick
///         double-scalar multiplication. Roughly ~700k gas per verify;
///         acceptable because K11 mutations are master-only and rare
///         (scope grant/revoke, multi-master pairing, recovery). Per-call
///         hot paths (broker cap-mint, worker cap-verify) never invoke this.
///
///         Algorithm reference: standard ECDSA verify with:
///           1. Validate r,s ∈ [1, n-1] and (Qx, Qy) on curve.
///           2. e = msgHash mod n
///           3. sInv = s^-1 mod n
///           4. u1 = e * sInv mod n;  u2 = r * sInv mod n
///           5. R' = u1*G + u2*Q (Shamir's trick; Jacobian)
///           6. Return R'.x mod n == r
///
///         Jacobian formulas: dbl-2001-b and add-2007-bl from EFD
///         (https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html).
///
///         The caller (CLI) pre-extracts (r, s, msgHash, pubX, pubY) from the
///         raw WebAuthn assertion (authData || sha256(clientDataJSON)) and
///         submits the 5 cleaned values. On-chain CBOR/JSON parsing was
///         rejected (option 1 of the design Q): the CLI already has webauthn
///         parsing for the client-side ceremony — re-running it in Solidity
///         would add ~3M gas and ~500 lines of unaudited parser code.
contract P256Verifier {
    // ─── NIST P-256 (secp256r1) curve parameters ─────────────────────────
    /// @notice Field prime: 2^256 - 2^224 + 2^192 + 2^96 - 1
    uint256 internal constant P =
        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
    /// @notice Curve order
    uint256 internal constant N =
        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
    /// @notice Curve constant b (a = -3, implicit in dbl-2001-b)
    uint256 internal constant B =
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b;
    /// @notice Generator G.x
    uint256 internal constant GX =
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296;
    /// @notice Generator G.y
    uint256 internal constant GY =
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5;

    /// @notice Verify a P-256 ECDSA signature.
    /// @param msgHash 32-byte hash the authenticator signed (typically
    ///                sha256(authData || sha256(clientDataJSON))).
    /// @param r       ECDSA r component.
    /// @param s       ECDSA s component.
    /// @param pubX    Public key X coordinate.
    /// @param pubY    Public key Y coordinate.
    /// @return valid  True iff signature verifies under (pubX, pubY).
    function verify(bytes32 msgHash, uint256 r, uint256 s, uint256 pubX, uint256 pubY)
        external
        view
        returns (bool valid)
    {
        // Range checks per FIPS 186-5 6.4.2.
        if (r == 0 || r >= N) return false;
        if (s == 0 || s >= N) return false;
        if (pubX >= P || pubY >= P) return false;
        if (pubX == 0 && pubY == 0) return false; // disallow point at infinity
        if (!_onCurve(pubX, pubY)) return false;

        uint256 e = uint256(msgHash) % N;
        uint256 sInv = _modInverse(s, N);
        uint256 u1 = mulmod(e, sInv, N);
        uint256 u2 = mulmod(r, sInv, N);

        (uint256 rx, bool isInf) = _doubleScalarMul(u1, u2, pubX, pubY);
        if (isInf) return false;
        return rx % N == r;
    }

    /// @dev On-curve check: y² ≡ x³ - 3x + b  (mod p).
    function _onCurve(uint256 x, uint256 y) internal pure returns (bool) {
        uint256 lhs = mulmod(y, y, P);
        uint256 x3 = mulmod(mulmod(x, x, P), x, P);
        uint256 threeX = mulmod(3, x, P);
        // rhs = x³ - 3x + b  (mod p)
        uint256 rhs = addmod(addmod(x3, P - threeX, P), B, P);
        return lhs == rhs;
    }

    /// @dev Modular inverse via Fermat's little theorem (m prime) using
    ///      the modexp precompile at address 0x05.
    function _modInverse(uint256 x, uint256 m) internal view returns (uint256 result) {
        uint256 fermatExp = m - 2;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x20) // base length
            mstore(add(ptr, 0x20), 0x20) // exp length
            mstore(add(ptr, 0x40), 0x20) // mod length
            mstore(add(ptr, 0x60), x)
            mstore(add(ptr, 0x80), fermatExp)
            mstore(add(ptr, 0xa0), m)
            if iszero(staticcall(gas(), 0x05, ptr, 0xc0, ptr, 0x20)) { revert(0, 0) }
            result := mload(ptr)
        }
    }

    /// @dev Jacobian point doubling on y² = x³ - 3x + b (a = -3).
    ///      Formula dbl-2001-b: 4M + 4S + 8add. Returns (0,0,0) for ∞.
    function _jacDouble(uint256 x1, uint256 y1, uint256 z1)
        internal
        pure
        returns (uint256 x3, uint256 y3, uint256 z3)
    {
        if (z1 == 0) return (0, 0, 0);
        uint256 delta = mulmod(z1, z1, P);
        uint256 gamma = mulmod(y1, y1, P);
        uint256 beta = mulmod(x1, gamma, P);
        uint256 alpha =
            mulmod(3, mulmod(addmod(x1, P - delta, P), addmod(x1, delta, P), P), P);
        x3 = addmod(mulmod(alpha, alpha, P), P - mulmod(8, beta, P), P);
        uint256 yz = addmod(y1, z1, P);
        z3 = addmod(mulmod(yz, yz, P), P - addmod(gamma, delta, P), P);
        uint256 fourBetaMinusX3 = addmod(mulmod(4, beta, P), P - x3, P);
        y3 = addmod(
            mulmod(alpha, fourBetaMinusX3, P), P - mulmod(8, mulmod(gamma, gamma, P), P), P
        );
    }

    /// @dev Jacobian + Jacobian addition. Formula add-2007-bl: 11M + 5S + 9add.
    ///      Handles the P + (-P) = ∞ case explicitly, and delegates to doubling
    ///      when both inputs are the same point.
    function _jacAdd(
        uint256 x1,
        uint256 y1,
        uint256 z1,
        uint256 x2,
        uint256 y2,
        uint256 z2
    ) internal pure returns (uint256 x3, uint256 y3, uint256 z3) {
        if (z1 == 0) return (x2, y2, z2);
        if (z2 == 0) return (x1, y1, z1);

        uint256 z1z1 = mulmod(z1, z1, P);
        uint256 z2z2 = mulmod(z2, z2, P);
        uint256 u1 = mulmod(x1, z2z2, P);
        uint256 u2 = mulmod(x2, z1z1, P);
        uint256 s1 = mulmod(mulmod(y1, z2, P), z2z2, P);
        uint256 s2 = mulmod(mulmod(y2, z1, P), z1z1, P);

        if (u1 == u2) {
            if (s1 != s2) return (0, 0, 0); // P + (-P) = ∞
            return _jacDouble(x1, y1, z1);
        }

        uint256 h = addmod(u2, P - u1, P);
        uint256 i = mulmod(mulmod(2, h, P), mulmod(2, h, P), P);
        uint256 j = mulmod(h, i, P);
        uint256 r = mulmod(2, addmod(s2, P - s1, P), P);
        uint256 v = mulmod(u1, i, P);
        x3 = addmod(addmod(mulmod(r, r, P), P - j, P), P - mulmod(2, v, P), P);
        y3 = addmod(
            mulmod(r, addmod(v, P - x3, P), P), P - mulmod(2, mulmod(s1, j, P), P), P
        );
        uint256 z1z2 = addmod(z1, z2, P);
        z3 = mulmod(
            addmod(mulmod(z1z2, z1z2, P), P - addmod(z1z1, z2z2, P), P), h, P
        );
    }

    /// @dev Convert a Jacobian X coordinate back to affine.
    ///      affine.x = jac.x / z² mod p.
    function _jacToAffineX(uint256 x, uint256 z) internal view returns (uint256) {
        uint256 zInv = _modInverse(z, P);
        return mulmod(x, mulmod(zInv, zInv, P), P);
    }

    /// @dev Compute u1*G + u2*Q via Shamir's trick (process both scalars
    ///      simultaneously, sharing doublings). Precomputed table:
    ///        idx=0 (b1=0,b2=0): no-op
    ///        idx=1 (b1=0,b2=1): add Q
    ///        idx=2 (b1=1,b2=0): add G
    ///        idx=3 (b1=1,b2=1): add G+Q
    function _doubleScalarMul(uint256 k1, uint256 k2, uint256 qx, uint256 qy)
        internal
        view
        returns (uint256 affineX, bool isInfinity)
    {
        // Precompute G+Q once.
        (uint256 sumX, uint256 sumY, uint256 sumZ) = _jacAdd(GX, GY, 1, qx, qy, 1);

        // Accumulator starts at ∞.
        uint256 x = 0;
        uint256 y = 0;
        uint256 z = 0;

        for (uint256 i = 0; i < 256; ++i) {
            (x, y, z) = _jacDouble(x, y, z);
            uint256 b1 = (k1 >> (255 - i)) & 1;
            uint256 b2 = (k2 >> (255 - i)) & 1;
            uint256 idx = (b1 << 1) | b2;
            if (idx == 1) {
                (x, y, z) = _jacAdd(x, y, z, qx, qy, 1);
            } else if (idx == 2) {
                (x, y, z) = _jacAdd(x, y, z, GX, GY, 1);
            } else if (idx == 3) {
                (x, y, z) = _jacAdd(x, y, z, sumX, sumY, sumZ);
            }
        }

        if (z == 0) return (0, true);
        return (_jacToAffineX(x, z), false);
    }
}
