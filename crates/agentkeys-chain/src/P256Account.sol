// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {IAccount, PackedUserOperation} from "./IERC4337.sol";

/// @notice Subset of [K11Verifier] the account needs. Declared with `bytes memory`
///         so the account can pass decoded (memory) assertion bytes; the ABI
///         selector is identical to the deployed `bytes calldata` verifier.
interface IK11Verifier {
    function verifyAssertion(
        bytes32 expectedChallenge,
        bytes32 expectedRpIdHash,
        bytes memory authenticatorData,
        bytes memory clientDataJSON,
        uint256 challengeLocation,
        uint256 r,
        uint256 s,
        uint256 pubX,
        uint256 pubY
    ) external view returns (bool);
}

/// @title P256Account — ERC-4337 v0.7 master account gated by WebAuthn (K11) passkeys.
/// @notice The master authority for an operator (arch.md §6/§10), resolving #164.
///         `validateUserOp` verifies a WebAuthn assertion whose challenge **is**
///         the `userOpHash`, via the on-chain [K11Verifier]. Because `userOpHash`
///         commits the entire UserOp (callData + nonce + chainId + entryPoint),
///         the passkey signature is a provably-complete full-intent authorization
///         — no hand-rolled per-op challenge, and no secp256k1 key on any device.
/// @dev    Replay is the EntryPoint 2D nonce (no WebAuthn signCount). Multi-passkey
///         signer set + M-of-N guardian social recovery (#164 E5). The verifier
///         (P-256) is reused from the deployed K11Verifier, so no new crypto.
contract P256Account is IAccount {
    uint256 internal constant SIG_OK = 0;
    uint256 internal constant SIG_FAIL = 1;

    /// @notice Recovery challenge domain tag (guardian path is not an EntryPoint UserOp).
    bytes32 public constant OP_RECOVER = keccak256("agentkeys:v1:p256account-recover");

    struct Signer {
        uint256 pubX;
        uint256 pubY;
        bytes32 rpIdHash;
        bool active;
        uint64 generation; // a signer is live iff active && generation == signerGeneration
    }

    struct Guardian {
        uint256 pubX;
        uint256 pubY;
        bytes32 rpIdHash;
        bool active;
    }

    /// @dev WebAuthn assertion from a recovery guardian (recover() verifies M of N).
    struct GuardianAssertion {
        bytes32 guardianCredIdHash;
        bytes authenticatorData;
        bytes clientDataJSON;
        uint256 challengeLocation;
        uint256 r;
        uint256 s;
    }

    address public immutable entryPoint;
    address public immutable k11Verifier;

    /// @notice credIdHash => authorized passkey.
    mapping(bytes32 => Signer) public signers;
    /// @notice Count of live (current-generation, active) signers; never drops to zero.
    uint256 public activeSignerCount;
    /// @notice Monotonic signer generation. recover() bumps it, instantly
    ///         invalidating every signer from a prior generation (no iteration).
    uint64 public signerGeneration;

    /// @notice guardianCredIdHash => recovery guardian passkey.
    mapping(bytes32 => Guardian) public guardians;
    uint256 public activeGuardianCount;
    /// @notice M-of-N recovery threshold. 0 = recovery disabled (safe default).
    uint8 public recoveryThreshold;
    /// @notice Anti-replay for guardian recovery (recover() bypasses the EntryPoint nonce).
    uint256 public recoveryNonce;

    event SignerAdded(bytes32 indexed credIdHash, uint256 pubX, uint256 pubY, bytes32 rpIdHash);
    event SignerRemoved(bytes32 indexed credIdHash);
    event GuardianAdded(bytes32 indexed guardianCredIdHash);
    event GuardianRemoved(bytes32 indexed guardianCredIdHash);
    event RecoveryThresholdSet(uint8 threshold);
    event Recovered(bytes32 indexed newCredIdHash, uint64 generation);
    event Executed(address indexed dest, uint256 value, bytes data);

    error NotEntryPoint();
    error NotEntryPointOrSelf();
    error NotSelf();
    error SignerExists(bytes32 credIdHash);
    error UnknownSigner(bytes32 credIdHash);
    error LastSigner();
    error LengthMismatch();
    error GuardianExists(bytes32 guardianCredIdHash);
    error UnknownGuardian(bytes32 guardianCredIdHash);
    error RecoveryDisabled();
    error InsufficientGuardians(uint8 got, uint8 required);
    error DuplicateGuardian(bytes32 guardianCredIdHash);
    error ThresholdTooHigh(uint8 threshold, uint256 guardianCount);

    constructor(
        address _entryPoint,
        address _k11Verifier,
        bytes32 credIdHash,
        uint256 pubX,
        uint256 pubY,
        bytes32 rpIdHash
    ) {
        entryPoint = _entryPoint;
        k11Verifier = _k11Verifier;
        _addSigner(credIdHash, pubX, pubY, rpIdHash);
    }

    receive() external payable {}

    // ─── ERC-4337 validation ─────────────────────────────────────────────
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        if (msg.sender != entryPoint) revert NotEntryPoint();
        // ERC-4337: a bad signature must return SIG_VALIDATION_FAILED, never
        // revert, so the EntryPoint/bundler reject the op cleanly. The on-chain
        // K11Verifier REVERTS on malformed/mismatched assertions (wrong
        // challenge/RP, missing UP/UV flags, bad clientDataJSON), and abi.decode
        // reverts on a malformed blob — so run decode+verify via an external
        // self-call wrapped in try/catch and map any failure to SIG_FAIL.
        try this.checkUserOpSignature(userOp.signature, userOpHash) returns (bool ok) {
            validationData = ok ? SIG_OK : SIG_FAIL;
        } catch {
            validationData = SIG_FAIL;
        }
        _payPrefund(missingAccountFunds);
    }

    /// @dev signature = abi.encode(credIdHash, authenticatorData, clientDataJSON,
    ///      challengeLocation, r, s). The pubkey/rpIdHash come from the stored
    ///      signer; the challenge is the userOpHash (full-intent commitment).
    ///      External + self-only so validateUserOp can try/catch its reverts and
    ///      map them to SIG_VALIDATION_FAILED. View — no state change.
    function checkUserOpSignature(bytes calldata signature, bytes32 userOpHash)
        external
        view
        returns (bool)
    {
        if (msg.sender != address(this)) revert NotSelf();
        (
            bytes32 credIdHash,
            bytes memory authenticatorData,
            bytes memory clientDataJSON,
            uint256 challengeLocation,
            uint256 r,
            uint256 s
        ) = abi.decode(signature, (bytes32, bytes, bytes, uint256, uint256, uint256));

        Signer storage signer = signers[credIdHash];
        if (!_signerActive(signer)) return false;

        return IK11Verifier(k11Verifier).verifyAssertion(
            userOpHash,
            signer.rpIdHash,
            authenticatorData,
            clientDataJSON,
            challengeLocation,
            r,
            s,
            signer.pubX,
            signer.pubY
        );
    }

    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds}("");
            (success); // EntryPoint reverts the op if the prefund is unmet
        }
    }

    // ─── Execution (passkey-gated via EntryPoint, or self-call from a UserOp) ──
    function execute(address dest, uint256 value, bytes calldata func) external {
        _requireEntryPointOrSelf();
        _call(dest, value, func);
    }

    function executeBatch(
        address[] calldata dest,
        uint256[] calldata value,
        bytes[] calldata func
    ) external {
        _requireEntryPointOrSelf();
        if (dest.length != func.length || dest.length != value.length) revert LengthMismatch();
        for (uint256 i = 0; i < dest.length; ++i) {
            _call(dest[i], value[i], func[i]);
        }
    }

    function _call(address dest, uint256 value, bytes calldata func) internal {
        (bool ok, bytes memory ret) = dest.call{value: value}(func);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        emit Executed(dest, value, func);
    }

    // ─── Signer management (passkey-gated via EntryPoint/self) ────────────
    function addSigner(bytes32 credIdHash, uint256 pubX, uint256 pubY, bytes32 rpIdHash) external {
        _requireEntryPointOrSelf();
        _addSigner(credIdHash, pubX, pubY, rpIdHash);
    }

    function removeSigner(bytes32 credIdHash) external {
        _requireEntryPointOrSelf();
        if (!_signerActive(signers[credIdHash])) revert UnknownSigner(credIdHash);
        if (activeSignerCount <= 1) revert LastSigner();
        signers[credIdHash].active = false;
        activeSignerCount -= 1;
        emit SignerRemoved(credIdHash);
    }

    function _addSigner(bytes32 credIdHash, uint256 pubX, uint256 pubY, bytes32 rpIdHash) internal {
        if (_signerActive(signers[credIdHash])) revert SignerExists(credIdHash);
        signers[credIdHash] = Signer({
            pubX: pubX,
            pubY: pubY,
            rpIdHash: rpIdHash,
            active: true,
            generation: signerGeneration
        });
        activeSignerCount += 1;
        emit SignerAdded(credIdHash, pubX, pubY, rpIdHash);
    }

    function _signerActive(Signer storage s) internal view returns (bool) {
        return s.active && s.generation == signerGeneration;
    }

    // ─── Guardian management + social recovery (#164 E5) ──────────────────
    function addGuardian(bytes32 guardianCredIdHash, uint256 pubX, uint256 pubY, bytes32 rpIdHash)
        external
    {
        _requireEntryPointOrSelf();
        if (guardians[guardianCredIdHash].active) revert GuardianExists(guardianCredIdHash);
        guardians[guardianCredIdHash] =
            Guardian({pubX: pubX, pubY: pubY, rpIdHash: rpIdHash, active: true});
        activeGuardianCount += 1;
        emit GuardianAdded(guardianCredIdHash);
    }

    function removeGuardian(bytes32 guardianCredIdHash) external {
        _requireEntryPointOrSelf();
        if (!guardians[guardianCredIdHash].active) revert UnknownGuardian(guardianCredIdHash);
        guardians[guardianCredIdHash].active = false;
        activeGuardianCount -= 1;
        if (recoveryThreshold > activeGuardianCount) {
            recoveryThreshold = uint8(activeGuardianCount); // keep the quorum satisfiable
            emit RecoveryThresholdSet(recoveryThreshold);
        }
        emit GuardianRemoved(guardianCredIdHash);
    }

    function setRecoveryThreshold(uint8 threshold) external {
        _requireEntryPointOrSelf();
        if (threshold > activeGuardianCount) revert ThresholdTooHigh(threshold, activeGuardianCount);
        recoveryThreshold = threshold;
        emit RecoveryThresholdSet(threshold);
    }

    /// @notice Social recovery: M-of-N guardians rotate control to a fresh passkey
    ///         WITHOUT the (lost) primary signer or the EntryPoint — the independent
    ///         guardian path (threat-model §7). Permissionless to submit (a relayer
    ///         can land it for a locked-out operator); authorized purely by the
    ///         guardian assertions. Bumps `signerGeneration`, invalidating every
    ///         prior signer, and installs `new*` as the sole active signer.
    /// @dev    Guardian assertions are P-256 verified in-contract over a challenge
    ///         binding the new signer + recoveryNonce + chainId + this account — the
    ///         one retained defense-in-depth (a guardian recovering a stolen device
    ///         cannot route through the compromised primary's validateUserOp).
    function recover(
        bytes32 newCredIdHash,
        uint256 newPubX,
        uint256 newPubY,
        bytes32 newRpIdHash,
        GuardianAssertion[] calldata assertions
    ) external {
        uint8 threshold = recoveryThreshold;
        if (threshold == 0) revert RecoveryDisabled();
        if (assertions.length < threshold) {
            revert InsufficientGuardians(uint8(assertions.length), threshold);
        }

        bytes32 challenge = keccak256(
            abi.encode(
                OP_RECOVER,
                newCredIdHash,
                newPubX,
                newPubY,
                newRpIdHash,
                recoveryNonce,
                block.chainid,
                address(this)
            )
        );

        uint256 nValid;
        for (uint256 i = 0; i < assertions.length; ++i) {
            bytes32 gid = assertions[i].guardianCredIdHash;
            Guardian storage g = guardians[gid];
            if (!g.active) revert UnknownGuardian(gid);
            // codex #3: reject the same credId AND the same physical key registered
            // under a second credId — one guardian must not satisfy an M>=2 quorum.
            for (uint256 j = 0; j < i; ++j) {
                Guardian storage pg = guardians[assertions[j].guardianCredIdHash];
                if (
                    assertions[j].guardianCredIdHash == gid
                        || (pg.pubX == g.pubX && pg.pubY == g.pubY)
                ) {
                    revert DuplicateGuardian(gid);
                }
            }
            // A malformed/mismatched assertion reverts in the verifier; try/catch
            // so one bad guardian envelope doesn't grief the whole recovery.
            try IK11Verifier(k11Verifier).verifyAssertion(
                challenge,
                g.rpIdHash,
                assertions[i].authenticatorData,
                assertions[i].clientDataJSON,
                assertions[i].challengeLocation,
                assertions[i].r,
                assertions[i].s,
                g.pubX,
                g.pubY
            ) returns (bool ok) {
                if (ok) {
                    unchecked {
                        ++nValid;
                    }
                }
            } catch {}
        }
        if (nValid < threshold) revert InsufficientGuardians(uint8(nValid), threshold);

        recoveryNonce += 1;
        signerGeneration += 1; // invalidates all prior-generation signers
        activeSignerCount = 0; // _addSigner brings it back to 1
        _addSigner(newCredIdHash, newPubX, newPubY, newRpIdHash);
        emit Recovered(newCredIdHash, signerGeneration);
    }

    function _requireEntryPointOrSelf() internal view {
        if (msg.sender != entryPoint && msg.sender != address(this)) revert NotEntryPointOrSelf();
    }
}
