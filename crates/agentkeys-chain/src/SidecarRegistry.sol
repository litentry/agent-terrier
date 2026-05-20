// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {K11Verifier} from "./K11Verifier.sol";

/// @title SidecarRegistry — per-operator device-key bindings
/// @notice Single source of truth for "is this device registered to this operator?"
///         Workers re-verify caps against this state on every call (arch.md §10, §13.1).
///
/// @dev    Stage-2 (#90) hardening:
///         - K11 assertions are P-256 verified ON CHAIN via [K11Verifier] +
///           [P256Verifier] (Heima is at London EVM, no EIP-7212 precompile).
///         - K11 assertion challenge is bound to (operation_kind || operator ||
///           params || chainid || operatorNonce[operator]) so a captured K11
///           sig cannot be replayed for a different operation.
///         - Multi-master M-of-N recovery quorum: `revokeDevice` of a MASTER
///           device requires >= recoveryThreshold[operator] valid K11 sigs
///           from distinct registered masters with the RECOVERY role.
///         - DeviceEntry stores K11 P-256 pubkey (x, y) for on-chain verify.
contract SidecarRegistry {
    // ─── Role bitfield (per device, per arch.md §6.3) ────────────────────
    uint8 public constant ROLE_CAP_MINT = 1 << 0;
    uint8 public constant ROLE_RECOVERY = 1 << 1;
    uint8 public constant ROLE_SCOPE_MGMT = 1 << 2;

    // ─── Device tier (arch.md §10.1 vs §10.2) ────────────────────────────
    uint8 public constant TIER_MASTER = 1;
    uint8 public constant TIER_AGENT = 2;

    /// @notice Operation kind codes used in challenge-msg construction.
    bytes32 public constant OP_REGISTER_2ND_MASTER = keccak256("agentkeys:v1:register-master");
    bytes32 public constant OP_REVOKE_MASTER = keccak256("agentkeys:v1:revoke-master");
    bytes32 public constant OP_SET_THRESHOLD = keccak256("agentkeys:v1:set-recovery-threshold");

    struct DeviceEntry {
        bytes32 operatorOmni;
        bytes32 actorOmni;
        bytes32 k11CredId; // WebAuthn cred id (indexer hint; 0 for agents)
        bytes32 k11RpIdHash; // sha256(rpId) — bound at register time, checked on every K11 verify (codex H1)
        uint256 k11PubX; // P-256 X for on-chain verify (0 for agents)
        uint256 k11PubY; // P-256 Y for on-chain verify (0 for agents)
        uint8 tier;
        uint8 roles;
        uint64 registeredAt;
        uint32 lastSignCount; // anti-replay per-credential counter
        bool revoked;
    }

    /// @notice WebAuthn assertion payload submitted on chain. Caller provides
    ///         the raw authData + clientDataJSON; the contract reconstructs
    ///         the expected challenge from operation params + per-operator
    ///         nonce and binds the K11 sig to that challenge.
    struct K11Assertion {
        bytes32 attestingDeviceKeyHash; // which registered master is asserting
        bytes authenticatorData;
        bytes clientDataJSON;
        uint256 challengeLocation;
        uint256 r;
        uint256 s;
    }

    K11Verifier public immutable k11Verifier;

    mapping(bytes32 => DeviceEntry) public devices;
    mapping(bytes32 => bytes32[]) private operatorDevices;
    mapping(bytes32 => address) public operatorMasterWallet;
    mapping(bytes32 => uint8) public recoveryThreshold; // default 1 (single master can revoke)
    mapping(bytes32 => uint256) public operatorNonce; // ++ on every K11-gated mutation

    event DeviceRegistered(
        bytes32 indexed deviceKeyHash,
        bytes32 indexed operatorOmni,
        bytes32 indexed actorOmni,
        uint8 tier,
        uint8 roles,
        bytes32 k11CredId
    );
    event DeviceRevoked(bytes32 indexed deviceKeyHash, bytes32 indexed operatorOmni);
    event OperatorBootstrapped(bytes32 indexed operatorOmni, address indexed masterWallet);
    event RecoveryThresholdSet(bytes32 indexed operatorOmni, uint8 newThreshold);

    error DeviceAlreadyRegistered(bytes32 deviceKeyHash);
    error DeviceNotRegistered(bytes32 deviceKeyHash);
    error DeviceAlreadyRevoked(bytes32 deviceKeyHash);
    error OperatorNotRegistered(bytes32 operatorOmni);
    error NotAuthorized(address caller, address expected);
    error K11VerificationFailed();
    error InvalidAttestingDevice(bytes32 deviceKeyHash);
    error InsufficientQuorum(uint8 got, uint8 required);
    error DuplicateAttestor(bytes32 deviceKeyHash);
    error StaleSignCount(uint32 got, uint32 last);
    error InvalidRecoveryThreshold();
    error K11RoleMissing(uint8 required);

    constructor(address k11VerifierAddr) {
        k11Verifier = K11Verifier(k11VerifierAddr);
    }

    // ─── Master device registration ──────────────────────────────────────
    /// @notice Register the FIRST master device for an operator. First call wins;
    ///         subsequent master mutations need this sender.
    /// @dev    For initial bootstrap (no existing master), no K11 assertion is
    ///         required (chicken-and-egg — there's no prior K11 to attest with).
    function registerFirstMasterDevice(
        bytes32 deviceKeyHash,
        bytes32 operatorOmni,
        bytes32 actorOmni,
        bytes32 k11CredId,
        bytes32 k11RpIdHash,
        uint256 k11PubX,
        uint256 k11PubY,
        bytes calldata attestation,
        uint8 roles
    ) external {
        if (devices[deviceKeyHash].registeredAt != 0) {
            revert DeviceAlreadyRegistered(deviceKeyHash);
        }
        if (operatorMasterWallet[operatorOmni] != address(0)) {
            // Operator already has a first master; use registerAdditionalMasterDevice.
            revert DeviceAlreadyRegistered(deviceKeyHash);
        }

        operatorMasterWallet[operatorOmni] = msg.sender;
        recoveryThreshold[operatorOmni] = 1;
        emit OperatorBootstrapped(operatorOmni, msg.sender);

        devices[deviceKeyHash] = DeviceEntry({
            operatorOmni: operatorOmni,
            actorOmni: actorOmni,
            k11CredId: k11CredId,
            k11RpIdHash: k11RpIdHash,
            k11PubX: k11PubX,
            k11PubY: k11PubY,
            tier: TIER_MASTER,
            roles: roles,
            registeredAt: uint64(block.timestamp),
            lastSignCount: 0,
            revoked: false
        });
        operatorDevices[operatorOmni].push(deviceKeyHash);

        emit DeviceRegistered(deviceKeyHash, operatorOmni, actorOmni, TIER_MASTER, roles, k11CredId);
        attestation; // accepted but only emitted via event topics
    }

    /// @notice Register a 2nd+ master device. Existing master signs a K11
    ///         assertion authorizing the new device. Per arch.md §10.3.1.
    function registerAdditionalMasterDevice(
        bytes32 newDeviceKeyHash,
        bytes32 operatorOmni,
        bytes32 newActorOmni,
        bytes32 newK11CredId,
        bytes32 newK11RpIdHash,
        uint256 newK11PubX,
        uint256 newK11PubY,
        bytes calldata attestation,
        uint8 newRoles,
        K11Assertion calldata existingMasterAssertion
    ) external {
        if (devices[newDeviceKeyHash].registeredAt != 0) {
            revert DeviceAlreadyRegistered(newDeviceKeyHash);
        }
        address master = operatorMasterWallet[operatorOmni];
        if (master == address(0)) revert OperatorNotRegistered(operatorOmni);
        if (msg.sender != master) revert NotAuthorized(msg.sender, master);

        bytes32 expectedChallenge = keccak256(
            abi.encode(
                OP_REGISTER_2ND_MASTER,
                operatorOmni,
                newDeviceKeyHash,
                newRoles,
                block.chainid,
                operatorNonce[operatorOmni]
            )
        );
        _verifyAndConsumeK11(
            expectedChallenge, operatorOmni, ROLE_RECOVERY, existingMasterAssertion
        );

        devices[newDeviceKeyHash] = DeviceEntry({
            operatorOmni: operatorOmni,
            actorOmni: newActorOmni,
            k11CredId: newK11CredId,
            k11RpIdHash: newK11RpIdHash,
            k11PubX: newK11PubX,
            k11PubY: newK11PubY,
            tier: TIER_MASTER,
            roles: newRoles,
            registeredAt: uint64(block.timestamp),
            lastSignCount: 0,
            revoked: false
        });
        operatorDevices[operatorOmni].push(newDeviceKeyHash);

        emit DeviceRegistered(
            newDeviceKeyHash, operatorOmni, newActorOmni, TIER_MASTER, newRoles, newK11CredId
        );
        attestation;
    }

    /// @notice Register an agent device (link-code redeem path, K10-only).
    ///         Per arch.md §10.2 — agents never hold K11.
    function registerAgentDevice(
        bytes32 deviceKeyHash,
        bytes32 operatorOmni,
        bytes32 actorOmni,
        bytes calldata linkCodeRedemption,
        bytes calldata agentPopSig
    ) external {
        if (devices[deviceKeyHash].registeredAt != 0) {
            revert DeviceAlreadyRegistered(deviceKeyHash);
        }
        address master = operatorMasterWallet[operatorOmni];
        if (master == address(0)) revert OperatorNotRegistered(operatorOmni);
        if (msg.sender != master) revert NotAuthorized(msg.sender, master);

        devices[deviceKeyHash] = DeviceEntry({
            operatorOmni: operatorOmni,
            actorOmni: actorOmni,
            k11CredId: bytes32(0),
            k11RpIdHash: bytes32(0),
            k11PubX: 0,
            k11PubY: 0,
            tier: TIER_AGENT,
            roles: ROLE_CAP_MINT,
            registeredAt: uint64(block.timestamp),
            lastSignCount: 0,
            revoked: false
        });
        operatorDevices[operatorOmni].push(deviceKeyHash);

        emit DeviceRegistered(
            deviceKeyHash, operatorOmni, actorOmni, TIER_AGENT, ROLE_CAP_MINT, bytes32(0)
        );
        linkCodeRedemption;
        agentPopSig;
    }

    /// @notice Revoke an agent device. K10-only (no K11 — agents have none).
    function revokeAgentDevice(bytes32 deviceKeyHash) external {
        DeviceEntry storage entry = devices[deviceKeyHash];
        if (entry.registeredAt == 0) revert DeviceNotRegistered(deviceKeyHash);
        if (entry.revoked) revert DeviceAlreadyRevoked(deviceKeyHash);
        if (entry.tier != TIER_AGENT) revert NotAuthorized(msg.sender, address(0));

        address master = operatorMasterWallet[entry.operatorOmni];
        if (msg.sender != master) revert NotAuthorized(msg.sender, master);

        entry.revoked = true;
        emit DeviceRevoked(deviceKeyHash, entry.operatorOmni);
    }

    /// @notice Revoke a master device. Requires M-of-N K11 assertions where M =
    ///         recoveryThreshold[operator]. Each assertion must come from a
    ///         distinct registered MASTER device with the RECOVERY role.
    ///
    /// @dev    Refuses to revoke if doing so would leave fewer than 1
    ///         active master with the RECOVERY role for the operator —
    ///         that would permanently strand the operator (no surviving
    ///         master means no future master mutations are possible).
    ///         Same applies to keeping enough recovery-capable masters
    ///         to satisfy the current threshold.
    function revokeMasterDevice(
        bytes32 targetDeviceKeyHash,
        K11Assertion[] calldata recoveryAssertions
    ) external {
        DeviceEntry storage entry = devices[targetDeviceKeyHash];
        if (entry.registeredAt == 0) revert DeviceNotRegistered(targetDeviceKeyHash);
        if (entry.revoked) revert DeviceAlreadyRevoked(targetDeviceKeyHash);
        if (entry.tier != TIER_MASTER) revert NotAuthorized(msg.sender, address(0));

        bytes32 operatorOmni = entry.operatorOmni;
        address master = operatorMasterWallet[operatorOmni];
        if (msg.sender != master) revert NotAuthorized(msg.sender, master);

        uint8 threshold = recoveryThreshold[operatorOmni];
        if (threshold == 0) threshold = 1;
        if (recoveryAssertions.length < threshold) {
            revert InsufficientQuorum(uint8(recoveryAssertions.length), threshold);
        }

        // Post-revoke must leave at least max(1, threshold) recovery-capable
        // masters — never strand the operator. Codex review finding C1.
        uint8 activeRecovery = _activeRecoveryMasterCount(operatorOmni);
        uint8 remainingAfter = activeRecovery - 1;
        uint8 minRequired = threshold > 1 ? threshold : 1;
        if (remainingAfter < minRequired) {
            revert InsufficientQuorum(remainingAfter, minRequired);
        }

        bytes32 expectedChallenge = keccak256(
            abi.encode(
                OP_REVOKE_MASTER,
                operatorOmni,
                targetDeviceKeyHash,
                block.chainid,
                operatorNonce[operatorOmni]
            )
        );

        _verifyQuorum(
            expectedChallenge,
            operatorOmni,
            ROLE_RECOVERY,
            recoveryAssertions,
            threshold
        );

        entry.revoked = true;
        emit DeviceRevoked(targetDeviceKeyHash, operatorOmni);
    }

    /// @notice Update the per-operator recovery threshold. Master-only,
    ///         K11-gated (single sig from any master with RECOVERY role).
    ///
    /// @dev    Cannot set threshold higher than the current count of
    ///         active masters with the RECOVERY role — that would create
    ///         an unsatisfiable quorum and permanently freeze future
    ///         master mutations. Codex review finding C2.
    function setRecoveryThreshold(
        bytes32 operatorOmni,
        uint8 newThreshold,
        K11Assertion calldata assertion
    ) external {
        address master = operatorMasterWallet[operatorOmni];
        if (master == address(0)) revert OperatorNotRegistered(operatorOmni);
        if (msg.sender != master) revert NotAuthorized(msg.sender, master);
        if (newThreshold == 0) revert InvalidRecoveryThreshold();
        uint8 activeRecovery = _activeRecoveryMasterCount(operatorOmni);
        if (newThreshold > activeRecovery) revert InvalidRecoveryThreshold();

        bytes32 expectedChallenge = keccak256(
            abi.encode(
                OP_SET_THRESHOLD,
                operatorOmni,
                uint256(newThreshold),
                block.chainid,
                operatorNonce[operatorOmni]
            )
        );
        _verifyAndConsumeK11(expectedChallenge, operatorOmni, ROLE_RECOVERY, assertion);

        recoveryThreshold[operatorOmni] = newThreshold;
        emit RecoveryThresholdSet(operatorOmni, newThreshold);
    }

    // ─── Views ───────────────────────────────────────────────────────────
    function getDevice(bytes32 deviceKeyHash) external view returns (DeviceEntry memory) {
        return devices[deviceKeyHash];
    }

    function getOperatorDevices(bytes32 operatorOmni) external view returns (bytes32[] memory) {
        return operatorDevices[operatorOmni];
    }

    function isActive(bytes32 deviceKeyHash) external view returns (bool) {
        DeviceEntry storage entry = devices[deviceKeyHash];
        return entry.registeredAt != 0 && !entry.revoked;
    }

    // ─── K11 verification helpers ────────────────────────────────────────
    /// @dev Count active master devices with the RECOVERY role for an
    ///      operator. Used by revokeMasterDevice + setRecoveryThreshold to
    ///      enforce the "never strand the operator" invariant. O(N) over
    ///      the operator's device list; N is small (operators run a handful
    ///      of master devices typically).
    function _activeRecoveryMasterCount(bytes32 operatorOmni) internal view returns (uint8) {
        bytes32[] storage list = operatorDevices[operatorOmni];
        uint256 count = 0;
        for (uint256 i = 0; i < list.length; ++i) {
            DeviceEntry storage e = devices[list[i]];
            if (
                e.registeredAt != 0
                    && !e.revoked
                    && e.tier == TIER_MASTER
                    && (e.roles & ROLE_RECOVERY) != 0
            ) {
                unchecked { count += 1; }
            }
        }
        // Saturate at u8 max — operators with > 255 active masters are not a
        // real shape (UX collapses long before).
        return count > 255 ? 255 : uint8(count);
    }

    /// @notice Public view for off-chain tooling — operators inspecting
    ///         "how many active recovery-capable masters do I have right
    ///         now?" before raising the recovery threshold.
    function activeRecoveryMasterCount(bytes32 operatorOmni) external view returns (uint8) {
        return _activeRecoveryMasterCount(operatorOmni);
    }

    /// @dev Verify single K11 assertion + bump per-operator nonce + sign-count.
    function _verifyAndConsumeK11(
        bytes32 expectedChallenge,
        bytes32 expectedOperatorOmni,
        uint8 requiredRole,
        K11Assertion calldata a
    ) internal {
        _verifyK11One(expectedChallenge, expectedOperatorOmni, requiredRole, a);
        operatorNonce[expectedOperatorOmni] += 1;
    }

    function _verifyK11One(
        bytes32 expectedChallenge,
        bytes32 expectedOperatorOmni,
        uint8 requiredRole,
        K11Assertion calldata a
    ) internal {
        DeviceEntry storage entry = devices[a.attestingDeviceKeyHash];
        if (entry.registeredAt == 0 || entry.revoked) {
            revert InvalidAttestingDevice(a.attestingDeviceKeyHash);
        }
        if (entry.tier != TIER_MASTER) {
            revert InvalidAttestingDevice(a.attestingDeviceKeyHash);
        }
        if (entry.operatorOmni != expectedOperatorOmni) {
            revert InvalidAttestingDevice(a.attestingDeviceKeyHash);
        }
        if ((entry.roles & requiredRole) == 0) {
            revert K11RoleMissing(requiredRole);
        }

        uint32 signCount = k11Verifier.readSignCount(a.authenticatorData);
        if (signCount <= entry.lastSignCount && entry.lastSignCount != 0) {
            revert StaleSignCount(signCount, entry.lastSignCount);
        }

        bool ok = k11Verifier.verifyAssertion(
            expectedChallenge,
            entry.k11RpIdHash,
            a.authenticatorData,
            a.clientDataJSON,
            a.challengeLocation,
            a.r,
            a.s,
            entry.k11PubX,
            entry.k11PubY
        );
        if (!ok) revert K11VerificationFailed();

        entry.lastSignCount = signCount;
    }

    /// @dev Verify M-of-N K11 quorum + bump per-operator nonce. Each assertion
    ///      must be from a distinct device.
    function _verifyQuorum(
        bytes32 expectedChallenge,
        bytes32 expectedOperatorOmni,
        uint8 requiredRole,
        K11Assertion[] calldata assertions,
        uint8 threshold
    ) internal {
        uint256 nValid = 0;
        for (uint256 i = 0; i < assertions.length; ++i) {
            for (uint256 j = 0; j < i; ++j) {
                if (assertions[i].attestingDeviceKeyHash == assertions[j].attestingDeviceKeyHash)
                {
                    revert DuplicateAttestor(assertions[i].attestingDeviceKeyHash);
                }
            }
            _verifyK11One(expectedChallenge, expectedOperatorOmni, requiredRole, assertions[i]);
            unchecked {
                ++nValid;
            }
        }
        if (nValid < threshold) revert InsufficientQuorum(uint8(nValid), threshold);
        operatorNonce[expectedOperatorOmni] += 1;
    }
}
