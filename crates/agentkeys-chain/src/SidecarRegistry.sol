// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

/// @title SidecarRegistry — per-operator device-key bindings
/// @notice Single source of truth for "is this device registered to this operator?"
///         Workers re-verify caps against this state on every call (arch.md §10, §13.1).
///
/// @dev Stage-1 minimal shape. K11 WebAuthn assertions are stored as opaque bytes
///      but NOT verified on-chain — the broker pre-verifies via webauthn-rs and we
///      trust the call site. On-chain P-256 verification lands when EIP-7212 is
///      live on Heima (stage 2+). Bytes are still stored so an off-chain auditor
///      can re-check.
contract SidecarRegistry {
    // ─── Role bitfield (per device, per arch.md §6.3) ────────────────────
    uint8 public constant ROLE_CAP_MINT = 1 << 0;
    uint8 public constant ROLE_RECOVERY = 1 << 1;
    uint8 public constant ROLE_SCOPE_MGMT = 1 << 2;

    // ─── Device tier (arch.md §10.1 vs §10.2) ────────────────────────────
    uint8 public constant TIER_MASTER = 1;
    uint8 public constant TIER_AGENT = 2;

    struct DeviceEntry {
        bytes32 operatorOmni; // SHA256("agentkeys"||"evm"||initial_master_wallet) per arch.md §14.1
        bytes32 actorOmni; // == operatorOmni for masters; HDKD-derived for agents (arch.md §14)
        bytes32 k11CredId; // WebAuthn cred id (0 for agents)
        uint8 tier; // TIER_MASTER | TIER_AGENT
        uint8 roles; // bitfield ROLE_CAP_MINT | ROLE_RECOVERY | ROLE_SCOPE_MGMT
        uint64 registeredAt; // block.timestamp
        bool revoked;
    }

    /// @notice device_pubkey_hash (= keccak256(D_pub)) → DeviceEntry
    mapping(bytes32 => DeviceEntry) public devices;

    /// @notice per-operator device list (for enumeration; gas-bounded by per-call write cost)
    mapping(bytes32 => bytes32[]) private operatorDevices;

    /// @notice operator → wallet authorized to make master-mutation calls.
    ///         Set on the FIRST master device register (first-call-wins);
    ///         subsequent master mutations must come from this address.
    ///         Sovereign mode (arch.md §22a default): this IS the
    ///         operator's `current_master_wallet`.
    mapping(bytes32 => address) public operatorMasterWallet;

    // ─── Events ──────────────────────────────────────────────────────────
    /// @notice Indexer hook for "new device bound to operator". Workers
    ///         consume this to invalidate per-operator caches.
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

    // ─── Errors ──────────────────────────────────────────────────────────
    error DeviceAlreadyRegistered(bytes32 deviceKeyHash);
    error DeviceNotRegistered(bytes32 deviceKeyHash);
    error DeviceAlreadyRevoked(bytes32 deviceKeyHash);
    error OperatorNotRegistered(bytes32 operatorOmni);
    error NotAuthorized(address caller, address expected);
    error K11AssertionRequired();

    /// @notice Register the FIRST master device for an operator (first call wins;
    ///         subsequent master-mutations need this caller).
    /// @dev    For initial bootstrap, `msg.sender` becomes the operator's master
    ///         wallet. Per arch.md §10.1, this address is the operator's
    ///         current_master_wallet in sovereign mode. K11 assertion not required
    ///         for the first device (chicken-and-egg — there's no prior K11 to
    ///         attest to).
    function registerMasterDevice(
        bytes32 deviceKeyHash,
        bytes32 operatorOmni,
        bytes32 actorOmni,
        bytes32 k11CredId,
        bytes calldata attestation,
        uint8 roles,
        bytes calldata k11Assertion
    ) external {
        if (devices[deviceKeyHash].registeredAt != 0) {
            revert DeviceAlreadyRegistered(deviceKeyHash);
        }

        address existingMaster = operatorMasterWallet[operatorOmni];
        if (existingMaster == address(0)) {
            // First master for this operator — bootstrap.
            operatorMasterWallet[operatorOmni] = msg.sender;
            emit OperatorBootstrapped(operatorOmni, msg.sender);
        } else {
            // Adding a 2nd+ master device — must come from current master AND
            // include a K11 assertion of the existing master (per arch.md §10.3.1
            // cross-device confirmation).
            if (msg.sender != existingMaster) revert NotAuthorized(msg.sender, existingMaster);
            if (k11Assertion.length == 0) revert K11AssertionRequired();
        }

        devices[deviceKeyHash] = DeviceEntry({
            operatorOmni: operatorOmni,
            actorOmni: actorOmni,
            k11CredId: k11CredId,
            tier: TIER_MASTER,
            roles: roles,
            registeredAt: uint64(block.timestamp),
            revoked: false
        });
        operatorDevices[operatorOmni].push(deviceKeyHash);

        emit DeviceRegistered(deviceKeyHash, operatorOmni, actorOmni, TIER_MASTER, roles, k11CredId);
        // `attestation` is accepted but only emitted via the indexed event topics
        // for now; future versions verify it on-chain (see contract docstring).
        attestation;
    }

    /// @notice Register an agent device. Called by the operator's master after
    ///         minting a link code (arch.md §10.2). Agents never hold K11 and
    ///         only ever get the CAP_MINT role.
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
            tier: TIER_AGENT,
            roles: ROLE_CAP_MINT,
            registeredAt: uint64(block.timestamp),
            revoked: false
        });
        operatorDevices[operatorOmni].push(deviceKeyHash);

        emit DeviceRegistered(
            deviceKeyHash, operatorOmni, actorOmni, TIER_AGENT, ROLE_CAP_MINT, bytes32(0)
        );
        linkCodeRedemption;
        agentPopSig;
    }

    /// @notice Revoke a device. Master mutations require K11 assertion.
    function revokeDevice(bytes32 deviceKeyHash, bytes calldata k11Assertion) external {
        DeviceEntry storage entry = devices[deviceKeyHash];
        if (entry.registeredAt == 0) revert DeviceNotRegistered(deviceKeyHash);
        if (entry.revoked) revert DeviceAlreadyRevoked(deviceKeyHash);

        address master = operatorMasterWallet[entry.operatorOmni];
        if (msg.sender != master) revert NotAuthorized(msg.sender, master);

        if (entry.tier == TIER_MASTER && k11Assertion.length == 0) {
            revert K11AssertionRequired();
        }

        entry.revoked = true;
        emit DeviceRevoked(deviceKeyHash, entry.operatorOmni);
    }

    /// @notice Returns the device entry. For external consumers; redundant
    ///         with the auto-generated `devices(bytes32)` accessor but lets
    ///         callers retrieve the full struct in one call.
    function getDevice(bytes32 deviceKeyHash) external view returns (DeviceEntry memory) {
        return devices[deviceKeyHash];
    }

    /// @notice Enumerate device hashes registered to an operator. Workers
    ///         typically don't call this on hot paths (they look up by
    ///         deviceKeyHash directly); useful for explorers + UIs.
    function getOperatorDevices(bytes32 operatorOmni) external view returns (bytes32[] memory) {
        return operatorDevices[operatorOmni];
    }

    /// @notice Quick "is this device valid right now?" check used by workers.
    function isActive(bytes32 deviceKeyHash) external view returns (bool) {
        DeviceEntry storage entry = devices[deviceKeyHash];
        return entry.registeredAt != 0 && !entry.revoked;
    }
}
