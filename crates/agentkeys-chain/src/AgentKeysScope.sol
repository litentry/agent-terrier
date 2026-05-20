// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {K11Verifier} from "./K11Verifier.sol";

/// @notice Minimal SidecarRegistry surface AgentKeysScope needs for K11 auth.
interface ISidecarRegistry {
    struct DeviceEntry {
        bytes32 operatorOmni;
        bytes32 actorOmni;
        bytes32 k11CredId;
        bytes32 k11RpIdHash;
        uint256 k11PubX;
        uint256 k11PubY;
        uint8 tier;
        uint8 roles;
        uint64 registeredAt;
        uint32 lastSignCount;
        bool revoked;
    }

    function operatorMasterWallet(bytes32 operatorOmni) external view returns (address);
    function operatorNonce(bytes32 operatorOmni) external view returns (uint256);
    function getDevice(bytes32 deviceKeyHash) external view returns (DeviceEntry memory);
    function ROLE_SCOPE_MGMT() external view returns (uint8);
    function TIER_MASTER() external view returns (uint8);
}

/// @title AgentKeysScope — per-(operator, agent) scope state
/// @notice "Which services can this agent use, with what spend limits?"
///         Read by the broker on cap-mint AND by workers on cap-verify
///         (arch.md §12.4, §13.1, §19).
///
/// @dev    Stage-2 (#90) hardening: scope mutations are K11-bound via on-chain
///         P-256 verify against the asserting master's registered K11 pubkey.
///         K11 challenge commits to (operation || operator || agent || services
///         hash || chainid || scopeNonce[op][agent]) so a captured sig cannot
///         be replayed for a different scope target.
contract AgentKeysScope {
    ISidecarRegistry public immutable registry;
    K11Verifier public immutable k11Verifier;

    bytes32 public constant OP_SET_SCOPE = keccak256("agentkeys:v1:set-scope");
    bytes32 public constant OP_REVOKE_SCOPE = keccak256("agentkeys:v1:revoke-scope");

    struct Scope {
        bytes32[] services;
        bool readOnly;
        uint128 maxPerCall;
        uint128 maxPerPeriod;
        uint128 maxTotal;
        uint32 periodSeconds;
        uint64 updatedAt;
        bool exists;
    }

    struct K11Assertion {
        bytes32 attestingDeviceKeyHash;
        bytes authenticatorData;
        bytes clientDataJSON;
        uint256 challengeLocation;
        uint256 r;
        uint256 s;
    }

    /// @notice operator_omni → agent_omni → Scope
    mapping(bytes32 => mapping(bytes32 => Scope)) private scopes;
    /// @notice per-(operator, agent) monotonic nonce for anti-replay of K11
    mapping(bytes32 => mapping(bytes32 => uint256)) public scopeNonce;

    event ScopeUpdated(
        bytes32 indexed operatorOmni,
        bytes32 indexed agentOmni,
        bytes32[] services,
        bool readOnly,
        uint128 maxPerCall,
        uint128 maxPerPeriod,
        uint128 maxTotal,
        uint32 periodSeconds
    );
    event ScopeRevoked(bytes32 indexed operatorOmni, bytes32 indexed agentOmni);

    error OperatorNotRegistered(bytes32 operatorOmni);
    error NotAuthorized(address caller, address expected);
    error InvalidAttestingDevice(bytes32 deviceKeyHash);
    error K11VerificationFailed();
    error K11RoleMissing(uint8 required);
    error ScopeNotSet(bytes32 operatorOmni, bytes32 agentOmni);

    constructor(address registryAddr, address k11VerifierAddr) {
        registry = ISidecarRegistry(registryAddr);
        k11Verifier = K11Verifier(k11VerifierAddr);
    }

    /// @notice Grant or replace an agent's scope. Master-mutation, K11-gated.
    function setScopeWithWebauthn(
        bytes32 operatorOmni,
        bytes32 agentOmni,
        bytes32[] calldata services,
        bool readOnly,
        uint128 maxPerCall,
        uint128 maxPerPeriod,
        uint128 maxTotal,
        uint32 periodSeconds,
        K11Assertion calldata assertion
    ) external {
        address master = registry.operatorMasterWallet(operatorOmni);
        if (master == address(0)) revert OperatorNotRegistered(operatorOmni);
        if (msg.sender != master) revert NotAuthorized(msg.sender, master);

        bytes32 servicesDigest = keccak256(abi.encode(services));
        bytes32 expectedChallenge = keccak256(
            abi.encode(
                OP_SET_SCOPE,
                operatorOmni,
                agentOmni,
                servicesDigest,
                readOnly,
                maxPerCall,
                maxPerPeriod,
                maxTotal,
                periodSeconds,
                block.chainid,
                scopeNonce[operatorOmni][agentOmni]
            )
        );
        _verifyK11(expectedChallenge, operatorOmni, assertion);
        scopeNonce[operatorOmni][agentOmni] += 1;

        scopes[operatorOmni][agentOmni] = Scope({
            services: services,
            readOnly: readOnly,
            maxPerCall: maxPerCall,
            maxPerPeriod: maxPerPeriod,
            maxTotal: maxTotal,
            periodSeconds: periodSeconds,
            updatedAt: uint64(block.timestamp),
            exists: true
        });

        emit ScopeUpdated(
            operatorOmni,
            agentOmni,
            services,
            readOnly,
            maxPerCall,
            maxPerPeriod,
            maxTotal,
            periodSeconds
        );
    }

    /// @notice Revoke an agent's entire scope. Master-mutation, K11-gated.
    function revokeScope(
        bytes32 operatorOmni,
        bytes32 agentOmni,
        K11Assertion calldata assertion
    ) external {
        address master = registry.operatorMasterWallet(operatorOmni);
        if (master == address(0)) revert OperatorNotRegistered(operatorOmni);
        if (msg.sender != master) revert NotAuthorized(msg.sender, master);
        if (!scopes[operatorOmni][agentOmni].exists) {
            revert ScopeNotSet(operatorOmni, agentOmni);
        }

        bytes32 expectedChallenge = keccak256(
            abi.encode(
                OP_REVOKE_SCOPE,
                operatorOmni,
                agentOmni,
                block.chainid,
                scopeNonce[operatorOmni][agentOmni]
            )
        );
        _verifyK11(expectedChallenge, operatorOmni, assertion);
        scopeNonce[operatorOmni][agentOmni] += 1;

        delete scopes[operatorOmni][agentOmni];
        emit ScopeRevoked(operatorOmni, agentOmni);
    }

    function getScope(bytes32 operatorOmni, bytes32 agentOmni)
        external
        view
        returns (Scope memory)
    {
        return scopes[operatorOmni][agentOmni];
    }

    function isServiceInScope(bytes32 operatorOmni, bytes32 agentOmni, bytes32 serviceHash)
        external
        view
        returns (bool)
    {
        Scope storage s = scopes[operatorOmni][agentOmni];
        if (!s.exists) return false;
        for (uint256 i = 0; i < s.services.length; ++i) {
            if (s.services[i] == serviceHash) return true;
        }
        return false;
    }

    /// @dev Verify K11 assertion against an asserting MASTER device with the
    ///      SCOPE_MGMT role. Caller is responsible for incrementing the per-
    ///      (operator, agent) scopeNonce after this returns.
    function _verifyK11(
        bytes32 expectedChallenge,
        bytes32 expectedOperatorOmni,
        K11Assertion calldata a
    ) internal view {
        ISidecarRegistry.DeviceEntry memory entry = registry.getDevice(a.attestingDeviceKeyHash);
        if (entry.registeredAt == 0 || entry.revoked) {
            revert InvalidAttestingDevice(a.attestingDeviceKeyHash);
        }
        if (entry.tier != registry.TIER_MASTER()) {
            revert InvalidAttestingDevice(a.attestingDeviceKeyHash);
        }
        if (entry.operatorOmni != expectedOperatorOmni) {
            revert InvalidAttestingDevice(a.attestingDeviceKeyHash);
        }
        uint8 requiredRole = registry.ROLE_SCOPE_MGMT();
        if ((entry.roles & requiredRole) == 0) {
            revert K11RoleMissing(requiredRole);
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
    }
}
