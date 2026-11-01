// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

/// @notice Minimal SidecarRegistry surface AgentKeysScope needs.
interface ISidecarRegistry {
    function operatorMasterWallet(bytes32 operatorOmni) external view returns (address);
}

/// @title AgentKeysScope — per-(operator, agent) scope state
/// @notice Broker and workers independently read these service grants and limits.
/// @dev Mutations require the registry's operatorMasterWallet as caller. The
///      intended master is a passkey-controlled ERC-4337 account; signature and
///      replay checks belong to that account and its EntryPoint, not this contract.
contract AgentKeysScope {
    ISidecarRegistry public immutable registry;

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

    /// @notice operator_omni → agent_omni → Scope
    mapping(bytes32 => mapping(bytes32 => Scope)) private scopes;

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
    error ScopeNotSet(bytes32 operatorOmni, bytes32 agentOmni);

    constructor(address registryAddr) {
        registry = ISidecarRegistry(registryAddr);
    }

    /// @notice Grant or replace an agent's scope. Master-mutation: authorized by
    ///         the operator's master account (passkey-gated upstream in the
    ///         account's validateUserOp; see the contract-level notes).
    function setScope(
        bytes32 operatorOmni,
        bytes32 agentOmni,
        bytes32[] calldata services,
        bool readOnly,
        uint128 maxPerCall,
        uint128 maxPerPeriod,
        uint128 maxTotal,
        uint32 periodSeconds
    ) external {
        address master = registry.operatorMasterWallet(operatorOmni);
        if (master == address(0)) revert OperatorNotRegistered(operatorOmni);
        if (msg.sender != master) revert NotAuthorized(msg.sender, master);

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

    /// @notice Revoke an agent's entire scope. Master-mutation (see setScope).
    function revokeScope(bytes32 operatorOmni, bytes32 agentOmni) external {
        address master = registry.operatorMasterWallet(operatorOmni);
        if (master == address(0)) revert OperatorNotRegistered(operatorOmni);
        if (msg.sender != master) revert NotAuthorized(msg.sender, master);
        if (!scopes[operatorOmni][agentOmni].exists) {
            revert ScopeNotSet(operatorOmni, agentOmni);
        }

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
}
