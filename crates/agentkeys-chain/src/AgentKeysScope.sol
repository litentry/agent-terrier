// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

/// @notice Minimal SidecarRegistry surface AgentKeysScope needs for auth.
interface ISidecarRegistry {
    function operatorMasterWallet(bytes32 operatorOmni) external view returns (address);
}

/// @title AgentKeysScope — per-(operator, agent) scope state
/// @notice "Which services can this agent use, with what spend limits?"
///         Read by the broker on cap-mint AND by workers on cap-verify
///         (arch.md §12.4, §13.1, §19).
///
/// @dev Stage-1 sovereign-mode authorization: scope mutations require
///      `msg.sender == SidecarRegistry.operatorMasterWallet[operator]`.
///      K11 assertion is required (bytes-non-empty) but not P-256-verified
///      on-chain — same deferral as SidecarRegistry. Per arch.md §6.4 the
///      broker pre-verifies + signs the mutation; on-chain we trust the
///      sender + K11 presence as the gate.
contract AgentKeysScope {
    ISidecarRegistry public immutable registry;

    struct Scope {
        bytes32[] services; // keccak256(name) of each in-scope service
        bool readOnly; // if true, agent can READ stored creds but not store new ones
        uint128 maxPerCall; // hard per-call cap (units depend on service)
        uint128 maxPerPeriod; // sliding-window cap; workers enforce
        uint128 maxTotal; // lifetime cap
        uint32 periodSeconds; // sliding-window duration (0 = no period limit)
        uint64 updatedAt; // block.timestamp of last set
        bool exists; // distinguishes "never set" from "set to all-zero"
    }

    /// @notice operator_omni → agent_omni → Scope
    mapping(bytes32 => mapping(bytes32 => Scope)) private scopes;

    // ─── Events ──────────────────────────────────────────────────────────
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

    // ─── Errors ──────────────────────────────────────────────────────────
    error OperatorNotRegistered(bytes32 operatorOmni);
    error NotAuthorized(address caller, address expected);
    error K11AssertionRequired();
    error ScopeNotSet(bytes32 operatorOmni, bytes32 agentOmni);

    constructor(address registryAddr) {
        registry = ISidecarRegistry(registryAddr);
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
        bytes calldata k11Assertion
    ) external {
        address master = registry.operatorMasterWallet(operatorOmni);
        if (master == address(0)) revert OperatorNotRegistered(operatorOmni);
        if (msg.sender != master) revert NotAuthorized(msg.sender, master);
        if (k11Assertion.length == 0) revert K11AssertionRequired();

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
    function revokeScope(bytes32 operatorOmni, bytes32 agentOmni, bytes calldata k11Assertion)
        external
    {
        address master = registry.operatorMasterWallet(operatorOmni);
        if (master == address(0)) revert OperatorNotRegistered(operatorOmni);
        if (msg.sender != master) revert NotAuthorized(msg.sender, master);
        if (k11Assertion.length == 0) revert K11AssertionRequired();
        if (!scopes[operatorOmni][agentOmni].exists) {
            revert ScopeNotSet(operatorOmni, agentOmni);
        }
        delete scopes[operatorOmni][agentOmni];
        emit ScopeRevoked(operatorOmni, agentOmni);
    }

    /// @notice Read the full scope struct for an (operator, agent) pair.
    function getScope(bytes32 operatorOmni, bytes32 agentOmni)
        external
        view
        returns (Scope memory)
    {
        return scopes[operatorOmni][agentOmni];
    }

    /// @notice Fast-path "is this service in scope?" check for hot worker paths.
    function isServiceInScope(bytes32 operatorOmni, bytes32 agentOmni, bytes32 serviceHash)
        external
        view
        returns (bool)
    {
        Scope storage s = scopes[operatorOmni][agentOmni];
        if (!s.exists) return false;
        for (uint256 i = 0; i < s.services.length; i++) {
            if (s.services[i] == serviceHash) return true;
        }
        return false;
    }
}
