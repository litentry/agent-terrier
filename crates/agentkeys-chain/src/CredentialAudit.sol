// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

/// @title CredentialAudit — append-only audit log for credential CRUD
/// @notice Per arch.md §15.3 tier C (sovereign default), each credential
///         CRUD operation lands on chain as an append. Block-explorer
///         scans + custom indexers (subscan-essentials per arch.md §22a.6)
///         consume the events for operator-facing audit views.
///
/// @dev Stage-1 minimal shape. Append-only; no on-chain integrity proof
///      beyond chain-native event ordering. Stage 2 may add signature
///      verification per entry (broker-signed batches per arch.md §15.3
///      tier A/B), but the wire shape stays event-based.
contract CredentialAudit {
    /// @notice Operation type — kept as uint8 for cheap calldata. The
    ///         meanings are pinned: 0=STORE, 1=READ, 2=TEARDOWN. New
    ///         values land via an immutable doc table — do NOT reuse.
    uint8 public constant OP_STORE = 0;
    uint8 public constant OP_READ = 1;
    uint8 public constant OP_TEARDOWN = 2;

    struct AuditEntry {
        bytes32 actorOmni; // who did it (the agent, not the operator)
        bytes32 serviceHash; // keccak256(service_name)
        bytes32 payloadHash; // keccak256(encrypted blob) for STORE; keccak256(cap_token_hash) for READ
        uint64 timestamp;
        uint8 opType;
    }

    /// @notice operator_omni → append-only list of entries.
    mapping(bytes32 => AuditEntry[]) private entries;

    event AuditAppended(
        bytes32 indexed operatorOmni,
        bytes32 indexed actorOmni,
        bytes32 indexed serviceHash,
        uint8 opType,
        uint256 entryIndex,
        bytes32 payloadHash
    );

    /// @notice Append an audit row. Open to any caller — the chain itself
    ///         orders writes, and the indexer filters by operator_omni.
    ///         Spam-resistance is via gas cost (every append is a tx fee).
    ///         Future stage may add a per-(operator, service) submitter
    ///         whitelist if spam becomes an issue.
    function append(
        bytes32 operatorOmni,
        bytes32 actorOmni,
        bytes32 serviceHash,
        uint8 opType,
        bytes32 payloadHash
    ) external {
        AuditEntry memory entry = AuditEntry({
            actorOmni: actorOmni,
            serviceHash: serviceHash,
            payloadHash: payloadHash,
            timestamp: uint64(block.timestamp),
            opType: opType
        });
        uint256 idx = entries[operatorOmni].length;
        entries[operatorOmni].push(entry);
        emit AuditAppended(operatorOmni, actorOmni, serviceHash, opType, idx, payloadHash);
    }

    /// @notice Read a windowed slice of an operator's audit entries.
    function getEntries(bytes32 operatorOmni, uint256 offset, uint256 limit)
        external
        view
        returns (AuditEntry[] memory page)
    {
        AuditEntry[] storage all = entries[operatorOmni];
        if (offset >= all.length) return new AuditEntry[](0);
        uint256 end = offset + limit;
        if (end > all.length) end = all.length;
        page = new AuditEntry[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            page[i - offset] = all[i];
        }
    }

    function entryCount(bytes32 operatorOmni) external view returns (uint256) {
        return entries[operatorOmni].length;
    }
}
