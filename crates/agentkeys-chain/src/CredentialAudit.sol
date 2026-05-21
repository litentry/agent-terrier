// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

/// @notice Minimal SidecarRegistry surface CredentialAudit needs to gate
///         tier-A `appendRoot` against the operator's master wallet.
interface ISidecarRegistryForAudit {
    function operatorMasterWallet(bytes32 operatorOmni) external view returns (address);
}

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

    /// @notice SidecarRegistry — used to gate `appendRoot` so only the
    ///         operator's master wallet can commit a Merkle root for
    ///         that operator (codex review finding M1: prevent any
    ///         account from polluting an operator's root list).
    ISidecarRegistryForAudit public immutable registry;

    error NotOperatorMaster(address caller, address expected);

    constructor(address registryAddr) {
        registry = ISidecarRegistryForAudit(registryAddr);
    }

    struct AuditEntry {
        bytes32 actorOmni; // who did it (the agent, not the operator)
        bytes32 serviceHash; // keccak256(service_name)
        bytes32 payloadHash; // keccak256(encrypted blob) for STORE; keccak256(cap_token_hash) for READ
        uint64 timestamp;
        uint8 opType;
    }

    /// @notice operator_omni → append-only list of entries.
    mapping(bytes32 => AuditEntry[]) private entries;

    /// @notice tier-A Merkle-batched audit roots. The audit-service worker
    ///         accumulates per-operator events off-chain, builds a Merkle
    ///         tree, and commits one root per batch. Operators reconstruct
    ///         per-event proofs from leaves stored in S3
    ///         (`s3://<vault>/audit/<root>.jsonl`). arch.md §15.3 tier A.
    struct AuditRoot {
        bytes32 merkleRoot;
        uint64 entryCount;
        uint64 timestamp;
    }
    mapping(bytes32 => AuditRoot[]) private roots;

    event AuditAppended(
        bytes32 indexed operatorOmni,
        bytes32 indexed actorOmni,
        bytes32 indexed serviceHash,
        uint8 opType,
        uint256 entryIndex,
        bytes32 payloadHash
    );

    event AuditRootAppended(
        bytes32 indexed operatorOmni,
        bytes32 indexed merkleRoot,
        uint256 rootIndex,
        uint64 entryCount
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

    // ─── tier A: Merkle-batched audit roots ──────────────────────────────
    /// @notice Commit one Merkle root summarising a batch of audit events.
    ///         Called by the audit-service worker (arch.md §15.3 tier A).
    function appendRoot(bytes32 operatorOmni, bytes32 merkleRoot, uint64 batchEntryCount)
        external
    {
        // Codex review M1: prevent any caller from appending roots for an
        // arbitrary operator. Only the operator's master wallet (per the
        // SidecarRegistry's first-call-wins bootstrap) can commit roots.
        address master = registry.operatorMasterWallet(operatorOmni);
        if (master == address(0) || msg.sender != master) {
            revert NotOperatorMaster(msg.sender, master);
        }
        AuditRoot memory r = AuditRoot({
            merkleRoot: merkleRoot,
            entryCount: batchEntryCount,
            timestamp: uint64(block.timestamp)
        });
        uint256 idx = roots[operatorOmni].length;
        roots[operatorOmni].push(r);
        emit AuditRootAppended(operatorOmni, merkleRoot, idx, batchEntryCount);
    }

    function rootCount(bytes32 operatorOmni) external view returns (uint256) {
        return roots[operatorOmni].length;
    }

    // ─── V2 surface — `AuditEnvelope v1` (arch.md §15.3a, issue #97 phase C) ──
    //
    // V2 is event-only. The full envelope lives off-chain at the audit-service
    // worker, addressed by `envelopeHash`. The chain commits only
    // `(opKind, envelopeHash)` so the contract stays op-kind-agnostic — new
    // op_kinds need ZERO contract redeploys (non-break invariant #6).
    //
    // V1 surface (`append` + `appendRoot` above) is retained so existing
    // indexers + the live tier-A worker keep working through the migration.

    /// @notice Emitted by `appendV2`. The `opKind` topic is indexed so
    ///         explorers can filter "all this operator's typed-data signs"
    ///         via a single `eth_getLogs` call without scanning every row.
    event AuditAppendedV2(
        bytes32 indexed operatorOmni,
        bytes32 indexed actorOmni,
        uint8   indexed opKind,
        bytes32 envelopeHash
    );

    /// @notice Emitted by `appendRootV2`. `opKindBitmap` is `bytes32` where
    ///         each set bit corresponds to an op_kind byte present in the
    ///         batch (bit N = op_kind N). Explorers filter root batches by
    ///         op_kind without fetching every leaf.
    event AuditRootAppendedV2(
        bytes32 indexed operatorOmni,
        bytes32 indexed merkleRoot,
        bytes32 opKindBitmap,
        uint64  entryCount
    );

    /// @notice Append a single audit envelope commitment. `envelopeHash` is
    ///         `keccak256(canonical_cbor(AuditEnvelope))`; the worker
    ///         (`agentkeys-worker-audit`) holds the full envelope at
    ///         `GET /v1/audit/envelope/<envelopeHash>`.
    ///
    /// @dev    Open to any caller, same as V1 `append` — chain ordering +
    ///         indexed topic filtering is the primary safety. Spam-resistance
    ///         is via gas cost.
    function appendV2(
        bytes32 operatorOmni,
        bytes32 actorOmni,
        uint8 opKind,
        bytes32 envelopeHash
    ) external {
        emit AuditAppendedV2(operatorOmni, actorOmni, opKind, envelopeHash);
    }

    /// @notice Commit one Merkle root summarising a tier-A batch of
    ///         envelopes. Gated to the operator's master wallet (same as
    ///         V1 `appendRoot`).
    ///
    /// @param  opKindBitmap Each bit indexes one of 256 possible op_kinds
    ///                      present in the batch. Bit N = op_kind N.
    ///                      Lets explorers filter batches by op_kind
    ///                      without fetching every leaf from the worker.
    function appendRootV2(
        bytes32 operatorOmni,
        bytes32 merkleRoot,
        bytes32 opKindBitmap,
        uint64 batchEntryCount
    ) external {
        address master = registry.operatorMasterWallet(operatorOmni);
        if (master == address(0) || msg.sender != master) {
            revert NotOperatorMaster(msg.sender, master);
        }
        emit AuditRootAppendedV2(operatorOmni, merkleRoot, opKindBitmap, batchEntryCount);
    }

    function getRoot(bytes32 operatorOmni, uint256 rootIndex)
        external
        view
        returns (AuditRoot memory)
    {
        return roots[operatorOmni][rootIndex];
    }

    /// @notice Verify a single audit event is included in a previously
    ///         committed Merkle root. `leaf` is the application-level hash
    ///         of the audit event (e.g. keccak256(abi.encode(actor, service,
    ///         opType, payloadHash, timestamp))). `proof` is a sorted-pairs
    ///         Merkle proof.
    ///
    /// @dev    Domain-separated hashing (codex M2): leaves are prefixed with
    ///         0x00 and internal nodes with 0x01 before keccak256, so an
    ///         internal node digest cannot impersonate a leaf at a shorter
    ///         depth. Workers MUST mirror this scheme when producing proofs.
    function verifyEntryInRoot(
        bytes32 operatorOmni,
        uint256 rootIndex,
        bytes32[] calldata proof,
        bytes32 leaf
    ) external view returns (bool) {
        if (rootIndex >= roots[operatorOmni].length) return false;
        bytes32 root = roots[operatorOmni][rootIndex].merkleRoot;
        // Domain-prefix the leaf.
        bytes32 computed = keccak256(abi.encodePacked(bytes1(0x00), leaf));
        for (uint256 i = 0; i < proof.length; ++i) {
            bytes32 sibling = proof[i];
            if (computed < sibling) {
                computed = keccak256(abi.encodePacked(bytes1(0x01), computed, sibling));
            } else {
                computed = keccak256(abi.encodePacked(bytes1(0x01), sibling, computed));
            }
        }
        return computed == root;
    }
}
