// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AgentKeysAudit — append-only audit log for the AgentKeys broker.
/// @notice Phase C, US-030.
///
/// Per plan §Phase C: when the broker mints AWS credentials, it submits
/// one transaction per mint to this contract. The contract emits a
/// `RecordAnchored` event carrying the canonical record hash + indexed
/// (omni_account, wallet) pair so external auditors can subscribe to a
/// specific user's mints by `eth_getLogs(topic = recordHash | omni_account
/// | wallet)`.
///
/// Storage MUST be append-only. There is no admin function to redact or
/// rewrite past entries — audit immutability is the load-bearing property.
contract AgentKeysAudit {
    /// @dev `recordHash` is `SHA256(canonical_record)` — the same hash
    ///       the broker uses as the SQLite anchor's `record_hash` column.
    ///       Indexed so an auditor can verify a specific mint's on-chain
    ///       presence by hash.
    /// @dev `omniAccount` is the broker's identity hash
    ///       (`SHA256("agentkeys" || identity_type || identity_value)`).
    ///       Indexed so an auditor can subscribe to all of a user's mints.
    /// @dev `wallet` is the daemon address that minted. Indexed so an
    ///       auditor can audit a specific daemon's lifetime activity.
    /// @dev `service` + `mintedAt` ride non-indexed for context.
    event RecordAnchored(
        bytes32 indexed recordHash,
        bytes32 indexed omniAccount,
        address indexed wallet,
        string service,
        uint64 mintedAt,
        bytes32 grantId
    );

    /// @notice Append a new audit record. Anyone can call (the cost
    /// barrier is the only access control — a fee-payer wallet must hold
    /// gas). Plan §Phase C gas-drain mitigations cap per-identity TX
    /// budgets at the broker layer; on-chain rate-limiting is too
    /// expensive in storage.
    /// @param recordHash SHA256 of canonical record bytes.
    /// @param omniAccount Broker-derived identity hash.
    /// @param wallet Daemon address that minted.
    /// @param service Free-form service identifier (e.g. "s3").
    /// @param mintedAt Unix-seconds when the broker minted.
    /// @param grantId Capability-grant ULID (32 bytes left-padded zero
    ///        when no explicit grant — Phase 0 implicit-grant fallback).
    function anchor(
        bytes32 recordHash,
        bytes32 omniAccount,
        address wallet,
        string calldata service,
        uint64 mintedAt,
        bytes32 grantId
    ) external {
        emit RecordAnchored(
            recordHash,
            omniAccount,
            wallet,
            service,
            mintedAt,
            grantId
        );
    }
}
