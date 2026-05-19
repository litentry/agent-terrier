// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

/// @title K3EpochCounter — current K3 epoch for signer-side derivation
/// @notice The signer's K3 master secret rotates per-epoch (arch.md §16).
///         All callers (broker, workers, sidecar) read `currentEpoch` to
///         pick the right K3_v[N] for K4 + KEK derivation. Historical
///         epochs are retained inside the signer enclave so pre-rotation
///         credential blobs remain decryptable.
///
/// @dev Stage-1 governance shape: a single `signerGovernance` address may
///      advance the epoch. In stage 2 the governance address becomes an
///      M-of-N multisig (arch.md §11). For mainnet bootstrap, the deployer
///      sets `signerGovernance` to themselves and rotates it to the
///      operational signer wallet after the demo is verified.
contract K3EpochCounter {
    /// @notice Most-recent K3 epoch. Monotonically increasing.
    uint256 public currentEpoch;

    /// @notice Address authorized to call `advanceEpoch` and transfer
    ///         governance. For stage 1, a single EOA; stage 2 swaps in
    ///         an M-of-N multisig contract.
    address public signerGovernance;

    /// @notice epoch → block.timestamp the epoch started.
    mapping(uint256 => uint256) public epochStartedAt;

    event K3Rotated(uint256 indexed newEpoch, uint256 timestamp);
    event SignerGovernanceTransferred(address indexed oldGov, address indexed newGov);

    error NotSignerGovernance(address caller, address expected);
    error ZeroAddressGovernance();

    constructor(address initialSignerGov) {
        if (initialSignerGov == address(0)) revert ZeroAddressGovernance();
        signerGovernance = initialSignerGov;
        currentEpoch = 1;
        epochStartedAt[1] = block.timestamp;
        emit K3Rotated(1, block.timestamp);
        emit SignerGovernanceTransferred(address(0), initialSignerGov);
    }

    /// @notice Advance to the next K3 epoch. Operator-driven rotation per
    ///         arch.md §16 (e.g., quarterly or upon TEE-compromise indicator).
    function advanceEpoch() external {
        if (msg.sender != signerGovernance) {
            revert NotSignerGovernance(msg.sender, signerGovernance);
        }
        unchecked {
            currentEpoch += 1;
        }
        epochStartedAt[currentEpoch] = block.timestamp;
        emit K3Rotated(currentEpoch, block.timestamp);
    }

    /// @notice Transfer governance. Used during the deploy → operations handoff
    ///         (deployer transfers to the signer enclave's wallet, OR to a
    ///         multisig address in stage 2).
    function setSignerGovernance(address newGov) external {
        if (msg.sender != signerGovernance) {
            revert NotSignerGovernance(msg.sender, signerGovernance);
        }
        if (newGov == address(0)) revert ZeroAddressGovernance();
        address old = signerGovernance;
        signerGovernance = newGov;
        emit SignerGovernanceTransferred(old, newGov);
    }
}
