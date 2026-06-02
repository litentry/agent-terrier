// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

/// @notice The two ERC-4337 v0.7 surfaces our account implements, vendored from
///         eth-infinitism/account-abstraction@v0.7.0. The full EntryPoint is
///         deployed separately and verified live on Heima mainnet — see
///         docs/plan/chain/erc4337-master-account.md §1. Vendoring keeps the
///         chain crate dependency-free (solc 0.8.20 pin) while staying ABI-exact
///         with the canonical v0.7 EntryPoint (field order/types are consensus).
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

interface IAccount {
    /// @return validationData 0 = signature valid; 1 = SIG_VALIDATION_FAILED.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData);
}
