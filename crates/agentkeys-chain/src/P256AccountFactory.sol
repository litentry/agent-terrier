// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {P256Account} from "./P256Account.sol";

/// @title P256AccountFactory — CREATE2 factory for passkey-gated master accounts.
/// @notice The account address is deterministic in (initial passkey, salt), so
///         the bootstrap ceremony (arch.md §9, #164 E7) can bind the master
///         address BEFORE the account is deployed — an attacker can deploy the
///         account but cannot make it act without the operator's passkey.
/// @dev    No external deterministic-deployer proxy is needed: CREATE2 is an
///         opcode the factory uses directly (Heima has no 0x4e59… proxy).
contract P256AccountFactory {
    address public immutable entryPoint;
    address public immutable k11Verifier;

    event AccountCreated(address indexed account, bytes32 indexed credIdHash, bytes32 salt);

    constructor(address _entryPoint, address _k11Verifier) {
        entryPoint = _entryPoint;
        k11Verifier = _k11Verifier;
    }

    /// @notice Deploy (or return, if already deployed) the account for an initial
    ///         passkey. Idempotent — safe to call from a UserOp's initCode.
    function createAccount(
        bytes32 credIdHash,
        uint256 pubX,
        uint256 pubY,
        bytes32 rpIdHash,
        bytes32 salt
    ) external returns (address) {
        address predicted = getAddress(credIdHash, pubX, pubY, rpIdHash, salt);
        if (predicted.code.length > 0) return predicted;
        P256Account acct =
            new P256Account{salt: salt}(entryPoint, k11Verifier, credIdHash, pubX, pubY, rpIdHash);
        emit AccountCreated(address(acct), credIdHash, salt);
        return address(acct);
    }

    /// @notice The deterministic account address for an initial passkey + salt.
    function getAddress(
        bytes32 credIdHash,
        uint256 pubX,
        uint256 pubY,
        bytes32 rpIdHash,
        bytes32 salt
    ) public view returns (address) {
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(P256Account).creationCode,
                abi.encode(entryPoint, k11Verifier, credIdHash, pubX, pubY, rpIdHash)
            )
        );
        return address(
            uint160(
                uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash)))
            )
        );
    }
}
