// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {PackedUserOperation} from "./IERC4337.sol";

enum PostOpMode {
    opSucceeded,
    opReverted,
    postOpReverted
}

/// @dev ERC-4337 v0.7 paymaster surface (vendored).
interface IPaymaster {
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData);

    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualGasUsedPenalty
    ) external;
}

/// @dev Minimal EntryPoint deposit surface (StakeManager).
interface IEntryPointStake {
    function depositTo(address account) external payable;
    function withdrawTo(address payable withdrawAddress, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

/// @title VerifyingPaymaster — sponsors only broker-co-signed UserOps (#164 E6).
/// @notice The Sybil gate for gasless master ops (threat-model §5): a UserOp is
///         sponsored ONLY if `brokerSigner` (an off-chain key the broker controls)
///         signed an approval over the op + validity window. The broker signs only
///         for an authenticated operator (valid J1 session), so a Sybil with no
///         operator session gets no sponsorship and must self-fund — no drain.
/// @dev    Standard EIP-191 verifying-paymaster pattern. The paymaster's EntryPoint
///         deposit must stay ≥ the Heima ExistentialDeposit (~0.1 HEI); fund via
///         `deposit()`. Per-operator budgets/rate-limits are enforced off-chain by
///         the broker before it co-signs (it holds the policy + the key).
contract VerifyingPaymaster is IPaymaster {
    address public immutable entryPoint;
    address public owner;
    address public brokerSigner;

    /// @dev paymasterAndData tail layout (after the 52-byte EntryPoint prefix:
    ///      20 paymaster + 16 verificationGasLimit + 16 postOpGasLimit):
    ///      validUntil(6) | validAfter(6) | signature(65).
    uint256 private constant VALID_TIMESTAMP_OFFSET = 52;
    uint256 private constant SIGNATURE_OFFSET = 64;

    event BrokerSignerChanged(address indexed previous, address indexed current);
    event OwnerChanged(address indexed previous, address indexed current);

    error NotEntryPoint();
    error NotOwner();
    error BadPaymasterDataLength();
    error ZeroAddress();

    constructor(address _entryPoint, address _brokerSigner, address _owner) {
        if (_entryPoint == address(0) || _brokerSigner == address(0) || _owner == address(0)) {
            revert ZeroAddress();
        }
        entryPoint = _entryPoint;
        brokerSigner = _brokerSigner;
        owner = _owner;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // ─── ERC-4337 paymaster ──────────────────────────────────────────────
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32, /* userOpHash */
        uint256 /* maxCost */
    ) external returns (bytes memory context, uint256 validationData) {
        if (msg.sender != entryPoint) revert NotEntryPoint();
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) =
            _parsePaymasterAndData(userOp.paymasterAndData);

        bytes32 signed = _ethSignedHash(getHash(userOp, validUntil, validAfter));
        bool sigOk = _recover(signed, signature) == brokerSigner;

        // ERC-4337 packed validationData: bit0 = sigFailed, [160:208) validUntil,
        // [208:256) validAfter. On bad sig we still return the time range so the
        // EntryPoint rejects with AA34 rather than a hard revert.
        validationData = _packValidationData(!sigOk, validUntil, validAfter);
        context = "";
    }

    function postOp(PostOpMode, bytes calldata, uint256, uint256) external {
        if (msg.sender != entryPoint) revert NotEntryPoint();
        // No per-op accounting on chain — budgets live in the broker. No-op.
    }

    /// @notice The digest the broker signs (EIP-191) to approve sponsorship.
    ///         Excludes the paymaster signature (avoids circularity) but binds
    ///         every other op field + chainId + this paymaster + brokerSigner +
    ///         the validity window.
    function getHash(PackedUserOperation calldata userOp, uint48 validUntil, uint48 validAfter)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                userOp.sender,
                userOp.nonce,
                keccak256(userOp.initCode),
                keccak256(userOp.callData),
                userOp.accountGasLimits,
                userOp.preVerificationGas,
                userOp.gasFees,
                // codex #1: bind the paymaster gas limits the broker approved
                // (paymasterAndData[20:52]) so a bundler can't inflate them while
                // reusing a valid sponsorship signature.
                userOp.paymasterAndData.length >= 52
                    ? bytes32(userOp.paymasterAndData[20:52])
                    : bytes32(0),
                block.chainid,
                address(this),
                brokerSigner,
                validUntil,
                validAfter
            )
        );
    }

    // ─── Owner / funding ─────────────────────────────────────────────────
    function setBrokerSigner(address newSigner) external onlyOwner {
        if (newSigner == address(0)) revert ZeroAddress();
        emit BrokerSignerChanged(brokerSigner, newSigner);
        brokerSigner = newSigner;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Fund this paymaster's EntryPoint deposit (keep it ≥ ED).
    function deposit() external payable {
        IEntryPointStake(entryPoint).depositTo{value: msg.value}(address(this));
    }

    function withdrawTo(address payable to, uint256 amount) external onlyOwner {
        IEntryPointStake(entryPoint).withdrawTo(to, amount);
    }

    function getDeposit() external view returns (uint256) {
        return IEntryPointStake(entryPoint).balanceOf(address(this));
    }

    // ─── Internals ───────────────────────────────────────────────────────
    function _parsePaymasterAndData(bytes calldata paymasterAndData)
        internal
        pure
        returns (uint48 validUntil, uint48 validAfter, bytes calldata signature)
    {
        if (paymasterAndData.length < SIGNATURE_OFFSET + 65) revert BadPaymasterDataLength();
        validUntil = uint48(bytes6(paymasterAndData[VALID_TIMESTAMP_OFFSET:VALID_TIMESTAMP_OFFSET + 6]));
        validAfter =
            uint48(bytes6(paymasterAndData[VALID_TIMESTAMP_OFFSET + 6:VALID_TIMESTAMP_OFFSET + 12]));
        signature = paymasterAndData[SIGNATURE_OFFSET:];
    }

    function _ethSignedHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function _recover(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0); // reject high-s (malleability)
        }
        return ecrecover(hash, v, r, s);
    }

    function _packValidationData(bool sigFailed, uint48 validUntil, uint48 validAfter)
        internal
        pure
        returns (uint256)
    {
        return (sigFailed ? 1 : 0) | (uint256(validUntil) << 160) | (uint256(validAfter) << 208);
    }
}
