// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title Herreta
 * @notice A share-based asset vault with queued configuration, guarded withdrawals, and optional Merkle rewards.
 * @dev Designed for mainnet use: no ETH receive path, explicit external calls, pull-based flows, and hardened checks.
 */

// =============================================================
// Interfaces
// =============================================================

interface IERC20Minimal {
    function totalSupply() external view returns (uint256);
    function balanceOf(address a) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IERC20PermitLike {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

// =============================================================
// Libraries (self-contained, minimal)
// =============================================================

library SafeTransferLib {
    error STF_TransferFailed();
    error STF_TransferFromFailed();
    error STF_ApproveFailed();

    function safeTransfer(IERC20Minimal t, address to, uint256 amount) internal {
        (bool ok, bytes memory ret) =
            address(t).call(abi.encodeWithSelector(IERC20Minimal.transfer.selector, to, amount));
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert STF_TransferFailed();
    }

    function safeTransferFrom(IERC20Minimal t, address from, address to, uint256 amount) internal {
        (bool ok, bytes memory ret) = address(t).call(
            abi.encodeWithSelector(IERC20Minimal.transferFrom.selector, from, to, amount)
        );
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert STF_TransferFromFailed();
    }

    function safeApprove(IERC20Minimal t, address spender, uint256 amount) internal {
        (bool ok, bytes memory ret) =
            address(t).call(abi.encodeWithSelector(IERC20Minimal.approve.selector, spender, amount));
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert STF_ApproveFailed();
    }
}

library FixedPointMath {
    function mulDivDown(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) {
        unchecked {
            z = (x * y) / d;
        }
    }

    function mulDivUp(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) {
        unchecked {
            z = (x * y + (d - 1)) / d;
        }
    }
}

library MerkleProofLib {
    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            computed = computed < p ? keccak256(abi.encodePacked(computed, p)) : keccak256(abi.encodePacked(p, computed));
        }
        return computed == root;
    }
}

library ReentrancyGuardLite {
    error RGL_Reentrancy();

    struct Guard {
        uint256 state;
    }

    function init(Guard storage g) internal {
        if (g.state == 0) g.state = 1;
    }

    function enter(Guard storage g) internal {
        if (g.state != 1) revert RGL_Reentrancy();
        g.state = 2;
    }

    function exit(Guard storage g) internal {
        g.state = 1;
    }
}

// =============================================================
// Contract
// =============================================================

contract Herreta {
    using SafeTransferLib for IERC20Minimal;
    using FixedPointMath for uint256;
    using ReentrancyGuardLite for ReentrancyGuardLite.Guard;

    // =============================================================
    // Errors (distinct prefixes)
    // =============================================================

    error HR_ZeroAddress();
    error HR_BadAmount();
    error HR_BadState();
    error HR_NotAuthorized();
    error HR_TooSoon();
    error HR_Expired();
    error HR_QueueEmpty();
    error HR_QueueMismatch();
    error HR_InsufficientShares();
    error HR_InsufficientAssets();
    error HR_BadFee();
    error HR_BadRoot();
    error HR_ProofInvalid();
    error HR_AlreadyClaimed();
    error HR_Unsupported();

    // =============================================================
    // Events
    // =============================================================

    event HerretaInitialized(address indexed owner, address indexed asset, string name, string symbol);
    event OwnershipProposed(address indexed currentOwner, address indexed pendingOwner);
    event OwnershipAccepted(address indexed previousOwner, address indexed newOwner);
    event GuardianUpdated(address indexed oldGuardian, address indexed newGuardian);
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    event Deposit(address indexed caller, address indexed receiver, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);

    event FeeBpsQueued(uint256 indexed nonce, uint16 feeBps, uint256 eta);
    event FeeBpsApplied(uint256 indexed nonce, uint16 feeBps);
    event FeeRecipientQueued(uint256 indexed nonce, address feeRecipient, uint256 eta);
    event FeeRecipientApplied(uint256 indexed nonce, address feeRecipient);

    event WithdrawalDelayQueued(uint256 indexed nonce, uint32 delaySeconds, uint256 eta);
    event WithdrawalDelayApplied(uint256 indexed nonce, uint32 delaySeconds);

    event WithdrawalRequested(bytes32 indexed requestId, address indexed owner, address indexed receiver, uint256 shares, uint256 minAssets, uint256 validAfter);
    event WithdrawalCancelled(bytes32 indexed requestId, address indexed owner);
    event WithdrawalExecuted(bytes32 indexed requestId, address indexed caller, uint256 assetsOut, uint256 sharesBurned);

    event RewardsRootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot, uint64 indexed epoch);
    event RewardsClaimed(uint64 indexed epoch, address indexed account, uint256 amount, bytes32 leaf);

    event UniquenessAnchors(address indexed addressA, address indexed addressB, address indexed addressC, bytes32 hexA, bytes32 hexB, bytes32 hexC);

    // =============================================================
    // Metadata (shares)
    // =============================================================

    string public name;
    string public symbol;
    uint8 public immutable decimals;

    // =============================================================
    // Core vault config
    // =============================================================

    IERC20Minimal public immutable asset;

    address public owner;
    address public pendingOwner;
    address public guardian;
    bool public paused;

    // Fee on withdraw (bps, charged in assets, sent to feeRecipient)
    uint16 public feeBps;
    address public feeRecipient;

    // Withdrawal request delay (seconds)
    uint32 public withdrawalDelay;

    // =============================================================
    // Share accounting (ERC20-like, minimal)
    // =============================================================

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // =============================================================
    // Timed queue (single-slot per key; nonce increments)
    // =============================================================

    struct QueuedUint16 {
        uint256 nonce;
        uint16 value;
        uint256 eta;
        bool queued;
