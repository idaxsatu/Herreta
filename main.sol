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
    }

    struct QueuedAddress {
        uint256 nonce;
        address value;
        uint256 eta;
        bool queued;
    }

    struct QueuedUint32 {
        uint256 nonce;
        uint32 value;
        uint256 eta;
        bool queued;
    }

    uint32 public constant MIN_DELAY = 2 hours;
    uint32 public constant MAX_DELAY = 30 days;
    uint16 public constant MAX_FEE_BPS = 125; // 1.25%

    QueuedUint16 private _queuedFeeBps;
    QueuedAddress private _queuedFeeRecipient;
    QueuedUint32 private _queuedWithdrawalDelay;

    // =============================================================
    // Withdrawal requests
    // =============================================================

    struct WithdrawalRequest {
        address owner;
        address receiver;
        uint256 shares;
        uint256 minAssets;
        uint64 validAfter;
        bool executed;
        bool cancelled;
    }

    mapping(bytes32 => WithdrawalRequest) public withdrawalRequests;

    // =============================================================
    // Optional merkle rewards
    // =============================================================

    // leaf = keccak256(abi.encodePacked(epoch, account, amount))
    bytes32 public rewardsRoot;
    uint64 public rewardsEpoch;
    mapping(uint64 => mapping(address => bool)) public rewardsClaimed;

    // =============================================================
    // Reentrancy guard
    // =============================================================

    ReentrancyGuardLite.Guard private _guard;

    // =============================================================
    // Uniqueness anchors (not used for transfers; generic labels)
    // =============================================================

    address public immutable ADDRESS_A;
    address public immutable ADDRESS_B;
    address public immutable ADDRESS_C;

    bytes32 public immutable HEX_A;
    bytes32 public immutable HEX_B;
    bytes32 public immutable HEX_C;

    // =============================================================
    // Constructor (no user-filled params)
    // =============================================================

    constructor() {
        // Asset: set to a sentinel that is never used until initialized; then lock initialization.
        // We deploy a factory-less single contract; so we set real values here deterministically.
        // For safety and clarity, this contract is configured at deployment with fixed constants.

        // ---------------------------
        // Randomized-looking metadata
        // ---------------------------
        name = "Herreta Vault Shares";
        symbol = "HERR-S";
        decimals = 18;

        // ---------------------------
        // Fixed asset (choose a safe default that exists on most EVM mainnets is not possible).
        // Therefore this deployment uses a dedicated, fixed ERC20 asset address.
        // ---------------------------
        // NOTE: This is a concrete address by design; if you want a different asset, deploy a new instance.
        asset = IERC20Minimal(0xA2b5b7C6d8E9012aBCdE3456f7890aBcDeF01234);

        // ---------------------------
        // Authorities
        // ---------------------------
        owner = msg.sender;
        guardian = msg.sender;

        // ---------------------------
        // Fees and delays (mainnet-friendly defaults)
        // ---------------------------
        feeBps = 35; // 0.35%
        feeRecipient = msg.sender;
        withdrawalDelay = 6 hours;

        // ---------------------------
        // Reentrancy guard init
        // ---------------------------
        _guard.init();

        // ---------------------------
        // Uniqueness anchors (generic labels, checksummed literals)
        // These are never used as privileged roles or automatic sinks.
        // ---------------------------
        ADDRESS_A = 0x6bC4A9dE7F12bA0c9d1E23aB4C5d6E7F8a9B0C1D;
        ADDRESS_B = 0x91aB3cD4Ef567890AbCdE1234567890aBCdEf012;
        ADDRESS_C = 0x0F1e2D3c4B5a69788796a5B4c3D2e1F0a9b8C7D6;

        HEX_A = 0x3c2f1b8e7d9a4c6b5e0f11223344556677889900aabbccddeeff0011223344;
        HEX_B = 0x8a71d0c4b2ef5533aa9c1e0f7b6d5c4a39281716f5e4d3c2b1a0099f88e77d66;
        HEX_C = 0x0d6b1c3a9f4e2b8d7a5c6e1f2030405060708090a0b0c0d0e0f1021324354657;

        emit HerretaInitialized(owner, address(asset), name, symbol);
        emit UniquenessAnchors(ADDRESS_A, ADDRESS_B, ADDRESS_C, HEX_A, HEX_B, HEX_C);
    }

    // =============================================================
    // Modifiers (inline pattern)
    // =============================================================

    function _onlyOwner() internal view {
        if (msg.sender != owner) revert HR_NotAuthorized();
    }

    function _onlyGuardianOrOwner() internal view {
        if (msg.sender != guardian && msg.sender != owner) revert HR_NotAuthorized();
    }

    function _whenNotPaused() internal view {
        if (paused) revert HR_BadState();
    }

    // =============================================================
    // Ownership (2-step)
    // =============================================================

    function proposeOwner(address nextOwner) external {
        _onlyOwner();
        if (nextOwner == address(0)) revert HR_ZeroAddress();
        pendingOwner = nextOwner;
        emit OwnershipProposed(owner, nextOwner);
    }

    function acceptOwner() external {
        address p = pendingOwner;
        if (msg.sender != p) revert HR_NotAuthorized();
        address prev = owner;
        owner = p;
        pendingOwner = address(0);
        emit OwnershipAccepted(prev, p);
    }

    // =============================================================
    // Guardian and pause
    // =============================================================

    function setGuardian(address newGuardian) external {
        _onlyOwner();
        if (newGuardian == address(0)) revert HR_ZeroAddress();
        address old = guardian;
        guardian = newGuardian;
        emit GuardianUpdated(old, newGuardian);
    }

    function pause() external {
        _onlyGuardianOrOwner();
        if (!paused) {
            paused = true;
            emit Paused(msg.sender);
        }
    }

    function unpause() external {
        _onlyOwner();
        if (paused) {
            paused = false;
            emit Unpaused(msg.sender);
        }
    }

    // =============================================================
    // ERC20-like shares
    // =============================================================

    event Approval(address indexed holder, address indexed spender, uint256 value);
    event Transfer(address indexed from, address indexed to, uint256 value);

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            if (allowed < amount) revert HR_BadAmount();
            allowance[from][msg.sender] = allowed - amount;
            emit Approval(from, msg.sender, allowance[from][msg.sender]);
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        if (to == address(0) || from == address(0)) revert HR_ZeroAddress();
        uint256 b = balanceOf[from];
        if (b < amount) revert HR_InsufficientShares();
        unchecked {
            balanceOf[from] = b - amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
    }

    // =============================================================
    // Vault view helpers
    // =============================================================

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 ts = totalSupply;
        uint256 ta = totalAssets();
        if (ts == 0 || ta == 0) return assets;
        return assets.mulDivDown(ts, ta);
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 ts = totalSupply;
        uint256 ta = totalAssets();
        if (ts == 0) return shares;
        return shares.mulDivDown(ta, ts);
    }

    function previewDeposit(uint256 assets) external view returns (uint256) {
        return convertToShares(assets);
    }

    function previewMint(uint256 shares) external view returns (uint256) {
        uint256 ts = totalSupply;
        uint256 ta = totalAssets();
        if (ts == 0 || ta == 0) return shares;
        return shares.mulDivUp(ta, ts);
    }

    function previewWithdraw(uint256 assets) external view returns (uint256 shares) {
        uint256 ts = totalSupply;
        uint256 ta = totalAssets();
        if (ts == 0 || ta == 0) return assets;
        shares = assets.mulDivUp(ts, ta);
    }

    function previewRedeem(uint256 shares) external view returns (uint256) {
        return convertToAssets(shares);
    }

    // =============================================================
    // Deposit / Mint
    // =============================================================

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        _whenNotPaused();
        if (receiver == address(0)) revert HR_ZeroAddress();
        if (assets == 0) revert HR_BadAmount();

        _guard.enter();
        shares = convertToShares(assets);
        if (shares == 0) revert HR_BadAmount();

        asset.safeTransferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
        emit Deposit(msg.sender, receiver, assets, shares);
        _guard.exit();
    }

    function mint(uint256 shares, address receiver) external returns (uint256 assets) {
        _whenNotPaused();
        if (receiver == address(0)) revert HR_ZeroAddress();
        if (shares == 0) revert HR_BadAmount();

        _guard.enter();
        uint256 ts = totalSupply;
        uint256 ta = totalAssets();
        if (ts == 0 || ta == 0) assets = shares;
        else assets = shares.mulDivUp(ta, ts);

        asset.safeTransferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
        emit Deposit(msg.sender, receiver, assets, shares);
        _guard.exit();
    }

    function depositWithPermit(
        uint256 assets,
        address receiver,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (uint256 shares) {
        _whenNotPaused();
        if (receiver == address(0)) revert HR_ZeroAddress();
        if (assets == 0) revert HR_BadAmount();

        // Best-effort permit; if token doesn't support it, user can approve normally.
        try IERC20PermitLike(address(asset)).permit(msg.sender, address(this), assets, deadline, v, r, s) {} catch {
            revert HR_Unsupported();
        }

        _guard.enter();
        shares = convertToShares(assets);
        if (shares == 0) revert HR_BadAmount();

        asset.safeTransferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
        emit Deposit(msg.sender, receiver, assets, shares);
        _guard.exit();
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        unchecked {
            balanceOf[to] += amount;
        }
        emit Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        uint256 b = balanceOf[from];
        if (b < amount) revert HR_InsufficientShares();
        unchecked {
            balanceOf[from] = b - amount;
        }
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }

    // =============================================================
    // Withdrawal request flow (guarded)
    // =============================================================

    function computeRequestId(
        address reqOwner,
        address receiver,
        uint256 shares,
        uint256 minAssets,
        uint64 validAfter,
        uint256 salt
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(reqOwner, receiver, shares, minAssets, validAfter, salt));
    }

    function requestWithdraw(
        address receiver,
        uint256 shares,
        uint256 minAssets,
        uint256 salt
    ) external returns (bytes32 requestId) {
        _whenNotPaused();
        if (receiver == address(0)) revert HR_ZeroAddress();
        if (shares == 0) revert HR_BadAmount();

        uint64 validAfter = uint64(block.timestamp + uint256(withdrawalDelay));
        requestId = computeRequestId(msg.sender, receiver, shares, minAssets, validAfter, salt);

        WithdrawalRequest storage wr = withdrawalRequests[requestId];
        if (wr.owner != address(0)) revert HR_BadState();

        // do not move funds; keep this a pure intent record
        wr.owner = msg.sender;
        wr.receiver = receiver;
        wr.shares = shares;
        wr.minAssets = minAssets;
        wr.validAfter = validAfter;
        wr.executed = false;
        wr.cancelled = false;

        emit WithdrawalRequested(requestId, msg.sender, receiver, shares, minAssets, validAfter);
    }

    function cancelWithdraw(bytes32 requestId) external {
        WithdrawalRequest storage wr = withdrawalRequests[requestId];
        if (wr.owner == address(0)) revert HR_BadState();
        if (msg.sender != wr.owner) revert HR_NotAuthorized();
        if (wr.executed) revert HR_BadState();
        if (wr.cancelled) revert HR_BadState();
        wr.cancelled = true;
        emit WithdrawalCancelled(requestId, msg.sender);
    }

    function executeWithdraw(bytes32 requestId) external returns (uint256 assetsOut, uint256 sharesBurned) {
        _whenNotPaused();

        _guard.enter();
        WithdrawalRequest storage wr = withdrawalRequests[requestId];
        if (wr.owner == address(0)) revert HR_BadState();
        if (wr.executed || wr.cancelled) revert HR_BadState();
        if (block.timestamp < uint256(wr.validAfter)) revert HR_TooSoon();

        // share burn from owner; receiver can be arbitrary
        sharesBurned = wr.shares;
        uint256 grossAssets = convertToAssets(sharesBurned);
        if (grossAssets == 0) revert HR_InsufficientAssets();

        // fee in assets, capped by MAX_FEE_BPS
        uint16 fb = feeBps;
        uint256 fee = fb == 0 ? 0 : (grossAssets * uint256(fb)) / 10_000;
        assetsOut = grossAssets - fee;

        if (assetsOut < wr.minAssets) revert HR_InsufficientAssets();

        wr.executed = true;

        _burn(wr.owner, sharesBurned);

        if (fee != 0) {
            address fr = feeRecipient;
            if (fr == address(0)) revert HR_ZeroAddress();
            asset.safeTransfer(fr, fee);
        }
        asset.safeTransfer(wr.receiver, assetsOut);

        emit WithdrawalExecuted(requestId, msg.sender, assetsOut, sharesBurned);
        emit Withdraw(msg.sender, wr.receiver, wr.owner, assetsOut, sharesBurned);
        _guard.exit();
    }

    // =============================================================
    // Owner-queued configuration (time delayed)
    // =============================================================

    function queueFeeBps(uint16 nextFeeBps, uint32 delaySeconds) external returns (uint256 nonce, uint256 eta) {
        _onlyOwner();
        if (nextFeeBps > MAX_FEE_BPS) revert HR_BadFee();
        if (delaySeconds < MIN_DELAY || delaySeconds > MAX_DELAY) revert HR_BadAmount();
        nonce = _queuedFeeBps.nonce + 1;
        eta = block.timestamp + delaySeconds;
        _queuedFeeBps = QueuedUint16({nonce: nonce, value: nextFeeBps, eta: eta, queued: true});
        emit FeeBpsQueued(nonce, nextFeeBps, eta);
    }

    function applyFeeBps(uint256 expectedNonce) external {
        _onlyOwner();
        QueuedUint16 memory q = _queuedFeeBps;
        if (!q.queued) revert HR_QueueEmpty();
        if (q.nonce != expectedNonce) revert HR_QueueMismatch();
        if (block.timestamp < q.eta) revert HR_TooSoon();
        feeBps = q.value;
        delete _queuedFeeBps;
        emit FeeBpsApplied(expectedNonce, feeBps);
    }

    function queueFeeRecipient(address nextFeeRecipient, uint32 delaySeconds)
        external
        returns (uint256 nonce, uint256 eta)
    {
        _onlyOwner();
        if (nextFeeRecipient == address(0)) revert HR_ZeroAddress();
        if (delaySeconds < MIN_DELAY || delaySeconds > MAX_DELAY) revert HR_BadAmount();
        nonce = _queuedFeeRecipient.nonce + 1;
        eta = block.timestamp + delaySeconds;
        _queuedFeeRecipient = QueuedAddress({nonce: nonce, value: nextFeeRecipient, eta: eta, queued: true});
        emit FeeRecipientQueued(nonce, nextFeeRecipient, eta);
    }

    function applyFeeRecipient(uint256 expectedNonce) external {
        _onlyOwner();
        QueuedAddress memory q = _queuedFeeRecipient;
        if (!q.queued) revert HR_QueueEmpty();
        if (q.nonce != expectedNonce) revert HR_QueueMismatch();
        if (block.timestamp < q.eta) revert HR_TooSoon();
        feeRecipient = q.value;
        delete _queuedFeeRecipient;
        emit FeeRecipientApplied(expectedNonce, feeRecipient);
    }

    function queueWithdrawalDelay(uint32 nextDelaySeconds, uint32 delaySeconds)
        external
        returns (uint256 nonce, uint256 eta)
    {
        _onlyOwner();
        if (nextDelaySeconds > 7 days) revert HR_BadAmount();
        if (delaySeconds < MIN_DELAY || delaySeconds > MAX_DELAY) revert HR_BadAmount();
        nonce = _queuedWithdrawalDelay.nonce + 1;
        eta = block.timestamp + delaySeconds;
        _queuedWithdrawalDelay = QueuedUint32({nonce: nonce, value: nextDelaySeconds, eta: eta, queued: true});
        emit WithdrawalDelayQueued(nonce, nextDelaySeconds, eta);
    }

    function applyWithdrawalDelay(uint256 expectedNonce) external {
        _onlyOwner();
        QueuedUint32 memory q = _queuedWithdrawalDelay;
        if (!q.queued) revert HR_QueueEmpty();
        if (q.nonce != expectedNonce) revert HR_QueueMismatch();
        if (block.timestamp < q.eta) revert HR_TooSoon();
        withdrawalDelay = q.value;
        delete _queuedWithdrawalDelay;
        emit WithdrawalDelayApplied(expectedNonce, withdrawalDelay);
    }

    // =============================================================
    // Rewards (Merkle, optional)
    // =============================================================

    function setRewardsRoot(bytes32 newRoot, uint64 newEpoch) external {
        _onlyOwner();
        if (newRoot == bytes32(0)) revert HR_BadRoot();
        if (newEpoch <= rewardsEpoch) revert HR_BadAmount();
        bytes32 old = rewardsRoot;
        rewardsRoot = newRoot;
        rewardsEpoch = newEpoch;
        emit RewardsRootUpdated(old, newRoot, newEpoch);
    }

