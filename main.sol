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
