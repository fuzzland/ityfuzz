// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);

    function transfer(address to, uint256 amount) external returns (bool);

    function allowance(address owner, address spender) external view returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);

    function expiry() external pure returns (uint48 _expiry);


    function burn(address from, uint256 amount) external;

    function underlying() external pure returns (IERC20 _underlying);
    }

contract main {
    uint256 private locked = 1;

    modifier nonReentrant() {
        require(locked == 1, "REENTRANCY");

        locked = 2;

        _;

        locked = 1;
    }

    function redeem(IERC20 token_, uint256 amount_) external nonReentrant {
        require(uint48(block.timestamp) >= token_.expiry(), "NOT EXPIRED");
        token_.burn(msg.sender, amount_);
        token_.underlying().transfer(msg.sender, amount_);
        bug();
    }
}
