// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.6.0;

contract Overflow {
    uint256 public val1;
    uint256 public val2;
    uint256 public val3;

    function addToA(uint256 amount) external {
        val1 += amount;
    }

    function sub(uint256 amount) external {
        val2 -= amount;
    }
}
