// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Caller {
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }

    function pay(uint256 a) public payable returns (uint256) {
        return a;
    }
}
