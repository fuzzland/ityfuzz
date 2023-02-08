// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

contract main {
    uint256 v;

    // solution: a = 1
    function process(uint256 a) public returns (string memory){
        require(a < 2, "2");
        v += 1;
        return 'Hello Contracts';
    }

    function goal() public returns (uint256) {
        require(v > 10, "2");
        return v;
    }

    function oracle_harness() public view returns (bool) {
        return v > 10;
    }
}
