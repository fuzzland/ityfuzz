// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

interface X {
    function fx() external returns (uint256);
}

contract main {
    mapping(uint256 => uint256) knownsec;

    // solution: a = 1
    function process(uint256 a) public returns (string memory) {
        X x = X(0x0010000000000000000000000000000000000001);
        x.fx();
        require(a < 2, "2");
        knownsec[2] = a;
        bug();
        return "Hello Contracts";
    }
}
