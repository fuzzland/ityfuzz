// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

contract main {
    function process() public returns (string memory) {
        assembly {
            calldatacopy(71236619313044, 0, 32)
            // balance the stack
            pop(1)
        }
        bug();
        return "Hello Contracts";
    }
}
