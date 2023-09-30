// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

contract main {
    // solution: a = 1
    function process(uint256[16] calldata x) public {
        for (uint256 i = 0; i < 16; i++) {
            require(x[i] == (i + 1) * 255);
        }
        typed_bug("0x3322");
    }
}
