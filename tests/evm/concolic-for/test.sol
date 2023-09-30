// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

contract main {
    // solution: a = 1
    function pwn(uint256[7] calldata code) public {
        for (uint i = 0; i < 7; i++) {
            assert(1337 * i < code[i] && code[i] < 1337 * (i + 1));
        }
        typed_bug("0x3322");
    }
}
