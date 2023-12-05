// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

contract sb {
    function lol(uint256 x) public {
        require(tx.origin == address(0x0A101a8A56121470c49B5f477CE7eE7376a92c0a));
        require(x * 2 + 12 == 12903821381231231234132132);
        typed_bug("0x3322");
    }
}

contract main {
    // solution: a = 1
    function process(uint256 x) public {
        sb(0x8B5b40e31dCB1166f17d31315E3b17b6Bfc82B37).lol(x * 5);
    }
}
