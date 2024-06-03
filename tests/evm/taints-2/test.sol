// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

contract sb {
    bytes32 answer = 0x60298f78cc0b47170ba79c10aa3851d7648bd96f2f8e46a19dbc777c36fb0c00;

    function lol(bytes32 x) public {
        require(msg.sender == address(0x0A101a8A56121470c49B5f477CE7eE7376a92c0a));
        require(x == answer);
        // require(x != answer);
        typed_bug("0x3322");
    }
}

contract main {
    // solution: a = 1
    function process(uint256 x) public {
        bytes32 v = keccak256(abi.encodePacked(x));
        sb(0x8B5b40e31dCB1166f17d31315E3b17b6Bfc82B37).lol(v);
    }
}
