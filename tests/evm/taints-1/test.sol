// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

contract main {
    // solution: a = 1
    bytes32 public answer = 0x60298f78cc0b47170ba79c10aa3851d7648bd96f2f8e46a19dbc777c36fb0c00;

    // Magic word is "Solidity"
    function guess(string memory _word) public {
        if (keccak256(abi.encodePacked(_word)) == answer) {
            typed_bug("0x3322");
        }
    }
}
