// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

contract main {
    // solution: a = 1
    function process(uint8[] calldata a) public returns (string memory){
        require(a[0] != 0, "a[0] != 1");
        require(a[1] != 0, "a[1] != 2");
        require(a[2] != 0, "a[2] != 3");
        require(a[3] == 4, "a[3] != 4");
        require(a[4] == 5, "a[4] != 5");
        require(a[5] == 5, "a[5] != 6");
        require(a[6] == 7, "a[6] != 7");
        require(a[7] == 8, "a[7] != 8");
        bug();
        typed_bug("0x3322");
        return 'Hello Contracts';
    }

    function process_two(uint8[] calldata a) public returns (string memory){
            require(a[0] != 9, "a[0] != 9");
            require(a[1] != 9, "a[1] != 9");
            require(a[2] != 9, "a[2] != 9");
            require(a[3] == 9, "a[3] == 9");
            require(a[4] == 9, "a[4] == 9");
            require(a[5] == 9, "a[5] == 9");
            require(a[6] == 9, "a[6] == 9");
            require(a[7] == 9, "a[7] == 9");
            typed_bug("0x10010");
            return 'Hello Contracts';
        }

    function process_three(uint8[] calldata a) public returns (string memory){
            require(a[0] != 3, "a[0] != 3");
            require(a[1] != 3, "a[1] != 3");
            require(a[2] != 3, "a[2] != 3");
            require(a[3] == 9, "a[3] == 9");
            require(a[4] == 9, "a[4] == 9");
            require(a[5] == 2, "a[5] == 2");
            require(a[6] == 1, "a[6] == 1");
            require(a[7] == 0, "a[7] == 0");
            typed_bug("0x1234");
            return 'Hello Contracts';
        }
}
