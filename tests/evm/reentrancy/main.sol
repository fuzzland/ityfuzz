// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;
import "../../../solidity_utils/lib.sol";


interface Someone {
    function something() external;
}

contract main {
    uint256 balances;
    address owner;
    uint256 is_success;


    constructor() {
        balances = 1;
        is_success = 0;
    }

    function a(address x) public {
        require(balances > 0);
        is_success += 1;
        Someone(x).something();
        balances = 0;
    }

    function b() public {
        if (is_success == 3) {
            bug();
        }
    }
}
