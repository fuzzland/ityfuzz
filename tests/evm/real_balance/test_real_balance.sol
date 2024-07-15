// SPDX-License-Identifier: MIT
pragma solidity ^0.8.3;
import "solidity_utils/lib.sol";

contract Test1 {
    uint public x1 = 0;
    address public t;
    constructor(uint _x1, address _t) payable {
        x1 = _x1;
        t = _t;
    }

    function test1() payable public {
        x1 = 1;
        if (address(this).balance == 1800) {
            bug();
        }
    }
}


contract Test2 {
    uint x2 = 0;
    address public t;
    constructor(uint _x2, address _t) payable {
        x2 = _x2;
        t = _t;
    }

    function test1() public {
        x2 = 2;
    }
}

contract Test3 {
    uint x2 = 0;

    function test1() public {
        x2 = 2;
    }
}