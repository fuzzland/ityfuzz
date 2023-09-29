// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

contract EZ {
    // https://github.com/fuzzland/ityfuzz/blob/6c41c82e1e2ae902b7b6ecf7bba563e0a638b607/src/evm/vm.rs#L866
    // init with 3 wei or more to test
    constructor() payable {}

    function a() public {
        payable(msg.sender).transfer(1);
    }

    function b() public {
        if (address(this).balance == 0) {
            bug();
        }
    }
}
