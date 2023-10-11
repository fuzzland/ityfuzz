// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

contract EZ {
    function b(bytes calldata) public {
        uint256 a = 1;
    }

    receive() external payable {
        if (msg.value > 99.99999 ether) {
            bug();
        }
    }

    // fallback() external payable {
    //     if (msg.value > 0) {
    //         bug();
    //     }
    // }
}
