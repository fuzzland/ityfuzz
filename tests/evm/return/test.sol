// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;
import "../../../solidity_utils/lib.sol";


interface Someone {
    function something() external returns (uint256, uint256);
}

contract main {
    function a(address x) public {
        (uint256 a, uint256 b) = Someone(msg.sender).something();
        require(a > 2, "ret <= 2");
        require(b > 2, "ret <= 2");
        bug();
    }
}
