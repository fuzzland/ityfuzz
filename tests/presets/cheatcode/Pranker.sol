// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Pranker {
    function check_sender() public view {
        require(msg.sender == address(0x100));
    }

    function check_sender_origin() public view {
        require(msg.sender == address(0x100));
        require(tx.origin == address(0x200));
    }
}
