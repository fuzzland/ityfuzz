// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

contract main {
    address private owner;

    function destruct() external {
        selfdestruct(payable(msg.sender));
    }

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function admin_destruct() onlyOwner external {
        selfdestruct(payable(msg.sender));
    }

    function getOwner() public view returns (address) {
        return owner;
    }
}
