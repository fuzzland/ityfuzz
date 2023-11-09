// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Reverter {
    error CustomError();

    function revertWithoutReason() public pure {
        revert();
    }

    function revertWithMessage(string memory message) public pure {
        require(false, message);
    }

    function revertWithCustomError() public pure {
        revert CustomError();
    }

    function nestedRevert(Reverter inner, string memory message) public pure {
        inner.revertWithMessage(message);
    }
}
