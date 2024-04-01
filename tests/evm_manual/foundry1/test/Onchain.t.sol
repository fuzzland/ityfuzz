// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";

contract OnchainTest is Test {
    function setUp() public {
        vm.createSelectFork("http://bsc.internal.fuzz.land", "latest");

        targetContract(0xdDc0CFF76bcC0ee14c3e73aF630C029fe020F907);
        targetContract(0x40eD17221b3B2D8455F4F1a05CAc6b77c5f707e3);
    }

    function invariant_1() public {}
}
