// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {CounterLibByLib} from "src/CounterLibByLib.sol";
import "solidity_utils/lib.sol";

contract CounterLibByLibTest is Test {
    function setUp() public {
        CounterLibByLib t = new CounterLibByLib();
        t.test3();
    }

    function echidna_test1() public {
        console.log("here");
        bug();
    }
}

