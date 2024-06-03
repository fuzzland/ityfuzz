// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Counter} from "../src/Counter.sol";
import "solidity_utils/lib.sol";

contract CounterTestT is Test {
    Counter public counter;

    function setUp() public {
        counter = new Counter();
        counter.setNumber(0);
    }

    function test_Increment() public {
        counter.increment();
        assertEq(counter.number(), 2);
    }

    function testFuzz_In(uint256 x) public {
        counter.setNumber(x);
//        if (counter.number() != x - 1) {
//            bug();
//        }
        assertNotEq(counter.number(), x);
        bug();
    }
}
