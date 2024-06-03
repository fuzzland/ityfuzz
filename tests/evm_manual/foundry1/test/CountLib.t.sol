// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {CallingContract, NewCallingContract} from "../src/CountLib.sol";
import "solidity_utils/lib.sol";

contract CounterTestLib is Test {
    CallingContract public callingContract;

    function setUp() public {
        callingContract = new CallingContract();
    }

    function testFuzz_doSomething() public {
        callingContract.callImplementationLib();
        bug();
    }
}

contract TestNewCallingContract is Test {
    NewCallingContract public newCallingContract;

    function setUp() public {
        newCallingContract = new NewCallingContract();
    }

    function testFuzz() public {
        newCallingContract.test_new();
        bug();
    }

}
