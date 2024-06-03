// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {Create3Deployer} from "../src/Create3Deploy.sol";
import "solidity_utils/lib.sol";

contract Create3DeployerTest is Test {
    //
    Create3Deployer public create3Deployer = new Create3Deployer();
    TestCreate3 public testCreate3;

//    constructor() {
//        create3Deployer = new Create3Deployer();
//    }

    function setUp() public {
        require(address(create3Deployer) != address(0x0));
    }

    function test_deploy() public {
        bug();
        bytes32 b32 = hex"1234";
        address deployed_addr = create3Deployer.deploy(b32, type(TestCreate3).creationCode);
        bug();
    }
}

contract TestCreate3 {
    function test() public {}
}
