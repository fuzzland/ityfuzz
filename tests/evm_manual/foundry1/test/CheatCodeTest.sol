// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Counter} from "../src/Counter.sol";
import { Script } from "forge-std/Script.sol";

contract CheatCodeTest is Test {
    Counter public counter1;
    address public deployer;
    uint256 deployerPrivateKey;

    function setUp() public {
        if (block.chainid == 1) { // Tenderly mainnet fork
            deployerPrivateKey = vm.envUint("TT");
//            deployerPrivateKey = 55;
            deployer = vm.addr(deployerPrivateKey);
        }
    }
}
