// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.6.2 <0.9.0;

import {Test, console2} from "forge-std/Test.sol";
import {PancakePair} from "../src/UniswapV2.sol";
import {TetherToken} from "../src/TetherToken.sol";

contract V2PairTest is Test {
    address[] public v2Pairs;
    address public weth = 0x4200000000000000000000000000000000000006;
    address public usdt_weth;

    function registerUniswapV2Pair(address pair) internal {
        (bool is_token0_succ,) = pair.call(abi.encodeWithSignature("token0()"));
        (bool is_token1_succ,) = pair.call(abi.encodeWithSignature("token0()"));
        require(is_token0_succ || is_token1_succ, "not a uniswap v2 pair");
        v2Pairs.push(pair);
    }

    function createUniswapV2Pair(address token1, address token2) internal returns (address) {
        UniswapV2Pair p = new UniswapV2Pair();
        p.initialize(token1, token2);
        registerUniswapV2Pair(address(p));
        return address(p);
    }

    function setUp() public {
        vm.createSelectFork("mainnet", 15725066);

        address usdt = address(new TetherToken(10000000000, "TetherToken", "USDT", 6));
        usdt_weth = createUniswapV2Pair(usdt, weth);
    }

    function invariant_1() public {
        assertEq(usdt_weth, address(0));
    }
}
