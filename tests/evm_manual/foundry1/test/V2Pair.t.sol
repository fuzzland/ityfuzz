// SPDX-License-Identifier: UNLICENSED
// cargo run evm -f -m V2PairTest -- forge build

pragma solidity >=0.6.2 <0.9.0;

import {Test, console2} from "forge-std/Test.sol";
import {PancakePair} from "../src/UniswapV2.sol";
import {ItyFuzzToken} from "../src/ItyFuzzToken.sol";

contract V2PairTest is Test {
    address[] private _v2Pairs;
    address public weth = 0x4200000000000000000000000000000000000006;
    address public usdt_weth;

    // FYI: tests/evm_manual/foundry1/lib/forge-std/src/StdInvariant.sol
    function v2Pairs() public view returns (address[] memory) {
        return _v2Pairs;
    }

    function registerUniswapV2Pair(address pair) internal {
        (bool is_token0_succ,) = pair.call(abi.encodeWithSignature("token0()"));
        (bool is_token1_succ,) = pair.call(abi.encodeWithSignature("token1()"));
        require(is_token0_succ || is_token1_succ, "not a uniswap v2 pair");
        _v2Pairs.push(pair);
    }

    function createUniswapV2Pair(address token1, address token2) internal returns (address) {
        PancakePair p = new PancakePair();
        p.initialize(token1, token2);
        registerUniswapV2Pair(address(p));
        return address(p);
    }

    function setUp() public {
        address usdt = address(new ItyFuzzToken(type(uint112).max));
        usdt_weth = createUniswapV2Pair(usdt, weth);
    }

    function invariant_1() public {
        assertEq(v2Pairs().length, 0); // bug
    }
}
