pub enum UniswapVer {
    V1,
    V2,
    V3,
}

pub fn is_uniswap() -> Option<UniswapVer> {
    None
}

// if it is uniswap pair, then we deploy a router contract specifically for such a pair
// this saves significant amount of time since exploring router on chain takes infinite amount
// of time due to large number of pairs

// 1. fetch erc20 address of pair's both direction
// 2. append additional testcase: calling router.swap, router.addLiquidity, router.removeLiquidity

// to avoid recognizing this as re-entrancy, we deploy each router contract for each side of each pair

// function swap(
//     uint amountIn,
//     uint amountOutMin,
// ) external {
//     IERC20(token0).safeTransferFrom(msg.sender, pair, amountIn);
//     IUniswapV2Pair(pair).swap(amount0Out, amount1Out, to, new bytes(0));
// }
