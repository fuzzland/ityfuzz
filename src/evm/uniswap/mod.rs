use crate::evm::abi::{AArray, AEmpty, BoxedABI, A256};

use crate::evm::onchain::endpoints::Chain;

use crypto::digest::Digest;
use crypto::sha3::Sha3;

use permutator::CartesianProductIterator;
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::HashMap;

use std::ops::Deref;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use crate::evm::types::{EVMAddress, EVMU256};

pub enum UniswapVer {
    V1,
    V2,
    V3,
}

pub fn is_uniswap() -> Option<UniswapVer> {
    None
}

#[derive(Clone, Debug)]
pub enum UniswapProvider {
    PancakeSwap,
    SushiSwap,
    UniswapV2,
    UniswapV3,
    Biswap,
}

impl UniswapProvider {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pancakeswap" => Some(Self::PancakeSwap),
            "sushiswap" => Some(Self::SushiSwap),
            "uniswapv2" => Some(Self::UniswapV2),
            "uniswapv3" => Some(Self::UniswapV3),
            "biswap" => Some(Self::Biswap),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct UniswapInfo {
    pub pool_fee: usize,
    pub router: EVMAddress,
    pub factory: EVMAddress,
    pub init_code_hash: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SwapResult {
    pub amount: EVMU256,
    pub new_reserve_in: EVMU256,
    pub new_reserve_out: EVMU256,
}

#[derive(Clone, Debug, Default)]
pub struct PairContext {
    pub pair_address: EVMAddress,
    pub next_hop: EVMAddress,
    pub side: u8,
    pub uniswap_info: Arc<UniswapInfo>,
    pub initial_reserves: (EVMU256, EVMU256),
}

impl PairContext {
    // pub fn update_reserve_pre<I, S>(
    //     &mut self,
    //     ctx: &mut EVMOracleCtx,
    // ) {
    //     let mut abi = BoxedABI::new(Box::new(AEmpty {}));
    //     abi.function = [0x09, 0x02, 0xf1, 0xac];
    //     let res = ctx.call_pre(&mut EVMInput {
    //         caller: Default::default(),
    //         contract: self.pair_address,
    //         data: Some(abi),
    //         sstate: StagedVMState::new_uninitialized(),
    //         sstate_idx: 0,
    //         txn_value: None,
    //         step: false,
    //         env: Default::default(),
    //         access_pattern: ctx.input.get_access_pattern().clone(),
    //         #[cfg(any(test, feature = "debug"))]
    //         direct_data: Default::default()
    //     });
    //
    //     self.reserve0 = EVMU256::from_big_endian(&res.output[0..32]);
    //     self.reserve1 = EVMU256::from_big_endian(&res.output[32..64]);
    // }
    //
    // pub fn update_reserve_post<I, S>(
    //     &mut self,
    //     ctx: &mut EVMOracleCtx,
    // ) {
    //     let mut abi = BoxedABI::new(Box::new(AEmpty {}));
    //     abi.function = [0x09, 0x02, 0xf1, 0xac];
    //     let res = ctx.call_pre(&mut EVMInput {
    //         caller: Default::default(),
    //         contract: self.pair_address,
    //         data: Some(abi),
    //         sstate: StagedVMState::new_uninitialized(),
    //         sstate_idx: 0,
    //         txn_value: None,
    //         step: false,
    //         env: Default::default(),
    //         access_pattern: ctx.input.get_access_pattern().clone(),
    //         #[cfg(any(test, feature = "debug"))]
    //         direct_data: Default::default()
    //     });
    //
    //     self.reserve0 = EVMU256::from_big_endian(&res.output[0..32]);
    //     self.reserve1 = EVMU256::from_big_endian(&res.output[32..64]);
    // }

    pub fn get_amount_out(&self, amount_in: EVMU256, reserve0: EVMU256, reserve1: EVMU256) -> SwapResult {
        self.uniswap_info.calculate_amounts_out(
            if amount_in > EVMU256::from(u128::MAX) {
                EVMU256::from(u128::MAX)
            } else {
                amount_in
            },
            if self.side == 0 { reserve0 } else { reserve1 },
            if self.side == 0 { reserve1 } else { reserve0 },
        )
    }

    pub fn get_amount_in(&self, amount_out: EVMU256, reserve0: EVMU256, reserve1: EVMU256) -> SwapResult {
        self.uniswap_info.calculate_amounts_in(
            if amount_out > EVMU256::from(u128::MAX) {
                EVMU256::from(u128::MAX)
            } else {
                amount_out
            },
            if self.side == 0 { reserve1 } else { reserve0 },
            if self.side == 0 { reserve0 } else { reserve1 },
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct PathContext {
    pub route: Vec<Rc<RefCell<PairContext>>>,
    pub final_pegged_ratio: EVMU256,
    pub final_pegged_pair: Rc<RefCell<Option<PairContext>>>,
}

#[derive(Clone, Debug, Default)]
pub struct TokenContext {
    pub swaps: Vec<PathContext>,
    pub is_weth: bool,
    pub weth_address: EVMAddress,
    pub address: EVMAddress,
}

impl PathContext {
    pub fn get_amount_out(
        &self,
        amount_in: EVMU256,
        reserve_data: &mut HashMap<EVMAddress, (EVMU256, EVMU256)>,
    ) -> EVMU256 {
        let mut amount_in = amount_in;

        // address => (new reserve0, new reserve1)
        for pair in self.route.iter() {
            let p = pair.deref().borrow();
            let reserves = match reserve_data.get(&p.pair_address) {
                None => p.initial_reserves,
                Some(reserves) => reserves.clone(),
            };
            let swap_result = p.get_amount_out(amount_in, reserves.0, reserves.1);
            reserve_data.insert(
                p.pair_address,
                (
                    if p.side == 0 {
                        swap_result.new_reserve_in
                    } else {
                        swap_result.new_reserve_out
                    },
                    if p.side == 0 {
                        swap_result.new_reserve_out
                    } else {
                        swap_result.new_reserve_in
                    },
                ),
            );
            amount_in = swap_result.amount;
        }
        amount_in * self.final_pegged_ratio
    }

    pub fn get_amount_in(
        &self,
        percentage: usize,
        reserve_data: &HashMap<EVMAddress, (EVMU256, EVMU256)>,
    ) -> EVMU256 {
        let initial_pair = self.route.first().unwrap().deref().borrow();
        let initial_reserve = match reserve_data.get(&initial_pair.pair_address) {
            None => initial_pair.initial_reserves,
            Some(reserves) => reserves.clone(),
        };

        let mut amount_out = {
            if initial_pair.side == 0 {
                initial_reserve.0
            } else {
                initial_reserve.1
            }
        } * EVMU256::from(percentage) / EVMU256::from(1000);
        println!("amount_out: {}", amount_out);

        // address => (new reserve0, new reserve1)

        macro_rules! process_pair {
            ($pair: expr) => {{
                let reserves = match reserve_data.get(&$pair.pair_address) {
                    None => $pair.initial_reserves,
                    Some(reserves) => reserves.clone(),
                };
                let swap_result = $pair.get_amount_in(amount_out, reserves.0, reserves.1);
                amount_out = swap_result.amount;
            }};
        }

        for pair in self.route.iter() {
            // let p = ;
            process_pair!(pair.deref().borrow());
        }

        // wtf?
        if self.final_pegged_pair.deref().borrow().is_some() {
            process_pair!(self.final_pegged_pair.deref().borrow().as_ref().unwrap());
        }
        amount_out
    }
}

static mut WETH_MAX: EVMU256 = EVMU256::ZERO;

pub fn generate_uniswap_router_call(
    token: &TokenContext,
    path_idx: usize,
    amount_in: EVMU256,
    to: EVMAddress,
) -> Option<(BoxedABI, EVMU256, EVMAddress)> {
    unsafe {
        WETH_MAX = EVMU256::from(10).pow(EVMU256::from(24));
    }
    // function swapExactETHForTokensSupportingFeeOnTransferTokens(
    //     uint amountOutMin,
    //     address[] calldata path,
    //     address to,
    //     uint deadline
    // )
    if token.is_weth {
        let mut abi = BoxedABI::new(Box::new(AEmpty {}));
        abi.function = [0xd0, 0xe3, 0x0d, 0xb0]; // deposit
                                                 // EVMU256::from(perct) * unsafe {WETH_MAX}
        Some((abi, amount_in, token.weth_address))
    } else {
        if token.swaps.len() == 0 {
            return None;
        }
        let path_ctx = &token.swaps[path_idx % token.swaps.len()];
        // let amount_in = path_ctx.get_amount_in(perct, reserve);
        let mut path: Vec<EVMAddress> = path_ctx
            .route
            .iter()
            .rev()
            .map(|pair| pair.deref().borrow().next_hop)
            .collect();
        // when it is pegged token or weth
        if path.len() == 0 || path[0] != token.weth_address {
            path.insert(0, token.weth_address);
        }
        path.insert(path.len(), token.address);
        let mut abi = BoxedABI::new(Box::new(AArray {
            data: vec![
                BoxedABI::new(Box::new(A256 {
                    data: vec![0; 32],
                    is_address: false,
                    dont_mutate: false,
                })),
                BoxedABI::new(Box::new(AArray {
                    data: path
                        .iter()
                        .map(|addr| {
                            BoxedABI::new(Box::new(A256 {
                                data: addr.as_bytes().to_vec(),
                                is_address: true,
                                dont_mutate: false,
                            }))
                        })
                        .collect(),
                    dynamic_size: true,
                })),
                BoxedABI::new(Box::new(A256 {
                    data: to.0.to_vec(),
                    is_address: true,
                    dont_mutate: false,
                })),
                BoxedABI::new(Box::new(A256 {
                    data: vec![0xff; 32],
                    is_address: false,
                    dont_mutate: false,
                })),
            ],
            dynamic_size: false,
        }));
        abi.function = [0xb6, 0xf9, 0xde, 0x95]; // swapExactETHForTokensSupportingFeeOnTransferTokens

        match path_ctx.final_pegged_pair.deref().borrow().as_ref() {
            None => Some((
                abi,
                amount_in,
                path_ctx
                    .route
                    .last()
                    .unwrap()
                    .deref()
                    .borrow()
                    .uniswap_info
                    .router,
            )),
            Some(info) => Some((abi, amount_in, info.uniswap_info.router)),
        }
    }
}

pub fn liquidate_all_token(
    tokens: Vec<(&TokenContext, EVMU256)>,
    initial_reserve_data: HashMap<EVMAddress, (EVMU256, EVMU256)>,
) -> (EVMU256, HashMap<EVMAddress, (EVMU256, EVMU256)>) {
    let mut swap_combos: Vec<Vec<(PathContext, EVMU256)>> = Vec::new();
    for (token, amt) in tokens {
        let swaps: Vec<(PathContext, EVMU256)> =
            token.swaps.iter().map(|swap| (swap.clone(), amt)).collect();
        if swaps.len() > 0 {
            swap_combos.push(swaps);
        }
    }

    if swap_combos.len() == 0 {
        return (EVMU256::ZERO, initial_reserve_data);
    }

    let mut possible_amount_out = vec![];

    CartesianProductIterator::new(
        swap_combos
            .iter()
            .map(|x| x.as_slice())
            .collect::<Vec<&[(PathContext, EVMU256)]>>()
            .as_slice(),
    )
    .into_iter()
    .for_each(|swaps| {
        let mut reserve_data = initial_reserve_data.clone();
        let mut total_amount_out = EVMU256::ZERO;
        for (path, amt) in &swaps {
            total_amount_out += path.get_amount_out(amt.clone(), &mut reserve_data);
        }
        possible_amount_out.push((total_amount_out, reserve_data));
    });

    let mut best_quote = EVMU256::ZERO;
    let mut best_reserve_data = None;
    for (amount_out, reserve_data) in possible_amount_out {
        if amount_out > best_quote {
            best_quote = amount_out;
            best_reserve_data = Some(reserve_data);
        }
    }

    (
        best_quote,
        best_reserve_data.unwrap_or(initial_reserve_data),
    )
}

pub fn get_uniswap_info(provider: &UniswapProvider, chain: &Chain) -> UniswapInfo {
    match (provider, chain) {
        (&UniswapProvider::PancakeSwap, &Chain::BSC) => UniswapInfo {
            pool_fee: 25,
            router: EVMAddress::from_str("0x10ed43c718714eb63d5aa57b78b54704e256024e").unwrap(),
            factory: EVMAddress::from_str("0xca143ce32fe78f1f7019d7d551a6402fc5350c73").unwrap(),
            init_code_hash: hex::decode(
                "00fb7f630766e6a796048ea87d01acd3068e8ff67d078148a3fa3f4a84f69bd5",
            )
            .unwrap(),
        },
        (&UniswapProvider::UniswapV2, &Chain::ETH) => UniswapInfo {
            pool_fee: 3,
            router: EVMAddress::from_str("0x7a250d5630b4cf539739df2c5dacb4c659f2488d").unwrap(),
            factory: EVMAddress::from_str("0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f").unwrap(),
            init_code_hash: hex::decode(
                "96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f",
            )
            .unwrap(),
        },
        _ => panic!(
            "Uniswap provider {:?} @ chain {:?} not supported",
            provider, chain
        ),
    }
}

impl UniswapInfo {
    // todo: add support for Uniswap V3
    pub fn calculate_amounts_out(
        &self,
        amount_in: EVMU256,
        reserve_in: EVMU256,
        reserve_out: EVMU256,
    ) -> SwapResult {
        let amount_in_with_fee = amount_in * EVMU256::from(10000 - self.pool_fee);
        let numerator = amount_in_with_fee * reserve_out;
        let denominator = reserve_in * EVMU256::from(10000) + amount_in_with_fee;
        if denominator == EVMU256::ZERO {
            return SwapResult {
                amount: EVMU256::ZERO,
                new_reserve_in: reserve_in,
                new_reserve_out: reserve_out,
            };
        }
        let amount_out = numerator / denominator;
        SwapResult {
            amount: amount_out,
            new_reserve_in: reserve_in + amount_in,
            new_reserve_out: reserve_out - amount_out,
        }
    }

    pub fn calculate_amounts_in(
        &self,
        amount_out: EVMU256,
        reserve_in: EVMU256,
        reserve_out: EVMU256,
    ) -> SwapResult {
        println!("calculate_amounts_in amount_out: {}", amount_out);
        println!("calculate_amounts_in reserve_in: {}", reserve_in);
        println!("calculate_amounts_in reserve_out: {}", reserve_out);

        let adjusted_amount_out = if amount_out > reserve_out {
            reserve_out - EVMU256::from(1)
        } else {
            amount_out
        };

        let numerator = reserve_in * adjusted_amount_out * EVMU256::from(10000);
        let denominator = (reserve_out - adjusted_amount_out) * EVMU256::from(10000 - self.pool_fee);
        if denominator == EVMU256::ZERO {
            return SwapResult {
                amount: EVMU256::ZERO,
                new_reserve_in: reserve_in,
                new_reserve_out: reserve_out,
            };
        }
        let amount_in = (numerator / denominator) + EVMU256::from(1);
        println!("calculate_amounts_in amount_in: {}", amount_in);
        SwapResult {
            amount: amount_in,
            new_reserve_in: reserve_in + amount_in,
            new_reserve_out: (reserve_out - adjusted_amount_out),
        }
    }

    pub fn keccak(data: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha3::keccak256();
        let mut output = [0u8; 32];
        hasher.input(&data);
        hasher.result(&mut output);
        output.to_vec()
    }

    // calculate CREATE2 address for a pair without making any external calls
    pub fn get_pair_address(&self, token_a: EVMAddress, token_b: EVMAddress) -> EVMAddress {
        let mut tokens = vec![token_a, token_b];
        tokens.sort();
        let mut data = [0u8; 40];
        data[0..20].copy_from_slice(&tokens[0].0);
        data[20..].copy_from_slice(&tokens[1].0);
        let keccak_token = Self::keccak(data.to_vec());
        let mut data = [0u8; 85];
        data[0] = 0xff;
        data[1..21].copy_from_slice(&self.factory.0);
        data[21..53].copy_from_slice(&keccak_token);
        data[53..85].copy_from_slice(&self.init_code_hash);
        let keccak = Self::keccak(data.to_vec());
        return EVMAddress::from_slice(&keccak[12..]);
    }
}

pub fn reserve_parser(reserve_slot: &EVMU256) -> (EVMU256, EVMU256) {
    let mut reserve_bytes: [u8; 32] = reserve_slot.to_be_bytes();
    let reserve_0 = EVMU256::try_from_be_slice(&reserve_bytes[4..18]).unwrap();
    let reserve_1 = EVMU256::try_from_be_slice(&reserve_bytes[18..32]).unwrap();
    (reserve_0, reserve_1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::onchain::endpoints::Chain;
    use std::str::FromStr;

    #[test]
    fn test_get_pair_address() {
        let uniswap_info = get_uniswap_info(&UniswapProvider::UniswapV2, &Chain::ETH);
        let token_a = EVMAddress::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap();
        let token_b = EVMAddress::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
        let pair_address = uniswap_info.get_pair_address(token_a, token_b);
        assert_eq!(
            pair_address,
            EVMAddress::from_str("0xae461ca67b15dc8dc81ce7615e0320da1a9ab8d5").unwrap()
        );
    }

    macro_rules! wrap {
        ($x: expr) => {
            Rc::new(RefCell::new($x))
        };
    }

    #[test]
    fn test_simple_liquidate() {
        // 1000 * 9975 * 10000000000 / (10 * 10000 + 1000 * 9975) = 9900744416.87345
        let mut reserve_data = HashMap::new();
        reserve_data.insert(
            EVMAddress::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
            (EVMU256::from(10), EVMU256::from(10000000000 as u64)),
        );
        let path = PathContext {
            route: vec![wrap!(PairContext {
                pair_address: EVMAddress::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                side: 0,
                uniswap_info: Arc::new(get_uniswap_info(
                    &UniswapProvider::PancakeSwap,
                    &Chain::BSC
                )),
                initial_reserves: (Default::default(), Default::default()),
                next_hop: Default::default(),
            })],
            // 0.1 * 10^5 eth / token
            final_pegged_ratio: EVMU256::from(1),
            final_pegged_pair: Rc::new(RefCell::new(None)),
        };
        let res_out = path.get_amount_out(EVMU256::from(1), &mut reserve_data.clone());
        let res_in = path.get_amount_in(100, &mut reserve_data);

        assert_eq!(res_out, EVMU256::from(907024323 as u64));
        assert_eq!(res_in, EVMU256::from(1113895851 as u64));
    }

    #[test]
    fn test_long_path_liquidate() {
        // 1000 * 9975 * 10000000000 / (10 * 10000 + 1000 * 9975) = 9900744416.87345
        // 9900744416 * 9975 * 40 / (10000 * 10000 + 9900744416 * 9975) = 39.99999

        let mut reserve_data = HashMap::new();
        reserve_data.insert(
            EVMAddress::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
            (EVMU256::from(1000), EVMU256::from(10000000000 as u64)),
        );
        reserve_data.insert(
            EVMAddress::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(),
            (EVMU256::from(10000000), EVMU256::from(4000000000 as u64)),
        );
        let path = PathContext {
            route: vec![
                wrap!(PairContext {
                    pair_address: EVMAddress::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                        .unwrap(),
                    side: 0,
                    uniswap_info: Arc::new(get_uniswap_info(
                        &UniswapProvider::PancakeSwap,
                        &Chain::BSC
                    )),
                    initial_reserves: (Default::default(), Default::default()),
                    next_hop: Default::default(),
                }),
                wrap!(PairContext {
                    pair_address: EVMAddress::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                        .unwrap(),
                    side: 1,
                    uniswap_info: Arc::new(get_uniswap_info(
                        &UniswapProvider::PancakeSwap,
                        &Chain::BSC
                    )),
                    initial_reserves: (Default::default(), Default::default()),
                    next_hop: Default::default(),
                }),
            ],
            final_pegged_ratio: EVMU256::from(1),
            final_pegged_pair: Rc::new(RefCell::new(None)),
        };
        let res_in = path.get_amount_in(1, &mut reserve_data.clone());
        let res_out = path.get_amount_out(EVMU256::from(1), &mut reserve_data);

        assert_eq!(res_in, EVMU256::from(25214 as u64));
        assert_eq!(res_out, EVMU256::from(24788 as u64));
    }

    #[test]
    fn test_insufficient_liquidate() {
        // 1000 * 9975 * 0 / (10 * 10000 + 1000 * 9975) = 0
        let mut delta = HashMap::new();
        delta.insert(
            EVMAddress::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
            (EVMU256::from(10), EVMU256::from(0 as u64)),
        );
        let path = PathContext {
            route: vec![wrap!(PairContext {
                pair_address: EVMAddress::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                side: 0,
                uniswap_info: Arc::new(get_uniswap_info(
                    &UniswapProvider::PancakeSwap,
                    &Chain::BSC
                )),
                initial_reserves: (Default::default(), Default::default()),
                next_hop: Default::default(),
            })],
            final_pegged_ratio: EVMU256::from(1),
            final_pegged_pair: Rc::new(RefCell::new(None)),
        };
        let res_out = path.get_amount_out(EVMU256::from(1000), &mut delta);
        let res_in = path.get_amount_in(1000, &mut delta);
        assert_eq!(res_out, EVMU256::from(0 as u64));
        assert_eq!(res_in, EVMU256::from(0 as u64));
    }

    #[test]
    fn test_multi_paths_liquidate() {
        // 1000 * 9975 * 10 / (10 * 10000 + 1000 * 9975) = 9.900744416873449
        // 1000 * 9975 * 50 / (25 * 10000 + 1000 * 9975) = 48.77750611246944

        let mut reserve_data = HashMap::new();
        reserve_data.insert(
            EVMAddress::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            (EVMU256::from(25), EVMU256::from(50 as u64)),
        );
        reserve_data.insert(
            EVMAddress::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            (EVMU256::from(10), EVMU256::from(10 as u64)),
        );

        let t0 = TokenContext {
            swaps: vec![
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: EVMAddress::from_str("0x0000000000000000000000000000000000000000")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                        next_hop: Default::default(),
                    })],
                    final_pegged_ratio: EVMU256::from(20),
                    final_pegged_pair: Rc::new(RefCell::new(None)),
                },
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: EVMAddress::from_str("0x0000000000000000000000000000000000000001")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                        next_hop: Default::default(),
                    })],
                    final_pegged_ratio: EVMU256::from(1),
                    final_pegged_pair: Rc::new(RefCell::new(None)),
                },
            ],
            is_weth: false,
            weth_address: Default::default(),
            address: Default::default(),
        };
        let (amt, reserve) = liquidate_all_token(vec![(&t0, EVMU256::from(1000))], reserve_data);

        assert_eq!(amt, EVMU256::from(48 * 20 as u64));
    }

    #[test]
    fn test_multi_tokens_liquidate() {
        // 1000 * 9975 * 50 / (25 * 10000 + 1000 * 9975) = 48.77750611246944
        // 10000 * 9975 * 10 / (10 * 10000 + 10000 * 9975) = 9.900744416873449

        let mut reserve_data = HashMap::new();
        reserve_data.insert(
            EVMAddress::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            (EVMU256::from(25), EVMU256::from(50 as u64)),
        );
        reserve_data.insert(
            EVMAddress::from_str("0x0000000000000000000000000000000000000002").unwrap(),
            (EVMU256::from(10), EVMU256::from(10 as u64)),
        );
        reserve_data.insert(
            EVMAddress::from_str("0x0000000000000000000000000000000000000003").unwrap(),
            (EVMU256::from(10), EVMU256::from(10 as u64)),
        );

        let t0 = TokenContext {
            swaps: vec![
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: EVMAddress::from_str("0x0000000000000000000000000000000000000000")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                        next_hop: Default::default(),
                    })],
                    final_pegged_ratio: EVMU256::from(1),
                    final_pegged_pair: Rc::new(RefCell::new(None)),
                },
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: EVMAddress::from_str("0x0000000000000000000000000000000000000003")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                        next_hop: Default::default(),
                    })],
                    final_pegged_ratio: EVMU256::from(1),
                    final_pegged_pair: Rc::new(RefCell::new(None)),
                },
            ],
            is_weth: false,
            weth_address: Default::default(),
            address: Default::default(),
        };

        let t1 = TokenContext {
            swaps: vec![
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: EVMAddress::from_str("0x0000000000000000000000000000000000000000")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                        next_hop: Default::default(),
                    })],
                    final_pegged_ratio: EVMU256::from(1),
                    final_pegged_pair: Rc::new(RefCell::new(None)),
                },
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: EVMAddress::from_str("0x0000000000000000000000000000000000000002")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                        next_hop: Default::default(),
                    })],
                    final_pegged_ratio: EVMU256::from(1),
                    final_pegged_pair: Rc::new(RefCell::new(None)),
                },
            ],
            is_weth: false,
            weth_address: Default::default(),
            address: Default::default(),
        };

        let (amt, reserve) = liquidate_all_token(
            vec![(&t0, EVMU256::from(1000)), (&t1, EVMU256::from(10000))],
            reserve_data,
        );

        assert_eq!(amt, EVMU256::from(58 as u64));
    }

    #[test]
    fn test_multi_tokens_no_path_liquidate() {
        // 10000 * 9975 * 50 / (25 * 10000 + 10000 * 9975) = 49.875

        let mut reserve_data = HashMap::new();
        reserve_data.insert(
            EVMAddress::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            (EVMU256::from(25), EVMU256::from(50 as u64)),
        );
        reserve_data.insert(
            EVMAddress::from_str("0x0000000000000000000000000000000000000002").unwrap(),
            (EVMU256::from(10), EVMU256::from(10 as u64)),
        );

        let t0 = TokenContext {
            swaps: vec![],
            is_weth: false,
            weth_address: Default::default(),
            address: Default::default(),
        };

        let t1 = TokenContext {
            swaps: vec![
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: EVMAddress::from_str("0x0000000000000000000000000000000000000000")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                        next_hop: Default::default(),
                    })],
                    final_pegged_ratio: EVMU256::from(1),
                    final_pegged_pair: Rc::new(RefCell::new(None)),
                },
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: EVMAddress::from_str("0x0000000000000000000000000000000000000002")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                        next_hop: Default::default(),
                    })],
                    final_pegged_ratio: EVMU256::from(1),
                    final_pegged_pair: Rc::new(RefCell::new(None)),
                },
            ],
            is_weth: false,
            weth_address: Default::default(),
            address: Default::default(),
        };
        let (amt, _) = liquidate_all_token(
            vec![(&t0, EVMU256::from(1000)), (&t1, EVMU256::from(10000))],
            reserve_data,
        );
        assert_eq!(amt, EVMU256::from(49 as u64));
    }

    #[test]
    fn test_reserve_parser() {
        let (r0, r1) = reserve_parser(&EVMU256::from_str_radix(
            "63cebab4000000004b702d24750df9f77b8400000016e7f19fdf1ede2902b6ae",
            16
        ).unwrap());
        assert_eq!(r0, EVMU256::from_str_radix("000000004b702d24750df9f77b84", 16).unwrap());
        assert_eq!(r1, EVMU256::from_str_radix("00000016e7f19fdf1ede2902b6ae", 16).unwrap());
    }
}
