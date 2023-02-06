use crate::evm::abi::{AEmpty, BoxedABI};
use crate::evm::input::{EVMInput, EVMInputT};
use crate::evm::onchain::endpoints::Chain;
use crate::evm::types::EVMOracleCtx;
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::generic_vm::vm_executor::GenericVM;
use crate::oracle::OracleCtx;
use crate::state_input::StagedVMState;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use itertools::iproduct;
use permutator::{cartesian_product, CartesianProduct, CartesianProductIterator};
use primitive_types::{H160, U256};
use std::cell::{Ref, RefCell};
use std::collections::HashMap;
use std::ops::Deref;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;

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
    pub router: H160,
    pub factory: H160,
    pub init_code_hash: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SwapResult {
    pub amount_out: U256,
    pub new_reserve_in: U256,
    pub new_reserve_out: U256,
}

#[derive(Clone, Debug, Default)]
pub struct PairContext {
    pub pair_address: H160,
    pub side: u8,
    pub uniswap_info: Arc<UniswapInfo>,
    pub initial_reserves: (U256, U256),
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
    //     self.reserve0 = U256::from_big_endian(&res.output[0..32]);
    //     self.reserve1 = U256::from_big_endian(&res.output[32..64]);
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
    //     self.reserve0 = U256::from_big_endian(&res.output[0..32]);
    //     self.reserve1 = U256::from_big_endian(&res.output[32..64]);
    // }

    pub fn get_amount_out(&self, amount_in: U256, reserve0: U256, reserve1: U256) -> SwapResult {
        self.uniswap_info.calculate_amounts_out(
            if amount_in > U256::from(u128::MAX) {
                U256::from(u128::MAX)
            } else {
                amount_in
            },
            if self.side == 0 { reserve0 } else { reserve1 },
            if self.side == 0 { reserve1 } else { reserve0 },
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct PathContext {
    pub route: Vec<Rc<RefCell<PairContext>>>,
    pub final_pegged_ratio: U256,
}

#[derive(Clone, Debug, Default)]
pub struct TokenContext {
    pub swaps: Vec<PathContext>,
}

impl PathContext {
    pub fn get_amount_out(
        &self,
        amount_in: U256,
        reserve_data: &mut HashMap<H160, (U256, U256)>,
    ) -> U256 {
        let mut amount_in = amount_in;

        // address => (new reserve0, new reserve1)
        for pair in self.route.iter() {
            let reserves = match reserve_data.get(&pair.deref().borrow().pair_address) {
                None => pair.deref().borrow().initial_reserves,
                Some(reserves) => reserves.clone(),
            };
            let swap_result = pair
                .borrow()
                .get_amount_out(amount_in, reserves.0, reserves.1);
            reserve_data.insert(
                pair.borrow().pair_address,
                (
                    if pair.borrow().side == 0 {
                        swap_result.new_reserve_in
                    } else {
                        swap_result.new_reserve_out
                    },
                    if pair.borrow().side == 0 {
                        swap_result.new_reserve_out
                    } else {
                        swap_result.new_reserve_in
                    },
                ),
            );
            amount_in = swap_result.amount_out;
        }
        amount_in * self.final_pegged_ratio
    }
}

pub fn liquidate_all_token(
    tokens: Vec<(&TokenContext, U256)>,
    initial_reserve_data: HashMap<H160, (U256, U256)>,
) -> U256 {
    let mut swap_combos: Vec<Vec<(PathContext, U256)>> = Vec::new();
    for (token, amt) in tokens {
        let swaps: Vec<(PathContext, U256)> =
            token.swaps.iter().map(|swap| (swap.clone(), amt)).collect();
        if swaps.len() > 0 {
            swap_combos.push(swaps);
        }
    }

    if swap_combos.len() == 0 {
        return U256::zero();
    }

    let mut possible_amount_out = vec![];

    CartesianProductIterator::new(
        swap_combos
            .iter()
            .map(|x| x.as_slice())
            .collect::<Vec<&[(PathContext, U256)]>>()
            .as_slice(),
    )
    .into_iter()
    .for_each(|swaps| {
        let mut reserve_data = initial_reserve_data.clone();
        let mut total_amount_out = U256::zero();
        for (path, amt) in &swaps {
            total_amount_out += path.get_amount_out(amt.clone(), &mut reserve_data);
        }
        possible_amount_out.push(total_amount_out);
    });

    possible_amount_out.iter().max().unwrap().clone()
}

pub fn get_uniswap_info(provider: &UniswapProvider, chain: &Chain) -> UniswapInfo {
    match (provider, chain) {
        (&UniswapProvider::PancakeSwap, &Chain::BSC) => UniswapInfo {
            pool_fee: 25,
            router: H160::from_str("0x10ed43c718714eb63d5aa57b78b54704e256024e").unwrap(),
            factory: H160::from_str("0xca143ce32fe78f1f7019d7d551a6402fc5350c73").unwrap(),
            init_code_hash: hex::decode(
                "00fb7f630766e6a796048ea87d01acd3068e8ff67d078148a3fa3f4a84f69bd5",
            )
            .unwrap(),
        },
        (&UniswapProvider::UniswapV2, &Chain::ETH) => UniswapInfo {
            pool_fee: 3,
            router: H160::from_str("0x7a250d5630b4cf539739df2c5dacb4c659f2488d").unwrap(),
            factory: H160::from_str("0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f").unwrap(),
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
        amount_in: U256,
        reserve_in: U256,
        reserve_out: U256,
    ) -> SwapResult {
        let amount_in_with_fee = amount_in * U256::from(10000 - self.pool_fee);
        let numerator = amount_in_with_fee * reserve_out;
        let denominator = reserve_in * U256::from(10000) + amount_in_with_fee;
        let amount_out = numerator / denominator;
        SwapResult {
            amount_out,
            new_reserve_in: reserve_in + amount_in,
            new_reserve_out: reserve_out - amount_out,
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
    pub fn get_pair_address(&self, token_a: H160, token_b: H160) -> H160 {
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
        return H160::from_slice(&keccak[12..]);
    }
}

pub fn reserve_parser(reserve_slot: &U256) -> (U256, U256) {
    let mut reserve_bytes = [0u8; 32];
    reserve_slot.to_big_endian(&mut reserve_bytes);
    let reserve_0 = U256::from_big_endian(&reserve_bytes[4..18]);
    let reserve_1 = U256::from_big_endian(&reserve_bytes[18..32]);
    (reserve_0, reserve_1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::onchain::endpoints::Chain;
    use crate::rand_utils::generate_random_address;
    use primitive_types::H160;
    use std::str::FromStr;

    #[test]
    fn test_get_pair_address() {
        let uniswap_info = get_uniswap_info(&UniswapProvider::UniswapV2, &Chain::ETH);
        let token_a = H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap();
        let token_b = H160::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
        let pair_address = uniswap_info.get_pair_address(token_a, token_b);
        assert_eq!(
            pair_address,
            H160::from_str("0xae461ca67b15dc8dc81ce7615e0320da1a9ab8d5").unwrap()
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
            H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
            (U256::from(10), U256::from(10000000000 as u64)),
        );
        let res = PathContext {
            route: vec![wrap!(PairContext {
                pair_address: H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                side: 0,
                uniswap_info: Arc::new(get_uniswap_info(
                    &UniswapProvider::PancakeSwap,
                    &Chain::BSC
                )),
                initial_reserves: (Default::default(), Default::default()),
            })],
            // 0.1 * 10^5 eth / token
            final_pegged_ratio: U256::from(1000),
        }
        .get_amount_out(U256::from(1000), &mut reserve_data);
        assert_eq!(res, U256::from(9900744416000 as u64));
    }

    #[test]
    fn test_long_path_liquidate() {
        // 1000 * 9975 * 10000000000 / (10 * 10000 + 1000 * 9975) = 9900744416.87345
        // 9900744416 * 9975 * 40 / (10000 * 10000 + 9900744416 * 9975) = 39.99999

        let mut reserve_data = HashMap::new();
        reserve_data.insert(
            H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
            (U256::from(10), U256::from(10000000000 as u64)),
        );
        reserve_data.insert(
            H160::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(),
            (U256::from(40), U256::from(10000 as u64)),
        );
        let res = PathContext {
            route: vec![
                wrap!(PairContext {
                    pair_address: H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                        .unwrap(),
                    side: 0,
                    uniswap_info: Arc::new(get_uniswap_info(
                        &UniswapProvider::PancakeSwap,
                        &Chain::BSC
                    )),
                    initial_reserves: (Default::default(), Default::default()),
                }),
                wrap!(PairContext {
                    pair_address: H160::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                        .unwrap(),
                    side: 1,
                    uniswap_info: Arc::new(get_uniswap_info(
                        &UniswapProvider::PancakeSwap,
                        &Chain::BSC
                    )),
                    initial_reserves: (Default::default(), Default::default()),
                }),
            ],
            final_pegged_ratio: U256::from(1),
        }
        .get_amount_out(U256::from(1000), &mut reserve_data);
        assert_eq!(res, U256::from(39 as u64));
    }

    #[test]
    fn test_insufficient_liquidate() {
        // 1000 * 9975 * 0 / (10 * 10000 + 1000 * 9975) = 0
        let mut delta = HashMap::new();
        delta.insert(
            H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
            (U256::from(10), U256::from(0 as u64)),
        );
        let res = PathContext {
            route: vec![wrap!(PairContext {
                pair_address: H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                side: 0,
                uniswap_info: Arc::new(get_uniswap_info(
                    &UniswapProvider::PancakeSwap,
                    &Chain::BSC
                )),
                initial_reserves: (Default::default(), Default::default()),
            })],
            final_pegged_ratio: U256::from(1),
        }
        .get_amount_out(U256::from(1000), &mut delta);
        assert_eq!(res, U256::from(0 as u64));
    }

    #[test]
    fn test_multi_paths_liquidate() {
        // 1000 * 9975 * 10 / (10 * 10000 + 1000 * 9975) = 9.900744416873449
        // 1000 * 9975 * 50 / (25 * 10000 + 1000 * 9975) = 48.77750611246944

        let mut reserve_data = HashMap::new();
        reserve_data.insert(
            H160::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            (U256::from(25), U256::from(50 as u64)),
        );
        reserve_data.insert(
            H160::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            (U256::from(10), U256::from(10 as u64)),
        );

        let t0 = TokenContext {
            swaps: vec![
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: H160::from_str("0x0000000000000000000000000000000000000000")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                    })],
                    final_pegged_ratio: U256::from(20),
                },
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: H160::from_str("0x0000000000000000000000000000000000000001")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                    })],
                    final_pegged_ratio: U256::from(1),
                },
            ],
        };
        assert_eq!(
            liquidate_all_token(vec![(&t0, U256::from(1000))], reserve_data),
            U256::from(48 * 20 as u64)
        );
    }

    #[test]
    fn test_multi_tokens_liquidate() {
        // 1000 * 9975 * 50 / (25 * 10000 + 1000 * 9975) = 48.77750611246944
        // 10000 * 9975 * 10 / (10 * 10000 + 10000 * 9975) = 9.900744416873449

        let mut reserve_data = HashMap::new();
        reserve_data.insert(
            H160::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            (U256::from(25), U256::from(50 as u64)),
        );
        reserve_data.insert(
            H160::from_str("0x0000000000000000000000000000000000000002").unwrap(),
            (U256::from(10), U256::from(10 as u64)),
        );
        reserve_data.insert(
            H160::from_str("0x0000000000000000000000000000000000000003").unwrap(),
            (U256::from(10), U256::from(10 as u64)),
        );

        let t0 = TokenContext {
            swaps: vec![
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: H160::from_str("0x0000000000000000000000000000000000000000")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                    })],
                    final_pegged_ratio: U256::from(1),
                },
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: H160::from_str("0x0000000000000000000000000000000000000003")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                    })],
                    final_pegged_ratio: U256::from(1),
                },
            ],
        };

        let t1 = TokenContext {
            swaps: vec![
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: H160::from_str("0x0000000000000000000000000000000000000000")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                    })],
                    final_pegged_ratio: U256::from(1),
                },
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: H160::from_str("0x0000000000000000000000000000000000000002")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                    })],
                    final_pegged_ratio: U256::from(1),
                },
            ],
        };
        assert_eq!(
            liquidate_all_token(
                vec![(&t0, U256::from(1000)), (&t1, U256::from(10000))],
                reserve_data
            ),
            U256::from(58 as u64)
        );
    }

    #[test]
    fn test_multi_tokens_no_path_liquidate() {
        // 10000 * 9975 * 50 / (25 * 10000 + 10000 * 9975) = 49.875

        let mut reserve_data = HashMap::new();
        reserve_data.insert(
            H160::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            (U256::from(25), U256::from(50 as u64)),
        );
        reserve_data.insert(
            H160::from_str("0x0000000000000000000000000000000000000002").unwrap(),
            (U256::from(10), U256::from(10 as u64)),
        );

        let t0 = TokenContext { swaps: vec![] };

        let t1 = TokenContext {
            swaps: vec![
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: H160::from_str("0x0000000000000000000000000000000000000000")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                    })],
                    final_pegged_ratio: U256::from(1),
                },
                PathContext {
                    route: vec![wrap!(PairContext {
                        pair_address: H160::from_str("0x0000000000000000000000000000000000000002")
                            .unwrap(),
                        side: 0,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::PancakeSwap,
                            &Chain::BSC
                        )),
                        initial_reserves: (Default::default(), Default::default()),
                    })],
                    final_pegged_ratio: U256::from(1),
                },
            ],
        };
        assert_eq!(
            liquidate_all_token(
                vec![(&t0, U256::from(1000)), (&t1, U256::from(10000))],
                reserve_data
            ),
            U256::from(49 as u64)
        );
    }

    #[test]
    fn test_reserve_parser() {
        let (r0, r1) = reserve_parser(&U256::from(
            "0x63cebab4000000004b702d24750df9f77b8400000016e7f19fdf1ede2902b6ae",
        ));
        assert_eq!(r0, U256::from("0x000000004b702d24750df9f77b84"));
        assert_eq!(r1, U256::from("0x00000016e7f19fdf1ede2902b6ae"));
    }
}
