use std::{
    cell::RefCell,
    collections::{hash_map, HashMap},
    fmt::Debug,
    ops::Deref,
    rc::Rc,
    str::FromStr,
    sync::Arc,
};

use alloy_primitives::hex;
use serde::{Deserialize, Serialize};

use super::types::checksum;
use crate::{
    evm::{
        abi::{A256InnerType, AArray, AEmpty, BoxedABI, A256},
        onchain::endpoints::Chain,
        types::{EVMAddress, EVMU256},
    },
    generic_vm::vm_state,
};

pub mod constant_pair;

// deposit
const SWAP_DEPOSIT: [u8; 4] = [0xd0, 0xe3, 0x0d, 0xb0];
// withdraw
const SWAP_WITHDRAW: [u8; 4] = [0x2e, 0x1a, 0x7d, 0x4d];
// swapExactETHForTokensSupportingFeeOnTransferTokens
const SWAP_BUY: [u8; 4] = [0xb6, 0xf9, 0xde, 0x95];
// swapExactTokensForETHSupportingFeeOnTransferTokens
const SWAP_SELL: [u8; 4] = [0x79, 0x1a, 0xc9, 0x47];

#[derive(Clone, Debug)]
pub enum UniswapProvider {
    PancakeSwap,
    SushiSwap,
    UniswapV2,
    UniswapV3,
    Biswap,
}
impl FromStr for UniswapProvider {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pancakeswap" => Ok(Self::PancakeSwap),
            "pancakeswapv2" => Ok(Self::PancakeSwap),
            "sushiswap" => Ok(Self::SushiSwap),
            "uniswapv2" => Ok(Self::UniswapV2),
            "uniswapv3" => Ok(Self::UniswapV3),
            "biswap" => Ok(Self::Biswap),
            _ => Err(()),
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct UniswapInfo {
    pub pool_fee: usize,
    pub router: EVMAddress,
    pub factory: EVMAddress,
    pub init_code_hash: Vec<u8>,
    pub pair_bytecode: Vec<u8>,
}
#[derive(Clone, Debug, Default)]
pub struct PairContext {
    pub pair_address: EVMAddress,
    pub next_hop: EVMAddress,
    pub side: u8,
    pub uniswap_info: Arc<UniswapInfo>,
    pub initial_reserves: (EVMU256, EVMU256),
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

static mut WETH_MAX: EVMU256 = EVMU256::ZERO;

impl TokenContext {
    pub fn buy(&self, amount_in: EVMU256, to: EVMAddress, seed: &[u8]) -> Vec<(EVMAddress, BoxedABI, EVMU256)> {
        unsafe {
            WETH_MAX = EVMU256::from(10).pow(EVMU256::from(24));
        }
        // function swapExactETHForTokensSupportingFeeOnTransferTokens(
        //     uint amountOutMin,
        //     address[] calldata path,
        //     address to,
        //     uint deadline
        // )
        if self.is_weth {
            let mut abi = BoxedABI::new(Box::new(AEmpty {}));
            abi.function = SWAP_DEPOSIT; // deposit
                                         // EVMU256::from(perct) * unsafe {WETH_MAX}
            vec![(self.weth_address, abi, amount_in)]
        } else {
            if self.swaps.is_empty() {
                return vec![];
            }
            let path_ctx = &self.swaps[seed[0] as usize % self.swaps.len()];
            // let amount_in = path_ctx.get_amount_in(perct, reserve);
            let mut path: Vec<EVMAddress> = path_ctx
                .route
                .iter()
                .rev()
                .map(|pair| pair.deref().borrow().next_hop)
                .collect();
            // when it is pegged token or weth
            if path.is_empty() || path[0] != self.weth_address {
                path.insert(0, self.weth_address);
            }
            path.insert(path.len(), self.address);
            let mut abi = BoxedABI::new(Box::new(AArray {
                data: vec![
                    BoxedABI::new(Box::new(A256 {
                        data: vec![0; 32],
                        is_address: false,
                        dont_mutate: false,
                        inner_type: A256InnerType::Uint,
                    })),
                    BoxedABI::new(Box::new(AArray {
                        data: path
                            .iter()
                            .map(|addr| {
                                BoxedABI::new(Box::new(A256 {
                                    data: addr.as_bytes().to_vec(),
                                    is_address: true,
                                    dont_mutate: false,
                                    inner_type: A256InnerType::Address,
                                }))
                            })
                            .collect(),
                        dynamic_size: true,
                    })),
                    BoxedABI::new(Box::new(A256 {
                        data: to.0.to_vec(),
                        is_address: true,
                        dont_mutate: false,
                        inner_type: A256InnerType::Address,
                    })),
                    BoxedABI::new(Box::new(A256 {
                        data: vec![0xff; 32],
                        is_address: false,
                        dont_mutate: false,
                        inner_type: A256InnerType::Uint,
                    })),
                ],
                dynamic_size: false,
            }));
            abi.function = SWAP_BUY;

            match path_ctx.final_pegged_pair.deref().borrow().as_ref() {
                None => vec![(
                    path_ctx.route.last().unwrap().deref().borrow().uniswap_info.router,
                    abi,
                    amount_in,
                )],
                Some(info) => vec![(info.uniswap_info.router, abi, amount_in)],
            }
        }
    }

    // swapExactTokensForETHSupportingFeeOnTransferTokens
    pub fn sell(&self, amount_in: EVMU256, to: EVMAddress, seed: &[u8]) -> Vec<(EVMAddress, BoxedABI, EVMU256)> {
        unsafe {
            WETH_MAX = EVMU256::from(10).pow(EVMU256::from(24));
        }
        // function swapExactTokensForETHSupportingFeeOnTransferTokens(
        //     uint amountIn,
        //     uint amountOutMin,
        //     address[] calldata path,
        //     address to,
        //     uint deadline
        // )
        let amount: [u8; 32] = amount_in.to_be_bytes();
        let mut abi_amount = BoxedABI::new(Box::new(A256 {
            data: amount.to_vec(),
            is_address: false,
            dont_mutate: false,
            inner_type: A256InnerType::Uint,
        }));

        if self.is_weth {
            abi_amount.function = SWAP_WITHDRAW; // withdraw
            vec![(self.weth_address, abi_amount, EVMU256::ZERO)]
        } else {
            if self.swaps.is_empty() {
                return vec![];
            }
            let path_ctx = &self.swaps[seed[0] as usize % self.swaps.len()];
            // let amount_in = path_ctx.get_amount_in(perct, reserve);
            let mut path: Vec<EVMAddress> = path_ctx
                .route
                .iter()
                .map(|pair| pair.deref().borrow().next_hop)
                .collect();
            // when it is pegged token or weth
            if path.is_empty() || *path.last().unwrap() != self.weth_address {
                path.push(self.weth_address);
            }
            path.insert(0, self.address);
            let mut sell_abi = BoxedABI::new(Box::new(AArray {
                data: vec![
                    abi_amount,
                    BoxedABI::new(Box::new(A256 {
                        data: vec![0; 32],
                        is_address: false,
                        dont_mutate: false,
                        inner_type: A256InnerType::Uint,
                    })),
                    BoxedABI::new(Box::new(AArray {
                        data: path
                            .iter()
                            .map(|addr| {
                                BoxedABI::new(Box::new(A256 {
                                    data: addr.as_bytes().to_vec(),
                                    is_address: true,
                                    dont_mutate: false,
                                    inner_type: A256InnerType::Address,
                                }))
                            })
                            .collect(),
                        dynamic_size: true,
                    })),
                    BoxedABI::new(Box::new(A256 {
                        data: to.0.to_vec(),
                        is_address: true,
                        dont_mutate: false,
                        inner_type: A256InnerType::Address,
                    })),
                    BoxedABI::new(Box::new(A256 {
                        data: vec![0xff; 32],
                        is_address: false,
                        dont_mutate: false,
                        inner_type: A256InnerType::Uint,
                    })),
                ],
                dynamic_size: false,
            }));
            sell_abi.function = SWAP_SELL;

            let router = match path_ctx.final_pegged_pair.deref().borrow().as_ref() {
                None => path_ctx.route.last().unwrap().deref().borrow().uniswap_info.router,
                Some(info) => info.uniswap_info.router,
            };

            let mut approve_abi = BoxedABI::new(Box::new(AArray {
                data: vec![
                    BoxedABI::new(Box::new(A256 {
                        data: router.0.to_vec(),
                        is_address: true,
                        dont_mutate: false,
                        inner_type: A256InnerType::Address,
                    })),
                    BoxedABI::new(Box::new(A256 {
                        data: vec![0xff; 32],
                        is_address: false,
                        dont_mutate: false,
                        inner_type: A256InnerType::Uint,
                    })),
                ],
                dynamic_size: false,
            }));

            approve_abi.function = [0x09, 0x5e, 0xa7, 0xb3]; // approve

            vec![
                (self.address, approve_abi, EVMU256::ZERO),
                (router, sell_abi, EVMU256::ZERO),
            ]
        }
    }
}

pub fn get_uniswap_info(provider: &UniswapProvider, chain: &Chain) -> UniswapInfo {
    match (provider, chain) {
        (&UniswapProvider::UniswapV2, &Chain::BSC) => UniswapInfo {
            pool_fee: 25,
            router: EVMAddress::from_str("0x10ed43c718714eb63d5aa57b78b54704e256024e").unwrap(),
            factory: EVMAddress::from_str("0xca143ce32fe78f1f7019d7d551a6402fc5350c73").unwrap(),
            init_code_hash: hex::decode("00fb7f630766e6a796048ea87d01acd3068e8ff67d078148a3fa3f4a84f69bd5").unwrap(),
            pair_bytecode: hex::decode(BSC_PANCAKEV2_PAIR_BYTECODE).unwrap(),
        },
        (&UniswapProvider::PancakeSwap, &Chain::BSC) => UniswapInfo {
            pool_fee: 25,
            router: EVMAddress::from_str("0x10ed43c718714eb63d5aa57b78b54704e256024e").unwrap(),
            factory: EVMAddress::from_str("0xca143ce32fe78f1f7019d7d551a6402fc5350c73").unwrap(),
            init_code_hash: hex::decode("00fb7f630766e6a796048ea87d01acd3068e8ff67d078148a3fa3f4a84f69bd5").unwrap(),
            pair_bytecode: hex::decode(BSC_PANCAKEV2_PAIR_BYTECODE).unwrap(),
        },
        (&UniswapProvider::UniswapV2, &Chain::ETH) => UniswapInfo {
            pool_fee: 3,
            router: EVMAddress::from_str("0x7a250d5630b4cf539739df2c5dacb4c659f2488d").unwrap(),
            factory: EVMAddress::from_str("0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f").unwrap(),
            init_code_hash: hex::decode("96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f").unwrap(),
            pair_bytecode: hex::decode(ETH_UNISWAPV2_PAIR_BYTECODE).unwrap(),
        },
        _ => panic!("Uniswap provider {:?} @ chain {:?} not supported", provider, chain),
    }
}
pub const BSC_PANCAKEV2_PAIR_BYTECODE: &str = include_str!("bsc_pancakeV2_pair.bin");
pub const ETH_UNISWAPV2_PAIR_BYTECODE: &str = include_str!("eth_uniswapV2_pair.bin");

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SwapData {
    inner: HashMap<SwapType, SwapInfo>,
}

impl SwapData {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn push(&mut self, addr: &EVMAddress, abi: &mut BoxedABI) {
        if let Some(new) = SwapInfo::try_new(addr, abi) {
            // swap_infos with same type will be merged
            if let hash_map::Entry::Vacant(e) = self.inner.entry(new.ty) {
                e.insert(new);
            } else {
                self.inner.get_mut(&new.ty).unwrap().concat_path(new.path);
            }
        }
    }

    pub fn to_generic(&self) -> HashMap<String, vm_state::SwapInfo> {
        self.inner
            .iter()
            .map(|(k, v)| ((*k).into(), v.clone().into()))
            .collect()
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
#[serde(into = "String")]
pub enum SwapType {
    #[default]
    Deposit,
    Buy,
    Withdraw,
    Sell,
}

impl From<SwapType> for String {
    fn from(ty: SwapType) -> Self {
        match ty {
            SwapType::Deposit => "deposit".to_string(),
            SwapType::Buy => "buy".to_string(),
            SwapType::Withdraw => "withdraw".to_string(),
            SwapType::Sell => "sell".to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SwapInfo {
    pub ty: SwapType,
    pub target: String,
    pub path: Vec<String>,
}

impl SwapInfo {
    pub fn try_new(target: &EVMAddress, abi: &mut BoxedABI) -> Option<Self> {
        let get_path = |abi: &mut BoxedABI, idx: usize| -> Option<Vec<String>> {
            if let Some(args) = abi.b.as_any().downcast_mut::<AArray>() {
                let path = args.data[idx]
                    .b
                    .as_any()
                    .downcast_ref::<AArray>()
                    .unwrap()
                    .data
                    .iter()
                    .map(|x| x.b.to_string())
                    .collect::<Vec<_>>();
                Some(path)
            } else {
                None
            }
        };

        let (ty, path) = match abi.function {
            SWAP_BUY => (SwapType::Buy, get_path(abi, 1)),
            SWAP_SELL => (SwapType::Sell, get_path(abi, 2)),
            SWAP_DEPOSIT => (SwapType::Deposit, Some(vec![])),
            SWAP_WITHDRAW => (SwapType::Withdraw, Some(vec![])),
            _ => return None,
        };

        if let Some(path) = path {
            let target = checksum(target);
            Some(Self { ty, target, path })
        } else {
            None
        }
    }

    pub fn concat_path(&mut self, new_path: Vec<String>) {
        // Find the first common element from the end
        let mut idx = self.path.len();
        for i in (0..self.path.len()).rev() {
            if self.path[i] == new_path[0] {
                idx = i;
                break;
            }
        }
        self.path.truncate(idx);
        self.path.extend(new_path);
    }
}

// Uniswap info -> Generic swap info
impl From<SwapInfo> for vm_state::SwapInfo {
    fn from(info: SwapInfo) -> Self {
        Self {
            ty: info.ty.into(),
            target: info.target,
            path: info.path,
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use std::str::FromStr;

//     use tracing::debug;

//     use super::*;
//     use crate::evm::onchain::endpoints::Chain;

//     macro_rules! wrap {
//         ($x: expr) => {
//             Rc::new(RefCell::new($x))
//         };
//     }

//     #[test]
//     fn test_uniswap_sell() {
//         let t1 = TokenContext {
//             swaps: vec![PathContext {
//                 route: vec![wrap!(PairContext {
//                     pair_address:
// EVMAddress::from_str("0x0000000000000000000000000000000000000000").unwrap(),
//                     side: 0,
//                     uniswap_info:
// Arc::new(get_uniswap_info(&UniswapProvider::PancakeSwap, &Chain::BSC)),
//                     initial_reserves: (Default::default(),
// Default::default()),                     next_hop:
// EVMAddress::from_str("0x1100000000000000000000000000000000000000").unwrap(),
//                 })],
//                 final_pegged_ratio: EVMU256::from(1),
//                 final_pegged_pair: Rc::new(RefCell::new(None)),
//             }],
//             is_weth: false,
//             weth_address:
// EVMAddress::from_str("0xee00000000000000000000000000000000000000").unwrap(),
//             address:
// EVMAddress::from_str("0xff00000000000000000000000000000000000000").unwrap(),
//         };

//         let plan = generate_uniswap_router_sell(
//             &t1,
//             0,
//             EVMU256::from(10000),
//
// EVMAddress::from_str("0x2300000000000000000000000000000000000000").unwrap(),
//         );
//         debug!(
//             "plan: {:?}",
//             plan.unwrap()
//                 .iter()
//                 .map(|x| hex::encode(x.0.get_bytes()))
//                 .collect::<Vec<_>>()
//         );
//     }
// }
