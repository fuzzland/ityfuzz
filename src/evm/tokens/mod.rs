use std::{
    borrow::BorrowMut,
    cell::RefCell,
    collections::{hash_map, HashMap},
    fmt::Debug,
    ops::Deref,
    rc::Rc,
    str::FromStr,
};

use alloy_primitives::hex;
use libafl::schedulers::Scheduler;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::{
    types::{checksum, EVMFuzzState},
    vm::EVMExecutor,
};
use crate::{
    evm::{
        abi::{AArray, BoxedABI},
        onchain::endpoints::Chain,
        tokens::v3_transformer::V3_TOKEN_HOLDER,
        types::{EVMAddress, EVMU256},
    },
    generic_vm::{
        vm_executor::GenericVM,
        vm_state::{self, VMStateT},
    },
    input::ConciseSerde,
    state::HasCaller,
};

pub mod constant_pair;
pub mod uniswap;
pub mod v2_transformer;
pub mod v3_transformer;
pub mod weth_transformer;

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
    PancakeSwapV2,
    PancakeSwapV3,
    SushiSwap,
    UniswapV2,
    UniswapV3,
    Biswap,
}

#[macro_export]
macro_rules! get_code_tokens {
    ($addr: expr, $vm: expr, $state: expr) => {
        match $vm.host.code.get(&$addr) {
            Some(code) => code.clone(),
            None => {
                let code = CODE_REGISTRY
                    .lock()
                    .unwrap()
                    .get(&$addr)
                    .cloned()
                    .expect(format!("Internal Error: token {:?} code not found in registry.", $addr).as_str());
                // println!("inserting: {:?}", $addr);
                $vm.host.set_code($addr, code.clone(), $state);
                $vm.host.code.get(&$addr).unwrap().clone()
            }
        }
    };
}

impl FromStr for UniswapProvider {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pancakeswap" => Ok(Self::PancakeSwapV2),
            "pancakeswapv2" => Ok(Self::PancakeSwapV2),
            "pancakeswapv3" => Ok(Self::PancakeSwapV3),
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
    pub router: Option<EVMAddress>,
}

pub trait PairContext {
    fn transform<VS, CI, SC>(
        &self,
        src: &EVMAddress,
        next: &EVMAddress,

        amount: EVMU256,
        state: &mut EVMFuzzState,
        vm: &mut EVMExecutor<VS, CI, SC>,
        reverse: bool,
    ) -> Option<(EVMAddress, EVMU256)>
    where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static;

    fn name(&self) -> String;
}

#[derive(Clone)]
enum PairContextTy {
    Uniswap(Rc<RefCell<v2_transformer::UniswapPairContext>>),
    UniswapV3(Rc<RefCell<v3_transformer::UniswapV3PairContext>>),
    Weth(Rc<RefCell<weth_transformer::WethContext>>),
}

impl Debug for PairContextTy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PairContextTy::Uniswap(ctx) => write!(f, "Uniswap({:?})", ctx.borrow()),
            PairContextTy::Weth(ctx) => write!(f, "Weth({:?})", ctx.borrow()),
            PairContextTy::UniswapV3(ctx) => write!(f, "UniswapV3({:?})", ctx.borrow()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct PathContext {
    pub route: Vec<PairContextTy>,
}

#[derive(Clone, Debug, Default)]
pub struct TokenContext {
    pub swaps: Vec<PathContext>,
    pub is_weth: bool,
    pub weth_address: EVMAddress,
}

static mut WETH_MAX: EVMU256 = EVMU256::ZERO;

impl TokenContext {
    pub fn buy<VS, CI, SC>(
        &self,
        amount_in: EVMU256,
        to: EVMAddress,
        state: &mut EVMFuzzState,
        vm: &mut EVMExecutor<VS, CI, SC>,
        seed: &[u8],
    ) -> Option<()>
    where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        if self.is_weth {
            let ctx = &self.swaps[0].route[0];
            if let PairContextTy::Weth(ctx) = ctx {
                ctx.deref().borrow_mut().transform(&to, &to, amount_in, state, vm, true);
            } else {
                panic!("Invalid weth context");
            }
        } else {
            if self.swaps.is_empty() {
                return None;
            }
            let mut current_amount_in = amount_in;
            let mut current_sender = None;
            let path_ctx = &self.swaps[seed[0] as usize % self.swaps.len()];
            let path_len = path_ctx.route.len();
            for (nth, pair) in path_ctx.route.iter().rev().enumerate() {
                let is_final = nth == path_len - 1;

                let next = if is_final {
                    to
                } else {
                    match &path_ctx.route[path_len - nth - 2] {
                        PairContextTy::Uniswap(ctx) => ctx.borrow().pair_address,
                        PairContextTy::UniswapV3(_) => EVMAddress::from_slice(&V3_TOKEN_HOLDER),
                        PairContextTy::Weth(_ctx) => panic!("Invalid weth context"),
                    }
                };

                match pair {
                    PairContextTy::Uniswap(ctx) => {
                        #[cfg(test)]
                        {
                            println!("======== Uniswap ========");
                            println!("pair = {:?}", ctx.borrow().pair_address);
                            println!(
                                "{:?} => {:?} ({}/{:?})",
                                current_sender, next, current_amount_in, current_amount_in
                            );
                        }
                        if let Some((receiver, amount)) = ctx.deref().borrow_mut().transform(
                            &current_sender.unwrap(),
                            &next,
                            current_amount_in,
                            state,
                            vm,
                            true,
                        ) {
                            #[cfg(test)]
                            {
                                println!("Hop out = {}/{:?}", amount, amount);
                            }
                            current_amount_in = amount;
                            current_sender = Some(receiver);
                        } else {
                            #[cfg(test)]
                            {
                                println!("!!! Uniswap Failed !!!");
                            }
                            return None;
                        }
                    }
                    PairContextTy::UniswapV3(ctx) => {
                        #[cfg(test)]
                        {
                            println!("======== Uniswap V3 ========");
                            println!("pair = {:?}", ctx.borrow().inner.pair_address);
                            println!(
                                "{:?} => {:?} ({}/{:?})",
                                current_sender, next, current_amount_in, current_amount_in
                            );
                        }
                        if let Some((receiver, amount)) = ctx.deref().borrow_mut().transform(
                            &current_sender.unwrap(),
                            &next,
                            current_amount_in,
                            state,
                            vm,
                            true,
                        ) {
                            #[cfg(test)]
                            {
                                println!("Hop out = {}/{:?}", amount, amount);
                            }
                            current_amount_in = amount;
                            current_sender = Some(receiver);
                        } else {
                            #[cfg(test)]
                            {
                                println!("!!! Uniswap Failed !!!");
                            }
                            return None;
                        }
                    }
                    PairContextTy::Weth(ctx) => {
                        #[cfg(test)]
                        {
                            println!("======== Weth ========");
                            println!(
                                "{:?} => {:?} ({}/{:?})",
                                current_sender, next, current_amount_in, current_amount_in
                            );
                        }
                        assert!(current_sender.is_none());
                        ctx.deref()
                            .borrow_mut()
                            .transform(&to, &next, amount_in, state, vm, true)
                            .expect("Weth failed");
                        current_sender = Some(to);
                    }
                }
            }
        }
        Some(())
    }

    // swapExactTokensForETHSupportingFeeOnTransferTokens
    pub fn sell<VS, CI, SC>(
        &self,
        amount_in: EVMU256,
        src: EVMAddress,
        state: &mut EVMFuzzState,
        vm: &mut EVMExecutor<VS, CI, SC>,
        seed: &[u8],
    ) -> Option<()>
    where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        if self.is_weth {
            if let PairContextTy::Weth(ctx) = &self.swaps[0].route[0] {
                ctx.deref()
                    .borrow_mut()
                    .transform(&src, &EVMAddress::zero(), amount_in, state, vm, false)
                    .map(|_| ());
            } else {
                panic!("Invalid weth context");
            }
        } else {
            if self.swaps.is_empty() {
                return None;
            }
            let mut current_amount_in = amount_in;
            let mut current_sender = src;
            let path_ctx = &self.swaps[seed[0] as usize % self.swaps.len()];
            let mut is_first = true;
            let path_len = path_ctx.route.len();
            for (nth, pair) in path_ctx.route.iter().enumerate() {
                let is_final = nth == path_len - 1;
                let next = if is_final {
                    EVMAddress::zero()
                } else {
                    match &path_ctx.route[nth + 1] {
                        PairContextTy::Uniswap(ctx) => ctx.borrow().pair_address,
                        PairContextTy::Weth(_ctx) => state.get_rand_caller(),
                        PairContextTy::UniswapV3(_) => EVMAddress::from_slice(&V3_TOKEN_HOLDER),
                    }
                };
                match pair {
                    PairContextTy::Uniswap(ctx) => {
                        #[cfg(test)]
                        {
                            println!("======== Uniswap ========");
                            println!("pair = {:?}", ctx.borrow().pair_address);
                            println!(
                                "{:?} => {:?} ({}/{:?})",
                                current_sender, next, current_amount_in, current_amount_in
                            );
                        }

                        let pair_address = ctx.deref().borrow_mut().pair_address;

                        if is_first {
                            ctx.deref().borrow_mut().initial_transfer(
                                &current_sender,
                                &pair_address,
                                current_amount_in,
                                state,
                                vm,
                            );
                            is_first = false;
                        }

                        if let Some((receiver, amount)) = ctx.deref().borrow_mut().transform(
                            &current_sender,
                            &next,
                            current_amount_in,
                            state,
                            vm,
                            false,
                        ) {
                            #[cfg(test)]
                            {
                                println!("Hop out = {}/{:?}", amount, amount);
                            }
                            current_amount_in = amount;
                            current_sender = receiver;
                        } else {
                            #[cfg(test)]
                            {
                                println!("!!! Uniswap Failed !!!");
                            }
                            return None;
                        }
                    }
                    PairContextTy::UniswapV3(ctx) => {
                        #[cfg(test)]
                        {
                            println!("======== Uniswap ========");
                            println!("pair = {:?}", ctx.borrow().inner.pair_address);
                            println!(
                                "{:?} => {:?} ({}/{:?})",
                                current_sender, next, current_amount_in, current_amount_in
                            );
                        }

                        if is_first {
                            ctx.deref().borrow_mut().initial_transfer(
                                &current_sender,
                                &EVMAddress::from_slice(&V3_TOKEN_HOLDER),
                                current_amount_in,
                                state,
                                vm,
                            );
                            is_first = false;
                        }

                        if let Some((receiver, amount)) = ctx.deref().borrow_mut().transform(
                            &current_sender,
                            &next,
                            current_amount_in,
                            state,
                            vm,
                            false,
                        ) {
                            #[cfg(test)]
                            {
                                println!("Hop out = {}/{:?}", amount, amount);
                            }
                            current_amount_in = amount;
                            current_sender = receiver;
                        } else {
                            #[cfg(test)]
                            {
                                println!("!!! Uniswap Failed !!!");
                            }
                            return None;
                        }
                    }
                    PairContextTy::Weth(ctx) => {
                        #[cfg(test)]
                        {
                            assert!(!is_first);
                            println!("======== Weth ========");
                            println!(
                                "{:?} => {:?} ({}/{:?})",
                                current_sender, next, current_amount_in, current_amount_in
                            );
                        }
                        ctx.deref()
                            .borrow_mut()
                            .transform(&current_sender, &next, current_amount_in, state, vm, false)
                            .expect("Weth failed");
                    }
                }
            }
        }
        Some(())
    }
}

pub fn get_uniswap_info(src_exact: &str) -> UniswapInfo {
    match src_exact {
        "uniswapv2_eth" | "sushiswapv2_bsc" => UniswapInfo {
            pool_fee: 30,
            router: None,
        },
        "uniswapv3_eth" | "sushiswap_v3_eth" | "pancakeswap_v3_eth" => UniswapInfo {
            pool_fee: 0,
            router: Some(EVMAddress::from_str("0xe592427a0aece92de3edee1f18e0157c05861564").unwrap()),
        },
        "pancakev1" => UniswapInfo {
            pool_fee: 20,
            router: None,
        },
        "pancakeswapv2_eth" | "pancakeswapv2_arb" | "pancakeswapv2_base" | "pancakeswapv2_bsc" | "biswapv2_bsc" => {
            UniswapInfo {
                pool_fee: 25,
                router: None,
            }
        }
        "sushiswapv2_eth" | "sushiswapv2_arb" | "sushiswapv2_polygon" | "sushiswapv2_avax" | "sushiswapv2_base" => {
            UniswapInfo {
                pool_fee: 30,
                router: None,
            }
        }
        "uniswapv3_bsc" | "pancakeswap_v3_bsc" | "sushiswap_v3_bsc" => UniswapInfo {
            pool_fee: 0,
            router: Some(EVMAddress::from_str("0x1b81D678ffb9C0263b24A97847620C99d213eB14").unwrap()),
        },
        "trader_joe_v1_bsc" | "trader_joe_v1_avax" | "trader_joe_v1_arb" => UniswapInfo {
            pool_fee: 30,
            router: None,
        },
        "camelotv2_arb" => UniswapInfo {
            pool_fee: 30,
            router: None,
        },
        "uniswapv3_polygon" | "sushiswap_v3_polygon" => UniswapInfo {
            pool_fee: 0,
            router: Some(EVMAddress::from_str("0x0aF89E1620b96170e2a9D0b68fEebb767eD044c3").unwrap()),
        },
        "quickswapv2_polygon" => UniswapInfo {
            pool_fee: 30,
            router: None,
        },
        "uniswapv3_avax" | "sushiswap_v3_avax" => UniswapInfo {
            pool_fee: 0,
            router: Some(EVMAddress::from_str("0xe592427a0aece92de3edee1f18e0157c05861564").unwrap()),
        },
        "uniswapv3_op" | "sushiswap_v3_op" | "uniswapv3_arb" | "sushiswap_v3_arb" => UniswapInfo {
            pool_fee: 0,
            router: Some(EVMAddress::from_str("0xe592427a0aece92de3edee1f18e0157c05861564").unwrap()),
        },
        "pancakeswapv3_base" | "uniswapv3_base" | "sushiswapv3_base" => UniswapInfo {
            pool_fee: 0,
            router: Some(EVMAddress::from_str("0x1b81D678ffb9C0263b24A97847620C99d213eB14").unwrap()),
        },
        "thruster_v3_blast" => UniswapInfo {
            pool_fee: 0,
            router: Some(EVMAddress::from_str("0x337827814155ECBf24D20231fCA4444F530C0555").unwrap()),
        },

        "thruster_v2_3_blast" => UniswapInfo {
            pool_fee: 30,
            router: None,
        },
        "thruster_v2_1_blast" => UniswapInfo {
            pool_fee: 100,
            router: None,
        },
        _ => panic!("Uniswap provider {:?} not supported", src_exact),
    }
}

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

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use libafl::{schedulers::StdScheduler, state::HasMetadata};

    use super::*;
    use crate::{
        evm::{
            abi::ABIAddressToInstanceMap,
            config::StorageFetchingMode,
            corpus_initializer::EnvMetadata,
            host::FuzzHost,
            input::ConciseEVMInput,
            onchain::{
                endpoints::{Chain, OnChainConfig},
                ChainConfig,
                OnChain,
            },
            oracles::v2_pair::reserve_parser,
            tokens::uniswap::{fetch_uniswap_path, CODE_REGISTRY},
            types::{generate_random_address, EVMAddress, EVMFuzzState, EVMU256},
            vm::{EVMExecutor, EVMState},
        },
        state::{FuzzState, HasCaller},
    };

    macro_rules! wrap {
        ($x: expr) => {
            Rc::new(RefCell::new($x))
        };
    }

    fn trade(direction: &str, token: EVMAddress, amount: EVMU256, nth: usize, block: u64, src: &EVMAddress) {
        let mut state = FuzzState::new(0);
        let dummy_caller = generate_random_address(&mut state);
        state.add_caller(&dummy_caller);
        state
            .metadata_map_mut()
            .insert::<ABIAddressToInstanceMap>(ABIAddressToInstanceMap::new());
        state.metadata_map_mut().insert::<EnvMetadata>(EnvMetadata::default());

        let mut fuzz_host = FuzzHost::new(StdScheduler::new(), "work_dir".to_string());

        let mut onchain = OnChainConfig::new(Chain::ETH, block);
        let onchain_mid = OnChain::new(onchain.clone(), StorageFetchingMode::OneByOne);
        let onchain_mid_ptr = wrap!(onchain_mid);
        fuzz_host.add_middlewares(onchain_mid_ptr);
        let vm_state = EVMState::default();

        fuzz_host.evmstate = vm_state;

        CODE_REGISTRY
            .lock()
            .unwrap()
            .insert(token, onchain.get_contract_code_analyzed(token, false));

        let mut chain: Box<dyn ChainConfig> = Box::new(onchain);
        let token_ctx = fetch_uniswap_path(&mut chain, token);

        println!("======== Token Swaps ========");
        token_ctx.swaps.iter().for_each(|x| {
            println!("route: {:?}", x.route.iter());
        });
        println!("selected route: {:?}", token_ctx.swaps[nth].route);

        let mut evm_executor: EVMExecutor<EVMState, ConciseEVMInput, StdScheduler<EVMFuzzState>> =
            EVMExecutor::new(fuzz_host, generate_random_address(&mut state));

        let res = if direction == "buy" {
            token_ctx.buy(
                amount,
                generate_random_address(&mut state),
                &mut state,
                &mut evm_executor,
                &[nth as u8],
            )
        } else {
            token_ctx.sell(amount, *src, &mut state, &mut evm_executor, &[nth as u8])
        };

        if res.is_none() {
            println!("failed");
            return;
        }

        let result_state = evm_executor.host.evmstate;

        // print reserve change
        println!("======== Reserve Changes ========");

        token_ctx.swaps[nth].route.iter().for_each(|x| match x {
            PairContextTy::Uniswap(ctx) => {
                let pair_addr = ctx.borrow().pair_address;
                let (r0, r1) = reserve_parser(&result_state.state[&pair_addr][&EVMU256::from(8)]);
                println!(
                    "{:?} ({}, {}) => ({}, {}), slot = {:?}",
                    ctx.borrow().pair_address,
                    ctx.borrow().initial_reserves.0,
                    ctx.borrow().initial_reserves.1,
                    r0,
                    r1,
                    result_state.state[&pair_addr][&EVMU256::from(8)]
                );
            }
            _ => {}
        });

        // print flashloan data
        println!("======== Flashloan Data ========");
        println!(
            "owed: {}/{:?}",
            result_state.flashloan_data.owed, result_state.flashloan_data.owed
        );
        println!(
            "earned: {}/{:?}",
            result_state.flashloan_data.earned, result_state.flashloan_data.earned
        );
    }

    // !!!!! Following Tests are for debugging purpose only !!!!!
    /*
    #[test]
    fn test_buy_single_hop() {
        let token =
    EVMAddress::from_str("0xf3ae5d769e153ef72b4e3591ac004e89f48107a1").
    unwrap();     let amount =
    EVMU256::from_str("2000000000000000000").unwrap();     // dpr => weth
        trade("buy", token, amount, 1, 19044110, &EVMAddress::zero());
    }

    const DPR_RICH: &str = "0x1959f0401e101620dd7e2ab5456f4b4a6e289aaf";

    #[test]
    fn test_sell_single_hop() {
        let token = EVMAddress::from_str("0xf3ae5d769e153ef72b4e3591ac004e89f48107a1").unwrap();
        let amount = EVMU256::from_str("20000000000000000000000").unwrap();
        // dpr => weth
        trade(
            "sell",
            token,
            amount,
            1,
            19044110,
            &EVMAddress::from_str(DPR_RICH).unwrap(),
        );
    }

    #[test]
    fn test_buy_two_hop() {
        let token =  EVMAddress::from_str("0xf3ae5d769e153ef72b4e3591ac004e89f48107a1").unwrap();
        let amount = EVMU256::from_str("2000000000000000000").unwrap();
        // dpr => usdc => weth
        trade("buy", token, amount, 0, 19044110, &EVMAddress::zero());
    }

    // https://www.tdly.co/shared/simulation/c1d5d70f-8718-4740-961a-3f789a0834c1
    #[test]
    fn test_buy_one_hop_with_fee() {
        let token = EVMAddress::from_str("0x72e4f9F808C49A2a61dE9C5896298920Dc4EEEa9").unwrap();
        let amount = EVMU256::from_str("2000000000000000000").unwrap();
        // HarryPotterObamaSonic10Inu => weth
        trade("buy", token, amount, 0, 19044110, &EVMAddress::zero());
    }

    // https://www.tdly.co/shared/simulation/83d283d4-b367-4893-85a4-4af19fc9a80b
    #[test]
    fn test_buy_two_hop_with_fee() {
        let token = EVMAddress::from_str("0x72e4f9F808C49A2a61dE9C5896298920Dc4EEEa9").unwrap();
        let amount = EVMU256::from_str("2000000000000000000").unwrap();
        // HarryPotterObamaSonic10Inu => OSAK => weth
        trade("buy", token, amount, 1, 19044110, &EVMAddress::zero());
    }

    #[test]
    fn test_buy_three_hop_with_fee() {
        // expected to fail
        let token = EVMAddress::from_str("0x72e4f9F808C49A2a61dE9C5896298920Dc4EEEa9").unwrap();
        let amount = EVMU256::from_str("2000000000000000000").unwrap();
        // HarryPotterObamaSonic10Inu => weth
        trade("buy", token, amount, 2, 19044110, &EVMAddress::zero());
    }

    #[test]
    fn test_buy_uni_v3() {
        let token = EVMAddress::from_str("0xE77EC1bF3A5C95bFe3be7BDbACfe3ac1c7E454CD").unwrap();
        let amount = EVMU256::from_str("2000000000000000000").unwrap();
        // weth => MINER
        trade("buy", token, amount, 0, 19226633, &EVMAddress::zero());
    }

    #[test]
    fn test_sell_uni_v3() {
        let token = EVMAddress::from_str("0xE77EC1bF3A5C95bFe3be7BDbACfe3ac1c7E454CD").unwrap();
        let amount = EVMU256::from_str("2000000000000000000").unwrap();
        // weth => MINER
        trade("sell", token, amount, 0, 19226633, &EVMAddress::from_str("0xD92Ec2123473e0E4099733b1e03405384Aa1024D").unwrap());
    }
    */
}
