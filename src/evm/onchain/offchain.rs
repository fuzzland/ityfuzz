use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    str::FromStr,
    sync::Arc,
};

use alloy_primitives::hex;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::{BytecodeLocked, CallContext, CallScheme, Contract, Interpreter};
use revm_primitives::Bytecode;
use serde::{de::DeserializeOwned, Serialize};
use tracing::debug;

use super::{endpoints::PairData, ChainConfig};
use crate::{
    evm::{
        tokens::uniswap::CODE_REGISTRY,
        types::{EVMAddress, EVMFuzzState, EVMU256},
        vm::{EVMExecutor, MEM_LIMIT},
    },
    generic_vm::vm_state::VMStateT,
    get_code_tokens,
    input::ConciseSerde,
    is_call_success,
};

/// Off-chain configuration
/// Due to the dependency on the vm executor and state when fetching data,
/// we implement eager loading for simplification.
#[derive(Clone, Default)]
pub struct OffChainConfig {
    /// Preset v2 pairs
    pub v2_pairs: HashSet<EVMAddress>,

    // token -> pair_data
    pair_cache: HashMap<EVMAddress, Vec<PairData>>,
    // pair -> reserves
    reserves_cache: HashMap<EVMAddress, (EVMU256, EVMU256)>,
    // (pair,token) -> balance
    balance_cache: HashMap<(EVMAddress, EVMAddress), EVMU256>,
}

impl OffChainConfig {
    pub fn new<VS, CI, SC>(
        v2_pairs: &[EVMAddress],
        state: &mut EVMFuzzState,
        vm: &mut EVMExecutor<VS, CI, SC>,
    ) -> Result<Self>
    where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        let v2_pairs: HashSet<_> = v2_pairs.iter().cloned().collect();
        let mut offchain = Self {
            v2_pairs: v2_pairs.clone(),
            ..Default::default()
        };
        for pair in v2_pairs {
            offchain.build_cache(pair, state, vm)?;
        }

        Ok(offchain)
    }

    fn build_cache<VS, CI, SC>(
        &mut self,
        pair: EVMAddress,
        state: &mut EVMFuzzState,
        vm: &mut EVMExecutor<VS, CI, SC>,
    ) -> Result<()>
    where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        debug!("Building cache for pair: {:?}", pair);
        let pair_code = get_code_tokens!(pair, vm, state);

        // token0
        let res = self.call(self.token0_input(), pair_code.clone(), pair, state, vm)?;
        let token0 = EVMAddress::from_slice(&res[12..32]);
        let token0_code = get_code_tokens!(token0, vm, state);
        let res = self.call(self.decimals_input(), token0_code.clone(), token0, state, vm)?;
        let decimals_0 = res[31] as u32;

        // token1
        let res = self.call(self.token1_input(), pair_code.clone(), pair, state, vm)?;
        let token1 = EVMAddress::from_slice(&res[12..32]);
        let token1_code = get_code_tokens!(token1, vm, state);
        let res = self.call(self.decimals_input(), token1_code.clone(), token1, state, vm)?;
        let decimals_1 = res[31] as u32;

        // reserves
        let res = self.call(self.get_reserves_input(), pair_code.clone(), pair, state, vm)?;
        let reserves0 = EVMU256::try_from_be_slice(&res[18..32]).unwrap_or_default();
        let reserves1 = EVMU256::try_from_be_slice(&res[4..18]).unwrap_or_default();

        // balances
        let res = self.call(self.balance_of_input(pair), token0_code.clone(), token0, state, vm)?;
        let balance0 = EVMU256::try_from_be_slice(res.to_vec().as_slice()).unwrap_or_default();
        let res = self.call(self.balance_of_input(pair), token1_code.clone(), token1, state, vm)?;
        let balance1 = EVMU256::try_from_be_slice(res.to_vec().as_slice()).unwrap_or_default();

        let pair_data = PairData {
            pair: format!("{:?}", pair),
            token0: format!("{:?}", token0),
            token1: format!("{:?}", token1),
            decimals_0,
            decimals_1,
            initial_reserves_0: reserves0,
            initial_reserves_1: reserves1,
            ..Default::default()
        };
        debug!("Pair data: {:?}", pair_data);

        // build cache
        self.build_pair_cache(token0, pair_data.clone());
        self.build_pair_cache(token1, pair_data);
        self.reserves_cache.insert(pair, (reserves0, reserves1));
        self.balance_cache.insert((pair, token0), balance0);
        self.balance_cache.insert((pair, token1), balance1);

        Ok(())
    }

    // TODO src_exact?
    fn build_pair_cache(&mut self, token: EVMAddress, mut pair: PairData) {
        let in_token = format!("{:?}", token);
        pair.in_ = if in_token == pair.token0 { 0 } else { 1 };
        pair.next = if in_token == pair.token0 {
            pair.token1.clone()
        } else {
            in_token.clone()
        };
        pair.in_token = in_token;
        pair.interface = "uniswapv2".to_string();

        self.pair_cache.entry(token).or_default().push(pair);
    }

    fn call<VS, CI, SC>(
        &self,
        input: Bytes,
        code: Arc<BytecodeLocked>,
        target: EVMAddress,
        state: &mut EVMFuzzState,
        vm: &mut EVMExecutor<VS, CI, SC>,
    ) -> Result<Bytes>
    where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        let call = Contract::new_with_context_analyzed(
            input,
            code,
            &CallContext {
                address: target,
                caller: EVMAddress::default(),
                code_address: target,
                apparent_value: EVMU256::ZERO,
                scheme: CallScheme::Call,
            },
        );

        let mut interp = Interpreter::new_with_memory_limit(call, 1e10 as u64, true, MEM_LIMIT);
        let ir = vm.host.run_inspect(&mut interp, state);
        if !is_call_success!(ir) {
            return Err(anyhow!("Call failed: {:?}", ir));
        }

        Ok(interp.return_value())
    }

    // token0()
    #[inline]
    fn token0_input(&self) -> Bytes {
        Bytes::from(hex!("0dfe1681").to_vec())
    }

    // token1()
    #[inline]
    fn token1_input(&self) -> Bytes {
        Bytes::from(hex!("d21220a7").to_vec())
    }

    // getReserves()
    #[inline]
    fn get_reserves_input(&self) -> Bytes {
        Bytes::from(hex!("0902f1ac").to_vec())
    }

    // decimals()
    #[inline]
    fn decimals_input(&self) -> Bytes {
        Bytes::from(hex!("313ce567").to_vec())
    }

    // balanceOf(address)
    #[inline]
    fn balance_of_input(&self, addr: EVMAddress) -> Bytes {
        let mut input = hex!("70a08231").to_vec(); // balanceOf
        input.extend_from_slice(&[0x00; 12]); // padding
        input.extend_from_slice(&addr.0); // addr
        Bytes::from(input)
    }
}

impl ChainConfig for OffChainConfig {
    // TODO pegged_tokens?
    fn get_pair(&mut self, token: &str, _network: &str, is_pegged: bool, _weth: String) -> Vec<PairData> {
        let token = EVMAddress::from_str(token).unwrap();
        let mut pairs = self.pair_cache.get(&token).cloned().unwrap_or_default();
        for pair in pairs.iter_mut() {
            pair.src = if is_pegged { "pegged" } else { "lp" }.to_string();
        }

        pairs
    }

    fn fetch_reserve(&self, pair: &str) -> Option<(String, String)> {
        let pair = EVMAddress::from_str(pair).unwrap();
        let (res0, res1) = self.reserves_cache.get(&pair)?;
        Some((res0.to_string(), res1.to_string()))
    }

    fn get_contract_code_analyzed(&mut self, _address: EVMAddress, _force_cache: bool) -> Bytecode {
        unreachable!()
    }

    fn get_v3_fee(&mut self, _address: EVMAddress) -> u32 {
        0
    }

    fn get_token_balance(&mut self, token: EVMAddress, address: EVMAddress) -> EVMU256 {
        self.balance_cache.get(&(address, token)).cloned().unwrap_or_default()
    }

    fn chain_name(&self) -> String {
        String::new()
    }
}
