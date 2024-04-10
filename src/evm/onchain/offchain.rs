use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    str::FromStr,
    sync::Arc,
};

use alloy_primitives::hex;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use itertools::Itertools;
use libafl::schedulers::{Scheduler, StdScheduler};
use revm_interpreter::{analysis::to_analysed, BytecodeLocked, CallContext, CallScheme, Contract, Host, Interpreter};
use revm_primitives::Bytecode;
use serde::{de::DeserializeOwned, Serialize};
use tracing::debug;

use super::{endpoints::PairData, ChainConfig};
use crate::{
    evm::{
        contract_utils::SetupData,
        host::FuzzHost,
        input::ConciseEVMInput,
        types::{generate_random_address, EVMAddress, EVMFuzzState, EVMU256},
        vm::{EVMExecutor, EVMState, MEM_LIMIT},
        PRESET_WETH,
    },
    generic_vm::vm_state::VMStateT,
    input::ConciseSerde,
    is_call_success,
};

/// Off-chain configuration
/// Due to the dependency on the vm executor and state when fetching data,
/// we implement eager loading for simplification.
#[derive(Clone, Default, Debug)]
pub struct OffChainConfig {
    /// Preset v2 pairs
    pub v2_pairs: HashSet<EVMAddress>,

    // token -> pair_data
    pair_cache: HashMap<EVMAddress, Vec<PairData>>,
    // pair -> reserves
    reserves_cache: HashMap<EVMAddress, (EVMU256, EVMU256)>,
    // (pair,token) -> balance
    balance_cache: HashMap<(EVMAddress, EVMAddress), EVMU256>,
    // addr -> code
    code_cache: HashMap<EVMAddress, Bytecode>,
}

impl OffChainConfig {
    pub fn new(setup_data: &SetupData) -> Result<Self> {
        // setup vm, state
        let mut state = EVMFuzzState::default();
        let mut fuzz_host = FuzzHost::new(StdScheduler::new(), "work_dir".to_string());
        fuzz_host.evmstate = setup_data.evmstate.clone();
        fuzz_host.env = setup_data.env.clone();
        for (addr, bytecode) in &setup_data.code {
            let code = Arc::new(BytecodeLocked::try_from(to_analysed(Bytecode::new_raw(bytecode.clone()))).unwrap());
            fuzz_host.code.insert(*addr, code);
        }
        let mut vm: EVMExecutor<EVMState, ConciseEVMInput, StdScheduler<EVMFuzzState>> =
            EVMExecutor::new(fuzz_host, generate_random_address(&mut state));

        // build offchain config
        let v2_pairs: HashSet<_> = setup_data.v2_pairs.iter().cloned().collect();
        let mut offchain = Self {
            v2_pairs,
            ..Default::default()
        };
        let v2_pairs = offchain.v2_pairs.clone();
        for pair in v2_pairs {
            offchain.build_cache(pair, &mut state, &mut vm)?;
        }

        debug!("🔥 OffChainConfig initialized: {:?}", offchain);
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
        let (pair_code, _) = vm
            .host
            .code(pair)
            .ok_or_else(|| anyhow!("Pair {:?} code not found", pair))?;

        // token0
        let res = self.call(self.token0_input(), pair_code.clone(), pair, state, vm)?;
        let token0 = EVMAddress::from_slice(&res[12..32]);
        let (token0_code, _) = vm
            .host
            .code(token0)
            .ok_or_else(|| anyhow!("Token0 {:?} code not found", token0))?;
        let res = self.call(self.decimals_input(), token0_code.clone(), token0, state, vm)?;
        let decimals_0 = res[31] as u32;

        // token1
        let res = self.call(self.token1_input(), pair_code.clone(), pair, state, vm)?;
        let token1 = EVMAddress::from_slice(&res[12..32]);
        let (token1_code, _) = vm
            .host
            .code(token1)
            .ok_or_else(|| anyhow!("Token1 {:?} code not found", token1))?;
        let res = self.call(self.decimals_input(), token1_code.clone(), token1, state, vm)?;
        let decimals_1 = res[31] as u32;

        // reserves
        let res = self.call(self.get_reserves_input(), pair_code.clone(), pair, state, vm)?;
        let reserves0 = EVMU256::try_from_be_slice(&res[..32]).unwrap_or_default();
        let reserves1 = EVMU256::try_from_be_slice(&res[32..64]).unwrap_or_default();

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
        let pair_code = Bytecode::new_raw(Bytes::from(pair_code.bytecode().to_vec()));
        self.code_cache.insert(pair, pair_code);
        let token0_code = Bytecode::new_raw(Bytes::from(token0_code.bytecode().to_vec()));
        self.code_cache.insert(token0, token0_code);
        let token1_code = Bytecode::new_raw(Bytes::from(token1_code.bytecode().to_vec()));
        self.code_cache.insert(token1, token1_code);

        Ok(())
    }

    fn build_pair_cache(&mut self, token: EVMAddress, mut pair: PairData) {
        let in_token = format!("{:?}", token);
        pair.in_ = if in_token == pair.token0 { 0 } else { 1 };
        pair.next = if in_token == pair.token0 {
            pair.token1.clone()
        } else {
            in_token.clone()
        };
        pair.in_token = in_token.clone();
        pair.interface = "uniswapv2".to_string();
        pair.src_exact = "uniswapv2_eth".to_string();
        pair.src = if self.get_pegged_token().values().contains(&in_token) {
            "pegged".to_string()
        } else {
            "lp".to_string()
        };

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
                scheme: CallScheme::StaticCall,
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
    fn get_pair(&mut self, token: &str, _is_pegged: bool) -> Vec<PairData> {
        let token = EVMAddress::from_str(token).unwrap();
        self.pair_cache.get(&token).cloned().unwrap_or_default()
    }

    fn fetch_reserve(&self, pair: &str) -> Option<(String, String)> {
        let pair = EVMAddress::from_str(pair).unwrap();
        let (res0, res1) = self.reserves_cache.get(&pair)?;
        let reserve0 = hex::encode::<[u8; 32]>(res0.to_be_bytes());
        let reserve1 = hex::encode::<[u8; 32]>(res1.to_be_bytes());
        Some((reserve0, reserve1))
    }

    fn get_contract_code_analyzed(&mut self, address: EVMAddress, _force_cache: bool) -> Bytecode {
        self.code_cache.get(&address).cloned().unwrap_or_default()
    }

    fn get_v3_fee(&mut self, _address: EVMAddress) -> u32 {
        0
    }

    fn get_token_balance(&mut self, token: EVMAddress, address: EVMAddress) -> EVMU256 {
        self.balance_cache.get(&(address, token)).cloned().unwrap_or_default()
    }

    fn get_weth(&self) -> String {
        PRESET_WETH.to_string()
    }

    fn get_pegged_token(&self) -> HashMap<String, String> {
        HashMap::from_iter([("WETH".to_string(), PRESET_WETH.to_string())])
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use libafl::schedulers::StdScheduler;

    use super::*;
    use crate::{
        evm::{host::FuzzHost, input::ConciseEVMInput, types::generate_random_address, vm::EVMState},
        generic_vm::vm_executor::GenericVM,
        logger,
    };

    #[test]
    fn test_offchain_v2_pairs() {
        logger::init_test();

        // UNI-V2: WETH-USDT
        let pair = "0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852";
        let pair_addr = EVMAddress::from_str(pair).unwrap();
        // WETH
        let weth = PRESET_WETH;
        let weth_addr = EVMAddress::from_str(weth).unwrap();
        // USDT
        let usdt = "0xdac17f958d2ee523a2206206994597c13d831ec7";
        let usdt_addr = EVMAddress::from_str(usdt).unwrap();

        // new offchain config
        let setup_data = build_setup_data(pair_addr, weth_addr, usdt_addr);
        let mut offchain = OffChainConfig::new(&setup_data).unwrap();
        assert_eq!(offchain.v2_pairs.len(), 1);

        // test get_pair
        let pairs = offchain.get_pair(weth, true);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].token0, weth);
        assert_eq!(pairs[0].token1, usdt);
        assert_eq!(pairs[0].decimals_0, 18);
        assert_eq!(pairs[0].decimals_1, 6);
        assert_eq!(
            pairs[0].initial_reserves_0,
            EVMU256::from_str_radix("049f9bc137cd08508bb0", 16).unwrap()
        );
        assert_eq!(
            pairs[0].initial_reserves_1,
            EVMU256::from_str_radix("41062620fcfd", 16).unwrap()
        );
        assert_eq!(pairs[0].in_, 0);
        assert_eq!(pairs[0].next, usdt);
        assert_eq!(pairs[0].in_token, weth);
        assert_eq!(pairs[0].interface, "uniswapv2");

        // test fetch_reserve
        let (res0, res1) = offchain.fetch_reserve(pair).unwrap();
        assert_eq!(res0, "00000000000000000000000000000000000000000000049f9bc137cd08508bb0");
        assert_eq!(res1, "000000000000000000000000000000000000000000000000000041062620fcfd");

        // test get_token_balance
        let balance = offchain.get_token_balance(usdt_addr, pair_addr);
        assert_eq!(balance, EVMU256::from(72553743663529u128));

        // test get_contract_code_analyzed
        let code = offchain.get_contract_code_analyzed(pair_addr, false);
        assert!(!code.is_empty());
    }

    fn build_setup_data(pair: EVMAddress, weth: EVMAddress, usdt: EVMAddress) -> SetupData {
        let mut state = EVMFuzzState::default();
        let fuzz_host = FuzzHost::new(StdScheduler::new(), "work_dir".to_string());
        let mut vm: EVMExecutor<EVMState, ConciseEVMInput, StdScheduler<EVMFuzzState>> =
            EVMExecutor::new(fuzz_host, generate_random_address(&mut state));

        // deploy contracts
        let code_path = "tests/presets/v2_pair/UniswapV2Pair.bytecode";
        deploy(&pair, code_path, &mut state, &mut vm);
        let code_path = "tests/presets/v2_pair/WETH9.bytecode";
        deploy(&weth, code_path, &mut state, &mut vm);
        let code_path = "tests/presets/v2_pair/USDT.bytecode";
        deploy(&usdt, code_path, &mut state, &mut vm);
        init_pair_tokens(&pair, &weth, &usdt, &mut vm);

        let code: HashMap<EVMAddress, Bytes> = vm
            .host
            .code
            .into_iter()
            .map(|(k, v)| (k, Bytes::from_iter(v.bytecode().iter().cloned())))
            .collect();

        SetupData {
            evmstate: vm.host.evmstate.clone(),
            env: vm.host.env.clone(),
            code,
            v2_pairs: vec![pair],
            ..Default::default()
        }
    }

    fn deploy<VS, CI, SC>(
        address: &EVMAddress,
        code_path: &str,
        state: &mut EVMFuzzState,
        vm: &mut EVMExecutor<VS, CI, SC>,
    ) where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        let hex_code = fs::read_to_string(code_path)
            .expect("bytecode not found")
            .trim()
            .to_string();
        let bytecode = Bytecode::new_raw(Bytes::from(hex::decode(hex_code).unwrap()));

        vm.deploy(bytecode, None, *address, state);
    }

    fn init_pair_tokens<VS, CI, SC>(
        pair: &EVMAddress,
        token0: &EVMAddress,
        token1: &EVMAddress,
        vm: &mut EVMExecutor<VS, CI, SC>,
    ) where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        // Initialize pair
        let slots = vm.host.evmstate.state.get_mut(pair).unwrap();
        // slot 6: token0
        slots.insert(EVMU256::from(6), EVMU256::from_be_slice(token0.as_slice()));
        // slot 7: token1
        slots.insert(EVMU256::from(7), EVMU256::from_be_slice(token1.as_slice()));
        // slot 8: blockTimestampLast + reserve1 + reserve0
        let slot8 =
            EVMU256::from_str_radix("660e130b000000000000000041062620fcfd00000000049f9bc137cd08508bb0", 16).unwrap();
        slots.insert(EVMU256::from(8), slot8);

        // Initialize token0
        let slots = vm.host.evmstate.state.get_mut(token0).unwrap();
        // balanceOf pair
        let slot =
            EVMU256::from_str_radix("aced72359d8708e95d2112ba70e71fa267967a5588d15e7c78c1904e0debe410", 16).unwrap();
        slots.insert(slot, EVMU256::from(21519275363657114356534u128));
        // slot 2: decimals
        slots.insert(EVMU256::from(2), EVMU256::from(18));

        // Initialize token1
        let slots = vm.host.evmstate.state.get_mut(token1).unwrap();
        // balanceOf pair
        let slot =
            EVMU256::from_str_radix("45b1147656da4d940c556082f0e09e91e3d046c1c84468f8ead64d8fdc1c749a", 16).unwrap();
        slots.insert(slot, EVMU256::from(72553743663529u128));
        // slot 9: decimals
        slots.insert(EVMU256::from(9), EVMU256::from(6));
    }
}
