pub mod abi_decompiler;
pub mod endpoints;
pub mod flashloan;
pub mod offchain;

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt::{Debug, Formatter},
    ops::Deref,
    rc::Rc,
    str::FromStr,
    sync::Arc,
};

use bytes::Bytes;
use crypto::{digest::Digest, sha3::Sha3};
use itertools::Itertools;
use libafl::{prelude::HasMetadata, schedulers::Scheduler};
use revm_interpreter::{analysis::to_analysed, Interpreter};
use revm_primitives::Bytecode;
use tracing::debug;

use self::endpoints::PairData;
use super::{corpus_initializer::EnvMetadata, types::EVMFuzzState};
use crate::{
    evm::{
        abi::{get_abi_type_boxed, register_abi_instance},
        blaz::builder::{ArtifactInfoMetadata, BuildJob},
        bytecode_analyzer,
        config::StorageFetchingMode,
        contract_utils::{extract_sig_from_contract, ABIConfig, ContractLoader},
        corpus_initializer::ABIMap,
        host::FuzzHost,
        input::{EVMInput, EVMInputTy},
        middlewares::{
            cheatcode::CHEATCODE_ADDRESS,
            middleware::{add_corpus, Middleware, MiddlewareType},
        },
        mutator::AccessPattern,
        onchain::{abi_decompiler::fetch_abi_evmole, endpoints::OnChainConfig, flashloan::register_borrow_txn},
        types::{convert_u256_to_h160, EVMAddress, EVMU256},
        vm::IS_FAST_CALL,
    },
    handle_contract_insertion,
    state::HasCaller,
    state_input::StagedVMState,
};

pub static mut BLACKLIST_ADDR: Option<HashSet<EVMAddress>> = None;
pub static mut WHITELIST_ADDR: Option<HashSet<EVMAddress>> = None;

const UNBOUND_THRESHOLD: usize = 30;

pub trait ChainConfig {
    fn get_pair(&mut self, token: &str, is_pegged: bool) -> Vec<PairData>;
    fn fetch_reserve(&self, pair: &str) -> Option<(String, String)>;
    fn get_contract_code_analyzed(&mut self, address: EVMAddress, force_cache: bool) -> Bytecode;
    fn get_v3_fee(&mut self, address: EVMAddress) -> u32;
    fn get_token_balance(&mut self, token: EVMAddress, address: EVMAddress) -> EVMU256;
    fn get_weth(&self) -> String;
    fn get_pegged_token(&self) -> HashMap<String, String>;
}

#[derive(Clone)]
pub struct OnChain {
    pub loaded_data: HashSet<(EVMAddress, EVMU256)>,
    pub loaded_code: HashSet<EVMAddress>,
    pub loaded_abi: HashSet<EVMAddress>,
    pub calls: HashMap<(EVMAddress, usize), HashSet<EVMAddress>>,
    pub locs: HashMap<(EVMAddress, usize), HashSet<EVMU256>>,
    pub endpoint: OnChainConfig,
    pub blacklist: HashSet<EVMAddress>,
    pub storage_fetching: StorageFetchingMode,
    pub storage_all: HashMap<EVMAddress, Arc<HashMap<String, EVMU256>>>,
    pub storage_dump: HashMap<EVMAddress, Arc<HashMap<EVMU256, EVMU256>>>,
    pub builder: Option<BuildJob>,
    pub address_to_abi: HashMap<EVMAddress, Vec<ABIConfig>>,
}

impl Debug for OnChain {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnChain")
            .field("loaded_data", &self.loaded_data)
            .field("loaded_code", &self.loaded_code)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl OnChain {
    pub fn new(endpoint: OnChainConfig, storage_fetching: StorageFetchingMode) -> Self {
        unsafe {
            BLACKLIST_ADDR = Some(HashSet::from([
                EVMAddress::from_str("0x3cb4ca3c9dc0e02d252098eebb3871ac7a43c54d").unwrap(),
                EVMAddress::from_str("0x6aed013308d847cb87502d86e7d9720b17b4c1f2").unwrap(),
                EVMAddress::from_str("0x5a58505a96d1dbf8df91cb21b54419fc36e93fde").unwrap(),
                EVMAddress::from_str("0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640").unwrap(),
                EVMAddress::from_str("0xa40cac1b04d7491bdfb42ccac97dff25e0efb09e").unwrap(),
                // uniswap router
                EVMAddress::from_str("0xca143ce32fe78f1f7019d7d551a6402fc5350c73").unwrap(),
                EVMAddress::from_str("0x7a250d5630b4cf539739df2c5dacb4c659f2488d").unwrap(),
                // pancake router
                EVMAddress::from_str("0x6CD71A07E72C514f5d511651F6808c6395353968").unwrap(),
                EVMAddress::from_str("0x10ed43c718714eb63d5aa57b78b54704e256024e").unwrap(),
            ]));
        }
        Self {
            loaded_data: Default::default(),
            loaded_code: Default::default(),
            loaded_abi: Default::default(),
            calls: Default::default(),
            locs: Default::default(),
            endpoint,
            blacklist: HashSet::from([
                EVMAddress::from_str("0x3cb4ca3c9dc0e02d252098eebb3871ac7a43c54d").unwrap(),
                EVMAddress::from_str("0x6aed013308d847cb87502d86e7d9720b17b4c1f2").unwrap(),
                EVMAddress::from_str("0x5a58505a96d1dbf8df91cb21b54419fc36e93fde").unwrap(),
                EVMAddress::from_str("0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640").unwrap(),
                EVMAddress::from_str("0xa40cac1b04d7491bdfb42ccac97dff25e0efb09e").unwrap(),
                // uniswap router
                EVMAddress::from_str("0xca143ce32fe78f1f7019d7d551a6402fc5350c73").unwrap(),
                EVMAddress::from_str("0x7a250d5630b4cf539739df2c5dacb4c659f2488d").unwrap(),
                // pancake router
                EVMAddress::from_str("0x6CD71A07E72C514f5d511651F6808c6395353968").unwrap(),
                EVMAddress::from_str("0x10ed43c718714eb63d5aa57b78b54704e256024e").unwrap(),
            ]),
            storage_all: Default::default(),
            storage_dump: Default::default(),
            builder: None,
            address_to_abi: Default::default(),
            storage_fetching,
        }
    }

    pub fn add_builder(&mut self, builder: BuildJob) {
        self.builder = Some(builder);
    }
    pub fn add_abi(&mut self, abi: HashMap<EVMAddress, Vec<ABIConfig>>) {
        self.address_to_abi = abi;
    }

    pub fn add_blacklist(&mut self, address: EVMAddress) {
        unsafe {
            BLACKLIST_ADDR.as_mut().unwrap().insert(address);
        }
        self.blacklist.insert(address);
    }
}

pub fn keccak256(input: &[u8]) -> EVMU256 {
    let mut hasher = Sha3::keccak256();
    let mut output = [0u8; 32];
    hasher.input(input);
    hasher.result(&mut output);
    EVMU256::from_be_bytes(output)
}

impl<SC> Middleware<SC> for OnChain
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, state: &mut EVMFuzzState) {
        #[cfg(feature = "force_cache")]
        macro_rules! force_cache {
            ($ty: expr, $target: expr) => {{
                let pc = interp.program_counter();
                match $ty.get_mut(&(interp.contract.address, pc)) {
                    None => {
                        $ty.insert((interp.contract.address, pc), HashSet::from([$target]));
                        false
                    }
                    Some(v) => {
                        if v.len() > UNBOUND_THRESHOLD {
                            true
                        } else {
                            v.insert($target);
                            false
                        }
                    }
                }
            }};
        }
        #[cfg(not(feature = "force_cache"))]
        macro_rules! force_cache {
            ($ty: expr, $target: expr) => {
                false
            };
        }

        match *interp.instruction_pointer {
            // SLOAD
            0x54 => {
                let address = interp.contract.address;
                let slot_idx: alloy_primitives::Uint<256, 4> = interp.stack.peek(0).unwrap();

                macro_rules! load_data {
                    ($func: ident, $stor: ident, $key: ident) => {{
                        if !self.$stor.contains_key(&address) {
                            if let Some(storage) = self.endpoint.$func(address) {
                                self.$stor.insert(address, storage);
                            }
                        }
                        match self.$stor.get(&address) {
                            Some(v) => v.get(&$key).unwrap_or(&EVMU256::ZERO).clone(),
                            None => {
                                self.endpoint
                                    .get_contract_slot(address, slot_idx, force_cache!(self.locs, slot_idx))
                            }
                        }
                    }};
                    () => {};
                }

                // todo! get storage data from reth
                host.next_slot = match self.storage_fetching {
                    StorageFetchingMode::Dump => {
                        load_data!(fetch_storage_dump, storage_dump, slot_idx)
                    }
                    StorageFetchingMode::OneByOne => {
                        self.endpoint
                            .get_contract_slot(address, slot_idx, force_cache!(self.locs, slot_idx))
                    }
                };
                // println!("SLOAD {:?} {:?}", slot_idx, host.next_slot);
            }
            #[cfg(feature = "real_balance")]
            // BALANCE
            0x31 => {
                let address = convert_u256_to_h160(interp.stack.peek(0).unwrap());
                debug!("onchain balance for {:?}", address);
                // std::thread::sleep(std::time::Duration::from_secs(3));
                host.next_slot = self.endpoint.get_balance(address);
            }
            #[cfg(feature = "real_balance")]
            // 	SELFBALANCE
            0x47 => {
                let address = interp.contract.address;
                debug!("onchain selfbalance for {:?}", address);
                // std::thread::sleep(std::time::Duration::from_secs(3));
                host.next_slot = self.endpoint.get_balance(address);
            }
            // COINBASE
            0x41 => {
                if host.env.block.coinbase == EVMAddress::zero() {
                    host.env.block.coinbase = self.endpoint.fetch_blk_coinbase();
                }
            }
            // TIMESTAMP
            0x42 => {
                if host.env.block.timestamp == EVMU256::from(1) {
                    host.env.block.timestamp = self.endpoint.fetch_blk_timestamp();
                }
            }
            // GASLIMIT
            0x45 => {
                if host.env.block.gas_limit == EVMU256::MAX {
                    host.env.block.gas_limit = self.endpoint.fetch_blk_gaslimit();
                }
            }
            // CHAINID
            0x46 => {
                host.env.tx.chain_id = Some(self.endpoint.chain_id as u64);
            }
            // CALL | CALLCODE | DELEGATECALL | STATICCALL | EXTCODESIZE | EXTCODECOPY | EXTCODEHASH
            0xf1 | 0xf2 | 0xf4 | 0xfa | 0x3b | 0x3c | 0x3f => {
                let caller = interp.contract.address;
                let address = match *interp.instruction_pointer {
                    0xf1 | 0xf2 => {
                        // CALL | CALLCODE
                        #[cfg(feature = "real_balance")]
                        {
                            // Get balance of the callee
                            host.next_slot = self.endpoint.get_balance(caller);
                        }

                        interp.stack.peek(1).unwrap()
                    }
                    0xf4 | 0xfa => interp.stack.peek(1).unwrap(),
                    0x3b | 0x3c | 0x3f => interp.stack.peek(0).unwrap(),
                    _ => unreachable!(),
                };

                let address_h160 = convert_u256_to_h160(address);
                if self.loaded_abi.contains(&address_h160) {
                    return;
                }
                let force_cache = force_cache!(self.calls, address_h160);
                let is_proxy_call = matches!(*interp.instruction_pointer, 0xf2 | 0xf4);
                let should_setup_abi = *interp.instruction_pointer != 0x3b && *interp.instruction_pointer != 0x3c;
                self.load_code(
                    address_h160,
                    host,
                    force_cache,
                    should_setup_abi,
                    is_proxy_call,
                    caller,
                    state,
                );
            }
            _ => {}
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::OnChain
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl OnChain {
    #[allow(clippy::too_many_arguments)]
    pub fn load_code<SC>(
        &mut self,
        address_h160: EVMAddress,
        host: &mut FuzzHost<SC>,
        force_cache: bool,
        _should_setup_abi: bool,
        is_proxy_call: bool,
        caller: EVMAddress,
        state: &mut EVMFuzzState,
    ) where
        SC: Scheduler<State = EVMFuzzState> + Clone,
    {
        let contract_code = self.endpoint.get_contract_code(address_h160, force_cache);
        let code = hex::decode(contract_code).unwrap();
        let contract_code = to_analysed(Bytecode::new_raw(Bytes::from(code)));

        if contract_code.is_empty() || force_cache {
            self.loaded_code.insert(address_h160);
            self.loaded_abi.insert(address_h160);
            return;
        }
        if !self.loaded_code.contains(&address_h160) && !host.code.contains_key(&address_h160) {
            bytecode_analyzer::add_analysis_result_to_state(&contract_code, state);
            host.set_codedata(address_h160, contract_code.clone());
        }
        if unsafe { IS_FAST_CALL } || self.blacklist.contains(&address_h160) {
            return;
        }

        // setup abi
        self.loaded_abi.insert(address_h160);

        let mut parsed_abi = vec![];
        if let Some(abis) = self.address_to_abi.get(&address_h160) {
            parsed_abi = abis.clone();
        } else {
            let mut abi = None;
            if let Some(builder) = &self.builder {
                debug!("onchain job {:?}", address_h160);
                let build_job = builder.onchain_job(self.endpoint.chain_name.clone(), address_h160);

                if let Some(job) = build_job {
                    abi = Some(job.abi.clone());
                    // replace the code with the one from builder
                    // debug!("replace code for {:?} with builder's", address_h160);
                    // host.set_codedata(address_h160, contract_code.clone());
                    state
                        .metadata_map_mut()
                        .get_mut::<ArtifactInfoMetadata>()
                        .expect("artifact info metadata")
                        .add(address_h160, job.clone());

                    job.save_source_map(&address_h160);
                }
            }

            if abi.is_none() {
                debug!("fetching abi {:?}", address_h160);
                abi = self.endpoint.fetch_abi(address_h160);
            }

            match abi {
                Some(ref abi_ins) => parsed_abi = ContractLoader::parse_abi_str(abi_ins),
                None => {
                    // 1. Extract abi from bytecode, and see do we have any function sig available
                    //    in state
                    // 2. Use EVMole to extract abi
                    // 3. Reconfirm on failures of EVMole
                    debug!("Contract {:?} has no abi", address_h160);
                    let contract_code = contract_code.bytes();
                    let contract_code_str = hex::encode(contract_code);
                    let sigs = extract_sig_from_contract(&contract_code_str);
                    let mut unknown_sigs: usize = 0;
                    for sig in &sigs {
                        match state.metadata_map().get::<ABIMap>() {
                            Some(abis) => {
                                if let Some(abi) = abis.get(sig) {
                                    parsed_abi.push(abi.clone());
                                } else {
                                    unknown_sigs += 1;
                                }
                            }
                            None => {
                                unknown_sigs += 1;
                            }
                        }
                    }

                    if unknown_sigs >= sigs.len() / 30 {
                        debug!("Too many unknown function signature ({:?}) for {:?}, we are going to decompile this contract using EVMole", unknown_sigs, address_h160);
                        let abis = fetch_abi_evmole(contract_code)
                            .iter()
                            .map(|abi| {
                                if let Some(known_abi) =
                                    state.metadata_map().get::<ABIMap>().unwrap().get(&abi.function)
                                {
                                    known_abi
                                } else {
                                    abi
                                }
                            })
                            .cloned()
                            .collect_vec();
                        parsed_abi = abis;
                    }
                }
            }
        }
        // set up host
        let mut abi_hashes_to_add = HashSet::new();
        if is_proxy_call {
            // check caller's hash and see what is missing
            let caller_hashes: Vec<[u8; 4]> = match host.address_to_hash.get(&caller) {
                Some(v) => v.clone(),
                None => vec![],
            };
            let caller_hashes_set = caller_hashes.iter().cloned().collect::<HashSet<_>>();
            let new_hashes = parsed_abi.iter().map(|abi| abi.function).collect::<HashSet<_>>();
            for hash in new_hashes {
                if !caller_hashes_set.contains(&hash) {
                    abi_hashes_to_add.insert(hash);
                    host.add_one_hashes(caller, hash);
                }
            }
            debug!(
                "Propagating hashes {:?} for proxy {:?}",
                abi_hashes_to_add.iter().map(hex::encode).collect::<Vec<_>>(),
                caller
            );
        } else {
            abi_hashes_to_add = parsed_abi.iter().map(|abi| abi.function).collect::<HashSet<_>>();
            host.add_hashes(address_h160, parsed_abi.iter().map(|abi| abi.function).collect());
        }
        let target = if is_proxy_call { caller } else { address_h160 };
        if target != CHEATCODE_ADDRESS {
            state.add_address(&target);
        }

        // notify flashloan and blacklisting flashloan addresses
        {
            handle_contract_insertion!(
                state,
                host,
                target,
                address_h160,
                parsed_abi
                    .iter()
                    .filter(|x| abi_hashes_to_add.contains(&x.function))
                    .cloned()
                    .collect::<Vec<ABIConfig>>()
            );
        }
        // add abi to corpus
        if let Some(whitelist) = unsafe { WHITELIST_ADDR.as_ref() } {
            if !whitelist.contains(&target) {
                return;
            }
        }

        parsed_abi
            .iter()
            .filter(|v| !v.is_constructor)
            .filter(|v| abi_hashes_to_add.contains(&v.function))
            .for_each(|abi| {
                #[cfg(not(feature = "fuzz_static"))]
                if abi.is_static {
                    return;
                }

                let mut abi_instance = get_abi_type_boxed(&abi.abi);
                abi_instance.set_func_with_signature(abi.function, &abi.function_name, &abi.abi);
                register_abi_instance(target, abi_instance.clone(), state);

                let input = EVMInput {
                    caller: state.get_rand_caller(),
                    contract: target,
                    data: Some(abi_instance),
                    sstate: StagedVMState::new_uninitialized(),
                    sstate_idx: 0,
                    txn_value: if abi.is_payable { Some(EVMU256::ZERO) } else { None },
                    step: false,
                    env: state.metadata_map().get::<EnvMetadata>().unwrap().env.clone(),
                    access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                    liquidation_percent: 0,
                    input_type: EVMInputTy::ABI,
                    direct_data: Default::default(),
                    randomness: vec![0],
                    repeat: 1,
                    swap_data: HashMap::new(),
                };
                add_corpus(host, state, &input);
            });
    }
}
