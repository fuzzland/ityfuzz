use crate::evm::abi::{get_abi_type_boxed, register_abi_instance};
use crate::evm::bytecode_analyzer;
use crate::evm::config::StorageFetchingMode;
use crate::evm::contract_utils::{ABIConfig, ContractLoader, extract_sig_from_contract};
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT, EVMInputTy};

use crate::evm::host::FuzzHost;
use crate::evm::middlewares::middleware::{add_corpus, Middleware, MiddlewareType};
use crate::evm::mutator::AccessPattern;
use crate::evm::onchain::abi_decompiler::fetch_abi_heimdall;
use crate::evm::onchain::endpoints::OnChainConfig;
use crate::evm::vm::IS_FAST_CALL;
use crate::generic_vm::vm_state::VMStateT;
use crate::handle_contract_insertion;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasItyState};
use crate::state_input::StagedVMState;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use libafl::corpus::Corpus;
use libafl::prelude::{HasCorpus, HasMetadata, Input};

use libafl::state::{HasRand, State};


use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::ops::Deref;

use crate::evm::onchain::flashloan::register_borrow_txn;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use bytes::Bytes;
use itertools::Itertools;
use revm_interpreter::Interpreter;
use revm_primitives::Bytecode;
use crate::evm::blaz::builder::{ArtifactInfoMetadata, BuildJob};
use crate::evm::corpus_initializer::ABIMap;
use crate::evm::types::{convert_u256_to_h160, EVMAddress, EVMU256};

pub static mut BLACKLIST_ADDR: Option<HashSet<EVMAddress>> = None;
pub static mut WHITELIST_ADDR: Option<HashSet<EVMAddress>> = None;

const UNBOUND_THRESHOLD: usize = 30;

pub struct OnChain<VS, I, S>
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput>,
    S: State,
    VS: VMStateT + Default,
{
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
    pub phantom: std::marker::PhantomData<(I, S, VS)>,
}

impl<VS, I, S> Debug for OnChain<VS, I, S>
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput>,
    S: State,
    VS: VMStateT + Default,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnChain")
            .field("loaded_data", &self.loaded_data)
            .field("loaded_code", &self.loaded_code)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl<VS, I, S> OnChain<VS, I, S>
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput>,
    S: State,
    VS: VMStateT + Default,
{
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
            phantom: Default::default(),
            storage_fetching,
        }
    }

    pub fn add_builder(&mut self, builder: BuildJob) {
        self.builder = Some(builder);
    }

    pub fn add_blacklist(&mut self, address: EVMAddress) {
        unsafe {
            BLACKLIST_ADDR.as_mut().unwrap().insert(address);
        }
        self.blacklist.insert(address);
    }
}

pub fn keccak_hex(data: EVMU256) -> String {
    let mut hasher = Sha3::keccak256();
    let mut output = [0u8; 32];
    let mut input: [u8; 32] = data.to_be_bytes();
    hasher.input(input.as_ref());
    hasher.result(&mut output);
    hex::encode(&output).to_string()
}

impl<VS, I, S> Middleware<VS, I, S> for OnChain<VS, I, S>
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        +HasRand
        + Debug
        + HasCaller<EVMAddress>
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + Clone
        + 'static,
    VS: VMStateT + Default + 'static,
{
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S>,
        state: &mut S,
    ) {
        let pc = interp.program_counter();
        #[cfg(feature = "force_cache")]
        macro_rules! force_cache {
            ($ty: expr, $target: expr) => {
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
            };
        }
        #[cfg(not(feature = "force_cache"))]
        macro_rules! force_cache {
            ($ty: expr, $target: expr) => {
                false
            };
        }

        match *interp.instruction_pointer {
            0x54 => {
                let address = interp.contract.address;
                let slot_idx = interp.stack.peek(0).unwrap();

                macro_rules! load_data {
                    ($func: ident, $stor: ident, $key: ident) => {{
                        if !self.$stor.contains_key(&address) {
                            let storage = self.endpoint.$func(address);
                            if storage.is_some() {
                                self.$stor.insert(address, storage.unwrap());
                            }
                        }
                        match self.$stor.get(&address) {
                            Some(v) => v.get(&$key).unwrap_or(&EVMU256::ZERO).clone(),
                            None => self.endpoint.get_contract_slot(
                                address,
                                slot_idx,
                                force_cache!(self.locs, slot_idx),
                            ),
                        }
                    }};
                    () => {};
                }
                macro_rules! slot_val {
                    () => {{
                        match self.storage_fetching {
                            StorageFetchingMode::Dump => {
                                load_data!(fetch_storage_dump, storage_dump, slot_idx)
                            }
                            StorageFetchingMode::All => {
                                // the key is in keccak256 format
                                let key = keccak_hex(slot_idx);
                                load_data!(fetch_storage_all, storage_all, key)
                            }
                            StorageFetchingMode::OneByOne => self.endpoint.get_contract_slot(
                                address,
                                slot_idx,
                                force_cache!(self.locs, slot_idx),
                            ),
                        }
                    }};
                }
                //
                // match host.data.get_mut(&address) {
                //     Some(data) => {
                //         if data.get(&slot_idx).is_none() {
                //             data.insert(slot_idx, slot_val!());
                //         }
                //     }
                //     None => {
                //         let mut data = HashMap::new();
                //         data.insert(slot_idx, slot_val!());
                //         host.data.insert(address, data);
                //     }
                // }

                host.next_slot = slot_val!();
            }

            0xf1 | 0xf2 | 0xf4 | 0xfa | 0x3b | 0x3c => {
                let caller = interp.contract.address;
                let address = match *interp.instruction_pointer {
                    0xf1 | 0xf2 | 0xf4 | 0xfa => interp.stack.peek(1).unwrap(),
                    0x3b | 0x3c => interp.stack.peek(0).unwrap(),
                    _ => {
                        unreachable!()
                    }
                };
                let address_h160 = convert_u256_to_h160(address);
                if self.loaded_abi.contains(&address_h160) {
                    return;
                }
                let force_cache = force_cache!(self.calls, address_h160);
                let contract_code = self.endpoint.get_contract_code(address_h160, force_cache);
                if contract_code.is_empty() || force_cache {
                    self.loaded_code.insert(address_h160);
                    self.loaded_abi.insert(address_h160);
                    return;
                }
                if !self.loaded_code.contains(&address_h160) && !host.code.contains_key(&address_h160) {
                    bytecode_analyzer::add_analysis_result_to_state(&contract_code, state);
                    host.set_codedata(address_h160, contract_code.clone());
                    println!("fetching code from {:?} due to call by {:?}",
                             address_h160, caller);
                }
                if unsafe { IS_FAST_CALL } || self.blacklist.contains(&address_h160) ||
                    *interp.instruction_pointer == 0x3b ||
                    *interp.instruction_pointer == 0x3c {
                    return;
                }

                // setup abi
                self.loaded_abi.insert(address_h160);
                let is_proxy_call = match *interp.instruction_pointer {
                    0xf2 | 0xf4 => true,
                    _ => false,
                };

                let mut abi = None;
                if let Some(builder) = &self.builder {
                    println!("onchain job {:?}", address_h160);
                    let build_job = builder.onchain_job(
                        self.endpoint.chain_name.clone(),
                        address_h160,
                    );

                    if let Some(job) = build_job {
                        abi = Some(job.abi.clone());
                        // replace the code with the one from builder
                        println!("replace code for {:?} with builder's", address_h160);
                        host.set_codedata(address_h160, contract_code.clone());
                        state.metadata_mut().get_mut::<ArtifactInfoMetadata>()
                            .expect("artifact info metadata").add(address_h160, job);
                    }
                }

                if abi.is_none() {
                    println!("fetching abi {:?}", address_h160);
                    abi = self.endpoint.fetch_abi(address_h160);
                }

                let mut parsed_abi = vec![];
                match abi {
                    Some(ref abi_ins) => {
                        parsed_abi = ContractLoader::parse_abi_str(abi_ins)
                    }
                    None => {
                        // 1. Extract abi from bytecode, and see do we have any function sig available in state
                        // 2. Use Heimdall to extract abi
                        // 3. Reconfirm on failures of heimdall
                        println!("Contract {:?} has no abi", address_h160);
                        let contract_code_str = hex::encode(contract_code.bytes());
                        let sigs = extract_sig_from_contract(&contract_code_str);
                        let mut unknown_sigs: usize = 0;
                        for sig in &sigs {
                            if let Some(abi) = state.metadata().get::<ABIMap>().unwrap().get(sig) {
                                parsed_abi.push(abi.clone());
                            } else {
                                unknown_sigs += 1;
                            }
                        }

                        if unknown_sigs >= sigs.len() / 30 {
                            println!("Too many unknown function signature ({:?}) for {:?}, we are going to decompile this contract using Heimdall", unknown_sigs, address_h160);
                            let abis = fetch_abi_heimdall(contract_code_str)
                                .iter()
                                .map(|abi| {
                                    if let Some(known_abi) = state.metadata().get::<ABIMap>().unwrap().get(&abi.function) {
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

                // set up host
                let mut abi_hashes_to_add = HashSet::new();
                if is_proxy_call {
                    // check caller's hash and see what is missing
                    let caller_hashes = match host.address_to_hash.get(&caller) {
                        Some(v) => v.clone(),
                        None => vec![]
                    };
                    let caller_hashes_set = caller_hashes.iter().cloned().collect::<HashSet<_>>();
                    let new_hashes = parsed_abi.iter().map(|abi| abi.function).collect::<HashSet<_>>();
                    for hash in new_hashes {
                        if !caller_hashes_set.contains(&hash) {
                            abi_hashes_to_add.insert(hash);
                            host.add_one_hashes(caller, hash);
                        }
                    }
                    println!("Propagating hashes {:?} for proxy {:?}",
                             abi_hashes_to_add
                                 .iter()
                                .map(|x| hex::encode(x))
                                 .collect::<Vec<_>>(),
                             caller
                    );

                } else {
                    abi_hashes_to_add = parsed_abi.iter().map(|abi| abi.function).collect::<HashSet<_>>();
                    host.add_hashes(
                        address_h160,
                        parsed_abi.iter().map(|abi| abi.function).collect(),
                    );
                }
                let target = if is_proxy_call {
                    caller
                } else {
                    address_h160
                };
                state.add_address(&target);

                // notify flashloan and blacklisting flashloan addresses
                #[cfg(feature = "flashloan_v2")]
                {
                    handle_contract_insertion!(state, host, target,
                        parsed_abi.iter().filter(
                            |x| abi_hashes_to_add.contains(&x.function)
                        ).cloned().collect::<Vec<ABIConfig>>()
                    );
                }
                // add abi to corpus

                unsafe {
                    match WHITELIST_ADDR.as_ref() {
                        Some(whitelist) => {
                            if !whitelist.contains(&target) {
                                return;
                            }
                        }
                        None => {}
                    }
                }

                parsed_abi
                    .iter()
                    .filter(|v| !v.is_constructor)
                    .filter( |v| abi_hashes_to_add.contains(&v.function))
                    .for_each(|abi| {
                        #[cfg(not(feature = "fuzz_static"))]
                        if abi.is_static {
                            return;
                        }

                        let mut abi_instance = get_abi_type_boxed(&abi.abi);
                        abi_instance
                            .set_func_with_name(abi.function, abi.function_name.clone());
                        register_abi_instance(target, abi_instance.clone(), state);

                        let input = EVMInput {
                            caller: state.get_rand_caller(),
                            contract: target,
                            data: Some(abi_instance),
                            sstate: StagedVMState::new_uninitialized(),
                            sstate_idx: 0,
                            txn_value: if abi.is_payable {
                                Some(EVMU256::ZERO)
                            } else {
                                None
                            },
                            step: false,

                            env: Default::default(),
                            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                            #[cfg(feature = "flashloan_v2")]
                            liquidation_percent: 0,
                            #[cfg(feature = "flashloan_v2")]
                            input_type: EVMInputTy::ABI,
                            direct_data: Default::default(),
                            randomness: vec![0],
                            repeat: 1,
                        };
                        add_corpus(host, state, &input);
                    });

            }
            _ => {}
        }
    }

    unsafe fn on_insert(&mut self, bytecode: &mut Bytecode, address: EVMAddress, host: &mut FuzzHost<VS, I, S>, state: &mut S) {

    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::OnChain
    }
}
