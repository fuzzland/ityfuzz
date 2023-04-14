use crate::evm::abi::get_abi_type_boxed;
use crate::evm::bytecode_analyzer;
use crate::evm::config::StorageFetchingMode;
use crate::evm::contract_utils::ContractLoader;
use crate::evm::input::{EVMInput, EVMInputT};
use crate::evm::middleware::MiddlewareOp::{AddCorpus, UpdateCode, UpdateSlot};
use crate::evm::middleware::{add_corpus, Middleware, MiddlewareOp, MiddlewareType};
use crate::evm::mutator::AccessPattern;
use crate::evm::onchain::abi_decompiler::fetch_abi_heimdall;
use crate::evm::onchain::endpoints::OnChainConfig;
use crate::evm::vm::{FuzzHost, IntermediateExecutionResult};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{FuzzState, HasCaller, HasItyState};
use crate::state_input::StagedVMState;
use crate::types::convert_u256_to_h160;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use libafl::corpus::{Corpus, Testcase};
use libafl::prelude::{HasCorpus, HasMetadata, Input, MutationResult};
use libafl::schedulers::Scheduler;
use libafl::state::State;
use nix::libc::stat;
use primitive_types::{H160, H256, U256};
use revm::Interpreter;
use serde::{Deserialize, Serialize, Serializer};
use std::any::Any;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::ops::Deref;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const UNBOUND_THRESHOLD: usize = 30;

pub struct OnChain<VS, I, S>
where
    I: Input + VMInputT<VS, H160, H160>,
    S: State,
    VS: VMStateT + Default,
{
    pub loaded_data: HashSet<(H160, U256)>,
    pub loaded_code: HashSet<H160>,
    pub calls: HashMap<(H160, usize), HashSet<H160>>,
    pub locs: HashMap<(H160, usize), HashSet<U256>>,
    pub endpoint: OnChainConfig,
    pub blacklist: HashSet<H160>,
    pub storage_fetching: StorageFetchingMode,
    pub storage_all: HashMap<H160, Arc<HashMap<String, U256>>>,
    pub storage_dump: HashMap<H160, Arc<HashMap<U256, U256>>>,
    pub phantom: std::marker::PhantomData<(I, S, VS)>,
}

impl<VS, I, S> Debug for OnChain<VS, I, S>
where
    I: Input + VMInputT<VS, H160, H160>,
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
    I: Input + VMInputT<VS, H160, H160>,
    S: State,
    VS: VMStateT + Default,
{
    pub fn new(endpoint: OnChainConfig, storage_fetching: StorageFetchingMode) -> Self {
        Self {
            loaded_data: Default::default(),
            loaded_code: Default::default(),
            calls: Default::default(),
            locs: Default::default(),
            endpoint,
            blacklist: HashSet::from([
                H160::from_str("0x3cb4ca3c9dc0e02d252098eebb3871ac7a43c54d").unwrap(),
                H160::from_str("0x6aed013308d847cb87502d86e7d9720b17b4c1f2").unwrap(),
                H160::from_str("0x5a58505a96d1dbf8df91cb21b54419fc36e93fde").unwrap(),
                H160::from_str("0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640").unwrap(),
                H160::from_str("0xa40cac1b04d7491bdfb42ccac97dff25e0efb09e").unwrap(),
                // uniswap router
                H160::from_str("0xca143ce32fe78f1f7019d7d551a6402fc5350c73").unwrap(),
                // pancake router
                H160::from_str("0x6CD71A07E72C514f5d511651F6808c6395353968").unwrap(),
            ]),
            storage_all: Default::default(),
            storage_dump: Default::default(),
            phantom: Default::default(),
            storage_fetching,
        }
    }

    pub fn add_blacklist(&mut self, address: H160) {
        self.blacklist.insert(address);
    }
}

pub fn keccak_hex(data: U256) -> String {
    let mut hasher = Sha3::keccak256();
    let mut output = [0u8; 32];
    let mut input = [0u8; 32];
    data.to_big_endian(&mut input);
    hasher.input(input.as_ref());
    hasher.result(&mut output);
    hex::encode(&output).to_string()
}

impl<VS, I, S> Middleware<VS, I, S> for OnChain<VS, I, S>
where
    I: Input + VMInputT<VS, H160, H160> + EVMInputT + 'static,
    S: State
        + Debug
        + HasCaller<H160>
        + HasCorpus<I>
        + HasItyState<H160, H160, VS>
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
                            Some(v) => v.get(&$key).unwrap_or(&U256::zero()).clone(),
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
                let address = match *interp.instruction_pointer {
                    0xf1 | 0xf2 | 0xf4 | 0xfa => interp.stack.peek(1).unwrap(),
                    0x3b | 0x3c => interp.stack.peek(0).unwrap(),
                    _ => {
                        unreachable!()
                    }
                };
                let address_h160 = convert_u256_to_h160(address);
                if self.blacklist.contains(&address_h160) || host.code.contains_key(&address_h160) {
                    return;
                }
                let force_cache = force_cache!(self.calls, address_h160);

                let contract_code = self.endpoint.get_contract_code(address_h160, force_cache);

                if !self.loaded_code.contains(&address_h160)
                    && !force_cache
                    && !contract_code.is_empty()
                {
                    let abi = self.endpoint.fetch_abi(address_h160);
                    self.loaded_code.insert(address_h160);

                    let parsed_abi = match abi {
                        Some(ref abi_ins) => ContractLoader::parse_abi_str(abi_ins),
                        None => fetch_abi_heimdall(hex::encode(contract_code.bytes())),
                    };

                    // set up host
                    host.add_hashes(
                        address_h160,
                        parsed_abi.iter().map(|abi| abi.function).collect(),
                    );
                    state.add_address(&address_h160);

                    // notify flashloan and blacklisting flashloan addresses
                    #[cfg(feature = "flashloan_v2")]
                    match host.flashloan_middleware {
                        Some(ref middleware) => {
                            let blacklists = middleware.deref().borrow_mut().on_contract_insertion(
                                &address_h160,
                                &parsed_abi,
                                state,
                            );
                            for addr in blacklists {
                                self.add_blacklist(addr);
                            }
                        }
                        None => {}
                    }

                    // add abi to corpus
                    parsed_abi
                        .iter()
                        .filter(|v| !v.is_constructor)
                        .for_each(|abi| {
                            #[cfg(not(feature = "fuzz_static"))]
                            if abi.is_static {
                                return;
                            }

                            let mut abi_instance = get_abi_type_boxed(&abi.abi);
                            abi_instance
                                .set_func_with_name(abi.function, abi.function_name.clone());
                            let input = EVMInput {
                                caller: state.get_rand_caller(),
                                contract: address_h160.clone(),
                                data: Some(abi_instance),
                                sstate: StagedVMState::new_uninitialized(),
                                sstate_idx: 0,
                                txn_value: if abi.is_payable {
                                    Some(U256::zero())
                                } else {
                                    None
                                },
                                step: false,

                                env: Default::default(),
                                access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                                #[cfg(feature = "flashloan_v2")]
                                liquidation_percent: 0,
                                #[cfg(any(test, feature = "debug"))]
                                direct_data: Default::default(),
                            };
                            add_corpus(host, state, &input);
                        });
                }

                bytecode_analyzer::add_analysis_result_to_state(&contract_code, state);
                host.set_code(address_h160, contract_code);
            }
            _ => {}
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::OnChain
    }
}
