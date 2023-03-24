use crate::evm::abi::get_abi_type_boxed;
use crate::evm::contract_utils::ContractLoader;
use crate::evm::input::EVMInput;
use crate::evm::middleware::MiddlewareOp::{AddCorpus, UpdateCode, UpdateSlot};
use crate::evm::middleware::{CanHandleDeferredActions, Middleware, MiddlewareOp, MiddlewareType};
use crate::evm::onchain::endpoints::OnChainConfig;
use crate::evm::vm::{FuzzHost, IntermediateExecutionResult};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{FuzzState, HasCaller, HasItyState};
use crate::state_input::StagedVMState;
use crate::types::convert_u256_to_h160;
use libafl::corpus::{Corpus, Testcase};
use libafl::prelude::{HasCorpus, HasMetadata, Input, MutationResult};
use libafl::schedulers::Scheduler;
use libafl::state::State;
use primitive_types::{H160, H256, U256};
use revm::Interpreter;
use serde::{Deserialize, Serialize, Serializer};
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::Duration;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use crate::evm::config::StorageFetchingMode;

const UNBOUND_THRESHOLD: usize = 5;

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
    pub scheduler: Option<Box<dyn Scheduler<I, S>>>,
    pub blacklist: HashSet<H160>,
    pub storage_fetching: StorageFetchingMode,
    pub storage_all: HashMap<H160, Arc<HashMap<String, U256>>>,
    pub storage_dump: HashMap<H160, Arc<HashMap<U256, U256>>>,
    pub phantom: std::marker::PhantomData<VS>,
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
    pub fn new<SC>(endpoint: OnChainConfig, scheduler: SC, storage_fetching: StorageFetchingMode) -> Self
    where
        SC: Scheduler<I, S> + 'static,
    {
        Self {
            loaded_data: Default::default(),
            loaded_code: Default::default(),
            calls: Default::default(),
            locs: Default::default(),
            endpoint,
            scheduler: Some(Box::new(scheduler)),
            blacklist: Default::default(),
            storage_all: Default::default(),
            storage_dump: Default::default(),
            phantom: Default::default(),
            storage_fetching
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

impl<VS, I, S> Middleware for OnChain<VS, I, S>
where
    I: Input + VMInputT<VS, H160, H160> + 'static,
    S: State + std::fmt::Debug + 'static,
    VS: VMStateT + Default + 'static,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter) -> Vec<MiddlewareOp> {
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
                let slot_idx = interp.stack.peek(0).unwrap();
                let address = interp.contract.address;

                macro_rules! load_data {
                    ($func: ident, $stor: ident, $key: ident) => {
                        {
                            if !self.$stor.contains_key(&address) {
                                let storage = self.endpoint.$func(address)
                                    .unwrap_or(Arc::new(HashMap::new()));
                                self.$stor.insert(address, storage);
                            }
                            self.$stor.get(&address).unwrap().get(&$key).unwrap_or(&U256::zero()).clone()
                        }
                    };
                    () => {};
                }

                let slot_val = {
                    match self.storage_fetching {
                        StorageFetchingMode::Dump => {
                            load_data!(fetch_storage_dump, storage_dump, slot_idx)
                        }
                        StorageFetchingMode::All => {
                            // the key is in keccak256 format
                            let key = keccak_hex(slot_idx);
                            load_data!(fetch_storage_all, storage_all, key)
                        }
                        StorageFetchingMode::OneByOne => {
                            self.endpoint.get_contract_slot(
                                address,
                                slot_idx,
                                force_cache!(self.locs, slot_idx),
                            )
                        }
                    }
                };
                vec![
                    UpdateSlot(
                        MiddlewareType::OnChain,
                        address,
                        slot_idx,
                        slot_val,
                    )
                ]
            }

            0xf1 | 0xf2 | 0xf4 | 0xfa => {
                let address = interp.stack.peek(1).unwrap();
                let address_h160 = convert_u256_to_h160(address);
                if self.blacklist.contains(&address_h160) {
                    return vec![];
                }
                let force_cache = force_cache!(self.calls, address_h160);

                let contract_code = self.endpoint.get_contract_code(address_h160, force_cache);
                let has_code = !contract_code.is_empty();

                let code_update = UpdateCode(MiddlewareType::OnChain, address_h160, contract_code);

                let abi = if !self.loaded_code.contains(&address_h160) && !force_cache && has_code {
                    self.endpoint.fetch_abi(address_h160)
                } else {
                    None
                };

                self.loaded_code.insert(address_h160);

                match abi {
                    Some(abi_ins) => {
                        // AddCorpus(MiddlewareType::OnChain, )
                        vec![
                            code_update,
                            AddCorpus(MiddlewareType::OnChain, abi_ins, address_h160),
                        ]
                    }
                    None => {
                        vec![code_update]
                    }
                }
            }
            _ => {
                vec![]
            }
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::OnChain
    }

    fn as_any(&mut self) -> &mut (dyn Any + 'static) {
        self
    }
}

impl<VS, I, S> CanHandleDeferredActions<VS, S> for OnChain<VS, I, S>
where
    I: Input + VMInputT<VS, H160, H160> + 'static,
    S: State + HasCorpus<I> + HasItyState<H160, H160, VS> + HasMetadata + HasCaller<H160> + 'static,
    VS: VMStateT + Default,
{
    fn handle_deferred_actions(
        &mut self,
        op: &MiddlewareOp,
        state: &mut S,
        result: &mut IntermediateExecutionResult,
    ) {
        match op {
            MiddlewareOp::AddCorpus(.., input, address) => {
                state.add_address(address);
                ContractLoader::parse_abi_str(input)
                    .iter()
                    .filter(|v| !v.is_constructor)
                    .for_each(|abi| {
                        #[cfg(not(feature = "fuzz_static"))]
                        if abi.is_static {
                            return;
                        }

                        let mut abi_instance = get_abi_type_boxed(&abi.abi);
                        abi_instance.set_func_with_name(abi.function, abi.function_name.clone());
                        let input = EVMInput {
                            caller: state.get_rand_caller(),
                            contract: address.clone(),
                            data: Some(abi_instance),
                            sstate: StagedVMState::new_uninitialized(),
                            sstate_idx: 0,
                            txn_value: if abi.is_payable { Some(0) } else { None },
                            step: false,

                            #[cfg(test)]
                            direct_data: Default::default(),
                        };
                        let mut tc =
                            Testcase::new(input.as_any().downcast_ref::<I>().unwrap().clone())
                                as Testcase<I>;
                        tc.set_exec_time(Duration::from_secs(0));
                        let idx = state.corpus_mut().add(tc).expect("failed to add");
                        self.scheduler
                            .as_ref()
                            .unwrap()
                            .on_add(state, idx)
                            .expect("failed to call scheduler on_add");
                    });
            }
            MiddlewareOp::AddBlacklist(.., address) => {
                self.blacklist.insert(address.clone());
            }
            _ => {
                panic!("MiddlewareOp::execute_with_state called with invalid op");
            }
        }
    }
}
