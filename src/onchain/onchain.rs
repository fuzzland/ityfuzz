use crate::abi::get_abi_type_boxed;
use crate::contract_utils::ContractLoader;
use crate::evm::{FuzzHost, IntermediateExecutionResult};
use crate::input::{VMInput, VMInputT};
use crate::middleware::MiddlewareOp::{AddCorpus, UpdateCode, UpdateSlot};
use crate::middleware::{CanHandleDeferredActions, Middleware, MiddlewareOp, MiddlewareType};
use crate::onchain::endpoints::OnChainConfig;
use crate::state::{FuzzState, HasItyState};
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
use std::time::Duration;

const UNBOUND_THRESHOLD: usize = 5;

pub struct OnChain<I, S>
where
    I: Input + VMInputT,
    S: State,
{
    pub loaded_data: HashSet<(H160, U256)>,
    pub loaded_code: HashSet<H160>,
    pub calls: HashMap<(H160, usize), usize>,
    pub endpoint: OnChainConfig,
    pub scheduler: Option<Box<dyn Scheduler<I, S>>>,
    pub blacklist: HashSet<H160>,
}

impl<I, S> Debug for OnChain<I, S>
where
    I: Input + VMInputT,
    S: State,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnChain")
            .field("loaded_data", &self.loaded_data)
            .field("loaded_code", &self.loaded_code)
            .field("calls", &self.calls)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl<I, S> OnChain<I, S>
where
    I: Input + VMInputT,
    S: State,
{
    pub fn new<SC>(endpoint: OnChainConfig, scheduler: SC) -> Self
    where
        SC: Scheduler<I, S> + 'static,
    {
        Self {
            loaded_data: Default::default(),
            loaded_code: Default::default(),
            calls: Default::default(),
            endpoint,
            scheduler: Some(Box::new(scheduler)),
            blacklist: Default::default(),
        }
    }

    pub fn add_blacklist(&mut self, address: H160) {
        self.blacklist.insert(address);
    }
}

impl<I, S> Middleware for OnChain<I, S>
where
    I: Input + VMInputT + 'static,
    S: State + std::fmt::Debug + 'static,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter) -> Vec<MiddlewareOp> {
        match *interp.instruction_pointer {
            0x54 => {
                let slot_idx = interp.stack.peek(0).unwrap();
                let address = interp.contract.address;
                vec![UpdateSlot(
                    MiddlewareType::OnChain,
                    address,
                    slot_idx,
                    self.endpoint.get_contract_slot(address, slot_idx),
                )]
            }

            0xf1 | 0xf2 | 0xf4 | 0xfa => {
                let pc = interp.program_counter();
                let calls_data = self.calls.get_mut(&(interp.contract.address, pc));
                match calls_data {
                    None => {
                        self.calls.insert((interp.contract.address, pc), 1);
                    }
                    Some(v) => {
                        if *v > UNBOUND_THRESHOLD {
                            return vec![];
                        }
                        *v += 1;
                    }
                }
                let address = interp.stack.peek(1).unwrap();
                let address_h160 = convert_u256_to_h160(address);
                let abi = if !self.loaded_code.contains(&address_h160) {
                    self.endpoint.fetch_abi(address_h160)
                } else {
                    None
                };
                self.loaded_code.insert(address_h160);
                let code_update = UpdateCode(
                    MiddlewareType::OnChain,
                    address_h160,
                    self.endpoint.get_contract_code(address_h160),
                );
                match abi {
                    Some(abi_ins) => {
                        // AddCorpus(MiddlewareType::OnChain, )
                        if self.blacklist.contains(&address_h160) {
                            vec![code_update]
                        } else {
                            vec![
                                code_update,
                                AddCorpus(MiddlewareType::OnChain, abi_ins, address_h160),
                            ]
                        }
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

impl<I, S> CanHandleDeferredActions<S> for OnChain<I, S>
where
    I: Input + VMInputT + 'static,
    S: State + HasCorpus<I> + HasItyState + HasMetadata + 'static,
{
    fn handle_deferred_actions(
        &self,
        op: &MiddlewareOp,
        state: &mut S,
        result: &mut IntermediateExecutionResult,
    ) {
        match op {
            MiddlewareOp::AddCorpus(.., input, address) => {
                ContractLoader::parse_abi_str(input)
                    .iter()
                    .filter(|v| !v.is_constructor)
                    .for_each(|abi| {
                        let mut abi_instance = get_abi_type_boxed(&abi.abi);
                        abi_instance.set_func(abi.function);
                        let input = VMInput {
                            caller: state.get_rand_caller(),
                            contract: address.clone(),
                            data: Some(abi_instance),
                            sstate: StagedVMState::new_uninitialized(),
                            sstate_idx: 0,
                            txn_value: if abi.is_payable { Some(0) } else { None },
                        };
                        let mut tc = Testcase::new(input) as Testcase<I>;
                        tc.set_exec_time(Duration::from_secs(0));
                        let idx = state.corpus_mut().add(tc).expect("failed to add");
                        self.scheduler
                            .as_ref()
                            .unwrap()
                            .on_add(state, idx)
                            .expect("failed to call scheduler on_add");
                    });
            }
            _ => {
                panic!("MiddlewareOp::execute_with_state called with invalid op");
            }
        }
    }
}
