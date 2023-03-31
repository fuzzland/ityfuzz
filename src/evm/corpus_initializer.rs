use std::borrow::BorrowMut;
use std::cell::RefCell;
use crate::evm::abi::get_abi_type_boxed;
use crate::evm::contract_utils::{ABIConfig, ContractInfo};
use crate::evm::input::{EVMInput};
use crate::evm::types::{EVMFuzzState, EVMInfantStateState, EVMStagedVMState};
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::generic_vm::vm_executor::GenericVM;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::rand_utils::{fixed_address, generate_random_address};
use crate::state::{FuzzState, HasCaller, HasItyState, InfantStateState};
use crate::state_input::StagedVMState;
use bytes::Bytes;
use libafl::corpus::{Corpus, Testcase};
use libafl::inputs::Input;
use libafl::schedulers::Scheduler;
use libafl::state::{HasCorpus, HasMetadata, State};
use primitive_types::{H160, U256};
use revm::Bytecode;
use std::collections::HashSet;
use std::ops::Deref;
use std::rc::Rc;
use std::time::Duration;
use crate::evm::bytecode_analyzer;
use crate::evm::mutator::AccessPattern;

pub struct EVMCorpusInitializer<'a> {
    executor: &'a mut EVMExecutor<EVMInput, EVMFuzzState, EVMState>,
    scheduler: &'a dyn Scheduler<EVMInput, EVMFuzzState>,
    infant_scheduler: &'a dyn Scheduler<EVMStagedVMState, EVMInfantStateState>,
    state: &'a mut EVMFuzzState,
}

impl<'a> EVMCorpusInitializer<'a> {
    pub fn new(
        executor: &'a mut EVMExecutor<EVMInput, EVMFuzzState, EVMState>,
        scheduler: &'a dyn Scheduler<EVMInput, EVMFuzzState>,
        infant_scheduler: &'a dyn Scheduler<EVMStagedVMState, EVMInfantStateState>,
        state: &'a mut EVMFuzzState,
    ) -> Self {
        Self {
            executor,
            scheduler,
            infant_scheduler,
            state,
        }
    }

    pub fn initialize(&mut self, contracts: Vec<ContractInfo>) {
        self.setup_default_callers();
        self.setup_contract_callers();
        self.initialize_corpus(contracts);
    }

    pub fn initialize_corpus(&mut self, contracts: Vec<ContractInfo>) {
        for contract in contracts {
            println!("Deploying contract: {}", contract.name);
            let deployed_address = if !contract.is_code_deployed {
                match self.executor.deploy(
                    Bytecode::new_raw(Bytes::from(contract.code)),
                    Some(Bytes::from(contract.constructor_args)),
                    contract.deployed_address,
                    self.state
                ) {
                    Some(addr) => addr,
                    None => {
                        println!("Failed to deploy contract: {}", contract.name);
                        // we could also panic here
                        continue;
                    }
                }
            } else {
                // directly set bytecode
                let contract_code = Bytecode::new_raw(Bytes::from(contract.code));
                // bytecode_analyzer::add_analysis_result_to_state(&contract_code, self.state);
                self.executor.host
                    .set_code(contract.deployed_address, contract_code);
                contract.deployed_address
            };

            #[cfg(feature = "flashloan_v2")]
            match self.executor.host.flashloan_middleware {
                Some(ref middleware) => {
                    let mut mid = middleware.deref().borrow_mut();

                    let blacklists = mid.on_contract_insertion(
                        &deployed_address,
                        &contract.abi,
                        &mut self.state,
                    );

                    for addr in blacklists {
                        mid.onchain_middlware.deref().borrow_mut().blacklist.insert(addr);
                    }
                }
                None => {}
            }

            self.state.add_address(&deployed_address);

            for abi in contract.abi {
                self.add_abi(&abi, self.scheduler, deployed_address);
            }
            // add transfer txn
            {
                let input = EVMInput {
                    caller: self.state.get_rand_caller(),
                    contract: deployed_address,
                    data: None,
                    sstate: StagedVMState::new_uninitialized(),
                    sstate_idx: 0,
                    txn_value: Some(U256::one()),
                    step: false,
                    env: Default::default(),
                    access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                    #[cfg(any(test, feature = "debug"))]
                    direct_data: Default::default(),
                };
                let mut tc = Testcase::new(input);
                tc.set_exec_time(Duration::from_secs(0));
                let idx = self.state.add_tx_to_corpus(tc).expect("failed to add");
                self.scheduler
                    .on_add(self.state, idx)
                    .expect("failed to call scheduler on_add");
            }
        }
        let mut tc = Testcase::new(StagedVMState::new_with_state(
            self.executor.host.data.clone(),
        ));
        tc.set_exec_time(Duration::from_secs(0));
        let idx = self
            .state
            .infant_states_state
            .corpus_mut()
            .add(tc)
            .expect("failed to add");
        self.infant_scheduler
            .on_add(&mut self.state.infant_states_state, idx)
            .expect("failed to call infant scheduler on_add");
    }

    pub fn setup_default_callers(&mut self) {
        let mut default_callers = HashSet::from([
            fixed_address("8EF508Aca04B32Ff3ba5003177cb18BfA6Cd79dd"),
            fixed_address("35c9dfd76bf02107ff4f7128Bd69716612d31dDb"),
            fixed_address("5E6B78f0748ACd4Fb4868dF6eCcfE41398aE09cb")
        ]);

        for caller in default_callers {
            self.state.add_caller(&caller);
        }
    }

    pub fn setup_contract_callers(&mut self) {
        let mut contract_callers = HashSet::from([
            fixed_address("e1A425f1AC34A8a441566f93c82dD730639c8510"),
            fixed_address("68Dd4F5AC792eAaa5e36f4f4e0474E0625dc9024"),
            fixed_address("aF97EE5eef1B02E12B650B8127D8E8a6cD722bD2"),
        ]);
        for caller in contract_callers {
            self.state.add_caller(&caller);
            self.executor
                .host
                .set_code(caller, Bytecode::new_raw(Bytes::from(vec![0xfd, 0x00])));
        }
    }

    fn add_abi(
        &mut self,
        abi: &ABIConfig,
        scheduler: &dyn Scheduler<EVMInput, EVMFuzzState>,
        deployed_address: H160,
    ) {
        if abi.is_constructor {
            return;
        }

        match self
            .state
            .hash_to_address
            .get_mut(abi.function.clone().as_slice())
        {
            Some(addrs) => {
                addrs.insert(deployed_address);
            }
            None => {
                self.state
                    .hash_to_address
                    .insert(abi.function.clone(), HashSet::from([deployed_address]));
            }
        }
        #[cfg(not(feature = "fuzz_static"))]
        if abi.is_static {
            return;
        }
        let mut abi_instance = get_abi_type_boxed(&abi.abi);
        abi_instance.set_func_with_name(abi.function, abi.function_name.clone());
        let input = EVMInput {
            caller: self.state.get_rand_caller(),
            contract: deployed_address,
            data: Some(abi_instance),
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: if abi.is_payable { Some(U256::zero()) } else { None },
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            #[cfg(any(test, feature = "debug"))]
            direct_data: Default::default(),
        };
        let mut tc = Testcase::new(input.clone());
        tc.set_exec_time(Duration::from_secs(0));
        let idx = self.state.add_tx_to_corpus(tc).expect("failed to add");
        scheduler
            .on_add(self.state, idx)
            .expect("failed to call scheduler on_add");
    }
}
