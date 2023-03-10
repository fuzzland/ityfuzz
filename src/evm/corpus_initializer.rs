use crate::evm::abi::get_abi_type_boxed;
use crate::evm::contract_utils::{ABIConfig, ContractInfo};
use crate::evm::input::EVMInput;
use crate::evm::types::{EVMFuzzState, EVMInfantStateState, EVMStagedVMState};
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::generic_vm::vm_executor::GenericVM;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::rand_utils::generate_random_address;
use crate::state::{
    FuzzState, HasCaller, HasItyState, InfantStateState, ACCOUNT_AMT, CONTRACT_AMT,
};
use crate::state_input::StagedVMState;
use bytes::Bytes;
use libafl::corpus::{Corpus, Testcase};
use libafl::inputs::Input;
use libafl::schedulers::Scheduler;
use libafl::state::{HasCorpus, HasMetadata, State};
use primitive_types::H160;
use revm::Bytecode;
use std::collections::HashSet;
use std::time::Duration;

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
        self.setup_default_callers(ACCOUNT_AMT as usize);
        self.setup_contract_callers(CONTRACT_AMT as usize);
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
                self.executor
                    .set_code(contract.deployed_address, contract.code);
                contract.deployed_address
            };

            self.state.add_caller(&deployed_address);

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
                    txn_value: Some(1),
                    step: false,
                    #[cfg(test)]
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

    pub fn setup_default_callers(&mut self, amount: usize) {
        for _ in 0..amount {
            let addr = generate_random_address();
            self.state.add_caller(&addr);
        }
    }

    pub fn setup_contract_callers(&mut self, amount: usize) {
        for _ in 0..amount {
            let address = generate_random_address();
            self.state.add_caller(&address);
            self.executor
                .host
                .set_code(address, Bytecode::new_raw(Bytes::from(vec![0xfd, 0x00])));
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
        #[cfg(feature = "fuzz_static")]
        if abi.is_static {
            return;
        }
        let mut abi_instance = get_abi_type_boxed(&abi.abi);
        abi_instance.set_func(abi.function);
        let input = EVMInput {
            caller: self.state.get_rand_caller(),
            contract: deployed_address,
            data: Some(abi_instance),
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: if abi.is_payable { Some(0) } else { None },
            step: false,
            #[cfg(test)]
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
