use crate::evm::contract_utils::ContractInfo;
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::generic_vm::vm_executor::GenericVM;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::rand_utils::generate_random_address;
use crate::state::{FuzzState, HasItyState, InfantStateState, ACCOUNT_AMT, CONTRACT_AMT, HasCaller};
use crate::state_input::StagedVMState;
use bytes::Bytes;
use libafl::corpus::{Corpus, Testcase};
use libafl::inputs::Input;
use libafl::schedulers::Scheduler;
use libafl::state::{HasCorpus, HasMetadata, State};
use revm::Bytecode;
use std::time::Duration;
use primitive_types::H160;
use crate::evm::input::EVMInput;
use crate::evm::types::EVMFuzzState;

pub struct EVMCorpusInitializer {
    executor: &'static mut EVMExecutor<EVMInput, EVMFuzzState, EVMState>,
    scheduler: &'static dyn Scheduler<EVMInput, EVMFuzzState>,
    infant_scheduler: &'static dyn Scheduler<StagedVMState<EVMState>, InfantStateState<EVMState>>,
    state: &'static mut EVMFuzzState,
}

impl EVMCorpusInitializer {
    pub fn new(
        executor: &'static mut EVMExecutor<EVMInput, EVMFuzzState, EVMState>,
        scheduler: &'static dyn Scheduler<EVMInput, EVMFuzzState>,
        infant_scheduler: &'static dyn Scheduler<
            StagedVMState<EVMState>,
            InfantStateState<EVMState>,
        >,
        state: &'static mut EVMFuzzState,
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
                    Bytes::from(contract.constructor_args),
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

            for abi in contract.abi {
                // self.state.add_abi(&abi, self.scheduler, deployed_address);
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
                };
                let mut tc = Testcase::new(input);
                tc.set_exec_time(Duration::from_secs(0));
                let idx = self.state.add_tx_to_corpus(tc).expect("failed to add");
                // self.scheduler
                //     .on_add(self.state, idx)
                //     .expect("failed to call scheduler on_add");
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
            self.state.default_callers.push(generate_random_address());
        }
    }

    pub fn setup_contract_callers(&mut self, amount: usize) {
        for _ in 0..amount {
            let address = generate_random_address();
            self.state.default_callers.push(address);
            self.executor
                .host
                .set_code(address, Bytecode::new_raw(Bytes::from(vec![0xfd, 0x00])));
        }
    }


}
