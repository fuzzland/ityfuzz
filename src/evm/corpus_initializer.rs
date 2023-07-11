/// Utilities to initialize the corpus
/// Add all potential calls with default args to the corpus
use crate::evm::abi::get_abi_type_boxed;
use crate::evm::bytecode_analyzer;
use crate::evm::contract_utils::{ABIConfig, ContractInfo};
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputTy};
use crate::evm::mutator::AccessPattern;

use crate::evm::onchain::onchain::BLACKLIST_ADDR;
use crate::evm::types::{fixed_address, EVMAddress, EVMFuzzState, EVMInfantStateState, EVMStagedVMState, EVMU256, ProjectSourceMapTy};
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::generic_vm::vm_executor::GenericVM;

use crate::state::HasCaller;
use crate::state_input::StagedVMState;
use bytes::Bytes;
use libafl::corpus::{Corpus, Testcase};

use libafl::schedulers::Scheduler;
use libafl::state::HasCorpus;
use revm_primitives::Bytecode;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ops::Deref;

use crate::evm::onchain::flashloan::register_borrow_txn;
use crate::evm::presets::presets::Preset;
use crate::evm::srcmap::parser::{decode_instructions, SourceMapLocation};
use hex;
use itertools::Itertools;
use std::rc::Rc;
use std::time::Duration;

pub struct EVMCorpusInitializer<'a> {
    executor: &'a mut EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>,
    scheduler: &'a dyn Scheduler<EVMInput, EVMFuzzState>,
    infant_scheduler: &'a dyn Scheduler<EVMStagedVMState, EVMInfantStateState>,
    state: &'a mut EVMFuzzState,
    #[cfg(feature = "use_presets")]
    presets: Vec<&'a dyn Preset<EVMInput, EVMFuzzState, EVMState>>,
}

pub struct EVMInitializationArtifacts {
    pub address_to_sourcemap: ProjectSourceMapTy,
}

#[macro_export]
macro_rules! handle_contract_insertion {
    ($state: expr, $host: expr, $deployed_address: expr, $abi: expr) => {
        let (is_erc20, is_pair) = match $host.flashloan_middleware {
            Some(ref middleware) => {
                let mut mid = middleware.deref().borrow_mut();
                mid.on_contract_insertion(&$deployed_address, &$abi, $state)
            }
            None => (false, false),
        };
        if is_erc20 {
            register_borrow_txn(&$host, $state, $deployed_address);
        }
        if is_pair {
            let mut mid = $host
                .flashloan_middleware
                .as_ref()
                .unwrap()
                .deref()
                .borrow_mut();
            mid.on_pair_insertion(&$host, $state, $deployed_address);
        }
    };
}

macro_rules! wrap_input {
    ($input: expr) => {{
        let mut tc = Testcase::new($input);
        tc.set_exec_time(Duration::from_secs(0));
        tc
    }};
}

macro_rules! add_input_to_corpus {
    ($state: expr, $scheduler: expr, $input: expr) => {
        let idx = $state
            .add_tx_to_corpus(wrap_input!($input))
            .expect("failed to add");
        $scheduler
            .on_add($state, idx)
            .expect("failed to call scheduler on_add");
    };
}

impl<'a> EVMCorpusInitializer<'a> {
    pub fn new(
        executor: &'a mut EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>,
        scheduler: &'a dyn Scheduler<EVMInput, EVMFuzzState>,
        infant_scheduler: &'a dyn Scheduler<EVMStagedVMState, EVMInfantStateState>,
        state: &'a mut EVMFuzzState,
    ) -> Self {
        Self {
            executor,
            scheduler,
            infant_scheduler,
            state,
            #[cfg(feature = "use_presets")]
            presets: vec![],
        }
    }

    #[cfg(feature = "use_presets")]
    pub fn register_preset(&mut self, preset: &'a dyn Preset<EVMInput, EVMFuzzState, EVMState>) {
        self.presets.push(preset);
    }

    pub fn initialize(&mut self, contracts: Vec<ContractInfo>) -> EVMInitializationArtifacts{
        self.setup_default_callers();
        self.setup_contract_callers();
        self.initialize_corpus(contracts)
    }

    pub fn initialize_corpus(&mut self, contracts: Vec<ContractInfo>) -> EVMInitializationArtifacts {
        let mut artifacts = EVMInitializationArtifacts {
            address_to_sourcemap: HashMap::new(),
        };
        for contract in contracts {
            println!("Deploying contract: {}", contract.name);
            let deployed_address = if !contract.is_code_deployed {
                match self.executor.deploy(
                    Bytecode::new_raw(Bytes::from(contract.code)),
                    Some(Bytes::from(contract.constructor_args)),
                    contract.deployed_address,
                    self.state,
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
                bytecode_analyzer::add_analysis_result_to_state(&contract_code, self.state);
                self.executor
                    .host
                    .set_code(contract.deployed_address, contract_code, self.state);
                contract.deployed_address
            };
            artifacts.address_to_sourcemap.insert(deployed_address, contract.source_map);

            #[cfg(feature = "flashloan_v2")]
            {
                handle_contract_insertion!(
                    self.state,
                    self.executor.host,
                    deployed_address,
                    contract.abi
                );
            }

            self.state.add_address(&deployed_address);

            if unsafe {
                BLACKLIST_ADDR.is_some()
                    && BLACKLIST_ADDR.as_ref().unwrap().contains(&deployed_address)
            } {
                continue;
            }

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
                    txn_value: Some(EVMU256::from(1)),
                    step: false,
                    env: Default::default(),
                    access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                    direct_data: Default::default(),
                    #[cfg(feature = "flashloan_v2")]
                    liquidation_percent: 0,
                    #[cfg(feature = "flashloan_v2")]
                    input_type: EVMInputTy::ABI,
                    randomness: vec![0],
                    repeat: 1,
                };
                add_input_to_corpus!(self.state, self.scheduler, input);
            }
        }
        let mut tc = Testcase::new(StagedVMState::new_with_state(
            self.executor.host.evmstate.clone(),
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
        artifacts
    }

    pub fn setup_default_callers(&mut self) {
        let default_callers = HashSet::from([
            fixed_address("8EF508Aca04B32Ff3ba5003177cb18BfA6Cd79dd"),
            fixed_address("35c9dfd76bf02107ff4f7128Bd69716612d31dDb"),
            // fixed_address("5E6B78f0748ACd4Fb4868dF6eCcfE41398aE09cb"),
        ]);

        for caller in default_callers {
            self.state.add_caller(&caller);
        }
    }

    pub fn setup_contract_callers(&mut self) {
        let contract_callers = HashSet::from([
            fixed_address("e1A425f1AC34A8a441566f93c82dD730639c8510"),
            fixed_address("68Dd4F5AC792eAaa5e36f4f4e0474E0625dc9024"),
            // fixed_address("aF97EE5eef1B02E12B650B8127D8E8a6cD722bD2"),
        ]);
        for caller in contract_callers {
            self.state.add_caller(&caller);
            self.executor.host.set_code(
                caller,
                Bytecode::new_raw(Bytes::from(vec![0xfd, 0x00])),
                self.state,
            );
        }
    }

    fn add_abi(
        &mut self,
        abi: &ABIConfig,
        scheduler: &dyn Scheduler<EVMInput, EVMFuzzState>,
        deployed_address: EVMAddress,
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
        add_input_to_corpus!(self.state, scheduler, input.clone());

        #[cfg(feature = "use_presets")]
        {
            let presets = self.presets.clone();
            for p in presets {
                let mut presets = p.presets(abi.function, &input, self.executor);
                presets.iter().for_each(|preset| {
                    add_input_to_corpus!(self.state, scheduler, preset.clone());
                });
            }
        }
    }
}
