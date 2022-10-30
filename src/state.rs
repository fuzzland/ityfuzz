use crate::abi::get_abi_type_boxed;
use crate::contract_utils::ContractInfo;
use crate::evm::{ExecutionResult, VMState};
use crate::input::VMInput;
use crate::rand::generate_random_address;
use crate::state_input::StagedVMState;
use crate::EVMExecutor;
use bytes::Bytes;
use libafl::corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase};
use libafl::inputs::Input;
use libafl::monitors::ClientPerfMonitor;
use libafl::prelude::powersched::PowerSchedule;
use libafl::prelude::{
    current_nanos, HasMetadata, NamedSerdeAnyMap, QueueScheduler, Rand, Scheduler, SerdeAnyMap,
    StdRand,
};
use libafl::schedulers::PowerQueueScheduler;
use libafl::state::{
    HasClientPerfMonitor, HasCorpus, HasExecutions, HasMaxSize, HasNamedMetadata, HasRand,
    HasSolutions, State,
};
use libafl::Error;
use nix::libc::stat;
use primitive_types::H160;
use revm::Bytecode;
use serde::{Deserialize, Serialize};
use std::cmp::max;
use std::path::Path;
use std::time::Duration;

const ACCOUNT_AMT: u8 = 10;

// Note: Probably a better design is to use StdState with a custom corpus?
// What are other metadata we need?
// shou: may need intermediate info for future adding concolic execution
pub trait HasItyState {
    fn get_infant_state<SC>(&mut self, scheduler: &SC) -> Option<(usize, StagedVMState)>
    where
        SC: Scheduler<StagedVMState, InfantStateState>;
    fn add_infant_state<SC>(&mut self, state: &StagedVMState, scheduler: &SC)
    where
        SC: Scheduler<StagedVMState, InfantStateState>;
    fn get_rand_caller(&mut self) -> H160;
}

pub trait HasInfantStateState {
    fn get_infant_state_state(&mut self) -> &mut InfantStateState;
}

pub trait HasExecutionResult {
    fn get_execution_result(&self) -> &ExecutionResult;
    fn get_execution_result_mut(&mut self) -> &mut ExecutionResult;
    fn set_execution_result(&mut self, res: ExecutionResult);
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FuzzState {
    infant_states_state: InfantStateState,
    txn_corpus: InMemoryCorpus<VMInput>,
    solutions: OnDiskCorpus<VMInput>,
    executions: usize,
    metadata: SerdeAnyMap,
    named_metadata: NamedSerdeAnyMap,
    execution_result: ExecutionResult,
    default_callers: Vec<H160>,
    pub rand_generator: StdRand,
    pub max_size: usize,
}

impl FuzzState {
    pub fn new() -> Self {
        Self {
            infant_states_state: InfantStateState::new(),
            txn_corpus: InMemoryCorpus::new(),
            solutions: OnDiskCorpus::new(Path::new("solutions")).unwrap(),
            executions: 0,
            metadata: Default::default(),
            named_metadata: Default::default(),
            execution_result: ExecutionResult::empty_result(),
            default_callers: vec![],
            rand_generator: StdRand::with_seed(current_nanos()),
            max_size: 1500,
        }
    }

    pub fn initialize<I, S>(
        &mut self,
        contracts: Vec<ContractInfo>,
        executor: &mut EVMExecutor<I, S>,
        scheduler: &dyn Scheduler<I, FuzzState>,
        infant_scheduler: &dyn Scheduler<I, FuzzState>,
    ) where
        I: Input,
    {
        self.setup_default_callers(ACCOUNT_AMT as usize);
        self.initialize_corpus(contracts, executor, scheduler, infant_scheduler);
    }

    pub fn initialize_corpus<I, S>(
        &mut self,
        contracts: Vec<ContractInfo>,
        executor: &mut EVMExecutor<I, S>,
        scheduler: &dyn Scheduler<I, FuzzState>,
        infant_scheduler: &dyn Scheduler<I, FuzzState>,
    ) where
        I: Input,
    {
        for contract in contracts {
            let deployed_address = executor.deploy(
                Bytecode::new_raw(Bytes::from(contract.code)),
                Bytes::from(contract.constructor_args),
            );
            for abi in contract.abi {
                let mut abi_instance = get_abi_type_boxed(&abi.abi);
                abi_instance.set_func(abi.function);
                let mut input = VMInput {
                    caller: self.get_rand_caller(),
                    contract: deployed_address,
                    data: abi_instance,
                    sstate: StagedVMState::new_uninitialized(),
                };
                let mut tc = Testcase::new(input);
                tc.set_exec_time(Duration::from_secs(0));
                let idx = self.txn_corpus.add(tc).expect("failed to add");
                scheduler
                    .on_add(self, idx)
                    .expect("failed to call scheduler on_add");
            }
        }
        let mut tc = Testcase::new(StagedVMState::new(executor.host.data.clone(), 0));
        tc.set_exec_time(Duration::from_secs(0));
        let idx = self
            .infant_states_state
            .corpus_mut()
            .add(tc)
            .expect("failed to add");
        infant_scheduler
            .on_add(self, idx)
            .expect("failed to call infant scheduler on_add");
    }

    pub fn setup_default_callers(&mut self, amount: usize) {
        for _ in 0..amount {
            self.default_callers.push(generate_random_address());
        }
    }
}

// shou: To use power schedule, we need to make it as a state lol, i'll submit a pr to libafl
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InfantStateState {
    pub infant_state: InMemoryCorpus<StagedVMState>,
    metadata: SerdeAnyMap,
}

impl InfantStateState {
    pub fn new() -> Self {
        Self {
            infant_state: InMemoryCorpus::new(),
            metadata: SerdeAnyMap::new(),
        }
    }
}

impl State for InfantStateState {}

impl HasCorpus<StagedVMState> for InfantStateState {
    type Corpus = InMemoryCorpus<StagedVMState>;

    fn corpus(&self) -> &InMemoryCorpus<StagedVMState> {
        &self.infant_state
    }

    fn corpus_mut(&mut self) -> &mut InMemoryCorpus<StagedVMState> {
        &mut self.infant_state
    }
}

impl HasMetadata for InfantStateState {
    fn metadata(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl HasItyState for FuzzState {
    fn get_infant_state<SC>(&mut self, scheduler: &SC) -> Option<(usize, StagedVMState)>
    where
        SC: Scheduler<StagedVMState, InfantStateState>,
    {
        let idx = scheduler
            .next(&mut self.infant_states_state)
            .expect("no more infant state");
        let mut state = self
            .infant_states_state
            .corpus()
            .get(idx)
            .unwrap()
            .borrow_mut();

        Some((idx, state.input().clone().unwrap()))
    }

    fn add_infant_state<SC>(&mut self, state: &StagedVMState, scheduler: &SC)
    where
        SC: Scheduler<StagedVMState, InfantStateState>,
    {
        let idx = self
            .infant_states_state
            .corpus_mut()
            .add(Testcase::new(state.clone()))
            .expect("Failed to add new infant state");
        scheduler
            .on_add(&mut self.infant_states_state, idx)
            .expect("Failed to setup scheduler");
    }

    fn get_rand_caller(&mut self) -> H160 {
        self.default_callers[self.rand_generator.below(self.default_callers.len() as u64) as usize]
    }
}

impl HasInfantStateState for FuzzState {
    fn get_infant_state_state(&mut self) -> &mut InfantStateState {
        &mut self.infant_states_state
    }
}

impl HasMaxSize for FuzzState {
    fn max_size(&self) -> usize {
        self.max_size
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
    }
}

impl HasRand for FuzzState {
    type Rand = StdRand;

    fn rand(&self) -> &Self::Rand {
        &self.rand_generator
    }

    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand_generator
    }
}

impl HasExecutions for FuzzState {
    fn executions(&self) -> &usize {
        &self.executions
    }

    fn executions_mut(&mut self) -> &mut usize {
        &mut self.executions
    }
}

impl HasMetadata for FuzzState {
    fn metadata(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl HasCorpus<VMInput> for FuzzState {
    type Corpus = InMemoryCorpus<VMInput>;

    fn corpus(&self) -> &InMemoryCorpus<VMInput> {
        &self.txn_corpus
    }

    fn corpus_mut(&mut self) -> &mut InMemoryCorpus<VMInput> {
        &mut self.txn_corpus
    }
}

impl HasSolutions<VMInput> for FuzzState {
    type Solutions = OnDiskCorpus<VMInput>;

    fn solutions(&self) -> &Self::Solutions {
        &self.solutions
    }

    fn solutions_mut(&mut self) -> &mut Self::Solutions {
        &mut self.solutions
    }
}

impl HasClientPerfMonitor for FuzzState {
    fn introspection_monitor(&self) -> &ClientPerfMonitor {
        todo!()
    }

    fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor {
        todo!()
    }
}

impl HasExecutionResult for FuzzState {
    fn get_execution_result(&self) -> &ExecutionResult {
        &self.execution_result
    }

    fn set_execution_result(&mut self, res: ExecutionResult) {
        self.execution_result = res
    }

    fn get_execution_result_mut(&mut self) -> &mut ExecutionResult {
        &mut self.execution_result
    }
}

impl HasNamedMetadata for FuzzState {
    fn named_metadata(&self) -> &NamedSerdeAnyMap {
        &self.named_metadata
    }

    fn named_metadata_mut(&mut self) -> &mut NamedSerdeAnyMap {
        &mut self.named_metadata
    }
}

impl State for FuzzState {}
