use crate::evm::{ExecutionResult, VMState};
use crate::input::VMInput;
use crate::state_input::ItyVMState;
use libafl::corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase};
use libafl::inputs::Input;
use libafl::monitors::ClientPerfMonitor;
use libafl::prelude::powersched::PowerSchedule;
use libafl::prelude::{
    current_nanos, HasMetadata, QueueScheduler, Scheduler, SerdeAnyMap, StdRand,
};
use libafl::schedulers::PowerQueueScheduler;
use libafl::state::{
    HasClientPerfMonitor, HasCorpus, HasExecutions, HasMaxSize, HasRand, HasSolutions, State,
};
use libafl::Error;
use nix::libc::stat;
use serde::{Deserialize, Serialize};
use std::cmp::max;
use std::path::Path;

// Note: Probably a better design is to use StdState with a custom corpus?
// What are other metadata we need?
// shou: may need intermediate info for future adding concolic execution
pub trait FuzzStateT {
    fn get_infant_state<SC>(&mut self, scheduler: &SC) -> Option<(usize, ItyVMState)>
    where
        SC: Scheduler<ItyVMState, InfantStateState>;
    fn add_infant_state<SC>(&mut self, scheduler: &SC)
    where
        SC: Scheduler<ItyVMState, InfantStateState>;
}

pub trait HasExecutionResult {
    fn get_execution_result(self) -> ExecutionResult;
    fn set_execution_result(&mut self, res: ExecutionResult);
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FuzzState {
    infant_states_state: InfantStateState,
    txn_corpus: InMemoryCorpus<VMInput>,
    solutions: OnDiskCorpus<VMInput>,
    executions: usize,
    metadata: SerdeAnyMap,
    execution_result: ExecutionResult,
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
            execution_result: ExecutionResult::empty_result(),
            rand_generator: StdRand::with_seed(current_nanos()),
            max_size: 1500,
        }
    }
}

// shou: To use power schedule, we need to make it as a state lol, i'll submit a pr to libafl
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InfantStateState {
    pub infant_state: InMemoryCorpus<ItyVMState>,
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

impl HasCorpus<ItyVMState> for InfantStateState {
    type Corpus = InMemoryCorpus<ItyVMState>;

    fn corpus(&self) -> &InMemoryCorpus<ItyVMState> {
        &self.infant_state
    }

    fn corpus_mut(&mut self) -> &mut InMemoryCorpus<ItyVMState> {
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

impl FuzzStateT for FuzzState {
    fn get_infant_state<SC>(&mut self, scheduler: &SC) -> Option<(usize, ItyVMState)>
    where
        SC: Scheduler<ItyVMState, InfantStateState>,
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

    fn add_infant_state<SC>(&mut self, scheduler: &SC)
    where
        SC: Scheduler<ItyVMState, InfantStateState>,
    {
        let idx = self
            .infant_states_state
            .corpus_mut()
            .add(Testcase::new(ItyVMState::new()))
            .expect("Failed to add new infant state");
        scheduler
            .on_add(&mut self.infant_states_state, idx)
            .expect("Failed to setup scheduler");
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
    fn get_execution_result(self) -> ExecutionResult {
        self.execution_result
    }

    fn set_execution_result(&mut self, res: ExecutionResult) {
        self.execution_result = res
    }
}

impl State for FuzzState {}
