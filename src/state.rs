use std::cmp::max;
use crate::evm::VMState;
use crate::input::VMInput;
use libafl::corpus::InMemoryCorpus;
use libafl::inputs::Input;
use libafl::Error;
use serde::{Deserialize, Serialize};
use std::path::Path;
use libafl::prelude::{current_nanos, StdRand};
use libafl::state::{HasMaxSize, HasRand};

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ItyVMState{
    pub state: VMState,
    pub rand_generator: StdRand,
    pub max_size: usize,
}

impl ItyVMState {
    pub fn new() -> Self {
        Self {
            state: VMState::new(),
            rand_generator: StdRand::with_seed(current_nanos()),
            max_size: 1500,
        }
    }
}

impl Input for ItyVMState {
    fn to_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        todo!()
    }

    fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        todo!()
    }

    fn generate_name(&self, idx: usize) -> String {
        todo!()
    }

    fn wrapped_as_testcase(&mut self) {
        // todo!()
    }
}

impl HasRand for ItyVMState {
    type Rand = StdRand;

    fn rand(&self) -> &Self::Rand {
        &self.rand_generator
    }

    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand_generator
    }
}

impl HasMaxSize for ItyVMState {
    fn max_size(&self) -> usize {
        self.max_size
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
    }
}

// Note: Probably a better design is to use StdState with a custom corpus?
// What are other metadata we need?
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FuzzState {
    infant_states: InMemoryCorpus<ItyVMState>,
    txn_corpus: InMemoryCorpus<VMInput>,
}
