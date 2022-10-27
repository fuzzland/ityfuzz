use crate::evm::VMState;
use crate::input::VMInput;
use crate::state_input::ItyVMState;
use libafl::corpus::InMemoryCorpus;
use libafl::inputs::Input;
use libafl::prelude::{current_nanos, StdRand};
use libafl::state::{HasMaxSize, HasRand, State};
use libafl::Error;
use serde::{Deserialize, Serialize};
use std::cmp::max;
use std::path::Path;

// Note: Probably a better design is to use StdState with a custom corpus?
// What are other metadata we need?
// shou: may need intermediate info for future adding concolic execution
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FuzzState {
    infant_states: InMemoryCorpus<ItyVMState>,
    txn_corpus: InMemoryCorpus<VMInput>,
    pub rand_generator: StdRand,
    pub max_size: usize,
}

impl FuzzState {
    pub fn new() -> Self {
        Self {
            infant_states: InMemoryCorpus::new(),
            txn_corpus: InMemoryCorpus::new(),
            rand_generator: StdRand::with_seed(current_nanos()),
            max_size: 0,
        }
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

impl State for FuzzState {}
