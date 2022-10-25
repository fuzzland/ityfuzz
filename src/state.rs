use crate::evm::VMState;
use crate::input::VMInput;
use libafl::corpus::InMemoryCorpus;
use libafl::inputs::Input;
use libafl::Error;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ItyVMState(VMState);

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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FuzzState {
    infant_states: InMemoryCorpus<ItyVMState>,
    txn_corpus: InMemoryCorpus<VMInput>,
}
