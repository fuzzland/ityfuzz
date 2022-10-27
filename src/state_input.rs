use crate::VMState;
use libafl::inputs::Input;
use libafl::Error;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ItyVMState(VMState);

impl ItyVMState {
    pub fn new() -> Self {
        Self(VMState::new())
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
