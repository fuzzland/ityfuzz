use std::path::Path;
use bytes::Bytes;
use libafl::Error;
use libafl::inputs::Input;
use primitive_types::H160;
use crate::{evm, VMState};
use serde::{Deserialize, Serialize};
use crate::abi::ABI;

pub trait VMInputT {
    fn to_bytes(&self) -> &Bytes;
    fn get_caller(&self) -> H160;
    fn get_contract(&self) -> H160;
    fn get_state(&self) -> &evm::VMState;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VMInput {
    pub caller: H160,
    pub contract: H160,
    pub data: dyn ABI,
    pub state: VMState,
}

impl VMInputT for VMInput {
    fn to_bytes(&self) -> &Bytes {
        &self.data
    }

    fn get_caller(&self) -> H160 {
        self.caller
    }

    fn get_contract(&self) -> H160 {
        self.contract
    }

    fn get_state(&self) -> &VMState {
        &self.state
    }
}

impl Input for VMInput {
    fn to_file<P>(&self, path: P) -> Result<(), Error> where P: AsRef<Path> {
        todo!()
    }

    fn from_file<P>(path: P) -> Result<Self, Error> where P: AsRef<Path> {
        todo!()
    }

    fn generate_name(&self, idx: usize) -> String {
        todo!()
    }

    fn wrapped_as_testcase(&mut self) {
        // todo!()
    }
}
