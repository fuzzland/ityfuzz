use crate::abi::BoxedABI;
use crate::{evm, VMState};
use bytes::Bytes;
use libafl::inputs::Input;
use libafl::Error;
use primitive_types::H160;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub trait VMInputT {
    fn to_bytes(&self) -> &Bytes;
    fn get_caller(&self) -> H160;
    fn get_contract(&self) -> H160;
    fn get_state(&self) -> &evm::VMState;
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VMInput {
    pub caller: H160,
    pub contract: H160,
    pub data: BoxedABI,
    pub state: VMState,
}

impl std::fmt::Debug for VMInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VMInput")
            .field("caller", &self.caller)
            .field("contract", &self.contract)
            // .field("data", &self.data)
            .field("state", &self.state)
            .finish()
    }
}

impl VMInputT for VMInput {
    fn to_bytes(&self) -> &Bytes {
        self.data.to_bytes()
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
