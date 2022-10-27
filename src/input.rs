use crate::abi::BoxedABI;
use crate::{evm, VMState};
use bytes::Bytes;
use libafl::inputs::Input;
use libafl::prelude::HasLen;
use libafl::Error;
use primitive_types::H160;
use serde::{Deserialize, Serialize};
use std::path::Path;

// ST: Should VMInputT be the generic type for both inputs?
pub trait VMInputT: Input {
    fn to_bytes(&self) -> Bytes;
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

impl HasLen for VMInput {
    fn len(&self) -> usize {
        self.data.get_bytes().len()
    }
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
    fn to_bytes(&self) -> Bytes {
        self.data.get_bytes()
    }

    fn get_caller(&self) -> H160 {
        self.caller.clone()
    }

    fn get_contract(&self) -> H160 {
        self.contract.clone()
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

// Input we saved in corpus, not real inputs to VM
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum CorpusInput {
    VMInput(VMInput),
    VMState(VMState),
}

impl Input for CorpusInput {
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
