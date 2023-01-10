mod evm;
mod rand;
mod types;

use std::{str::FromStr, time::Instant};
use std::fmt::{Debug, Formatter};
use std::ops::Deref;
use std::path::Path;

use bytes::Bytes;
use libafl::{Error, inputs};
use primitive_types::H160;
use revm::{db::CacheDB, Bytecode, TransactTo};

use libafl::executors::{Executor, ExitKind};
use libafl::inputs::Input;
use serde::{Deserialize, Serialize};


use crate::evm::{EVMExecutor, State};


#[derive(Debug, Clone)]
pub struct FuzzExecutor {
    pub evm_executor: EVMExecutor,
}

pub trait VMInput {
    fn to_bytes(&self) -> &Bytes;
    fn get_caller(&self) -> H160;
    fn get_contract(&self) -> H160;
    fn get_state(&self) -> &evm::State;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VMInputImpl {
    pub caller: H160,
    pub contract: H160,
    pub data: Bytes,
    pub state: State,
}

impl VMInput for VMInputImpl {
    fn to_bytes(&self) -> &Bytes {
        &self.data
    }

    fn get_caller(&self) -> H160 {
        self.caller
    }

    fn get_contract(&self) -> H160 {
        self.contract
    }

    fn get_state(&self) -> &State {
        &self.state
    }
}

impl Input for VMInputImpl {
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
        todo!()
    }
}

impl<EM, I, S, Z> Executor<EM, I, S, Z> for FuzzExecutor
where I: VMInput + Input {
    fn run_target(&mut self, fuzzer: &mut Z, state: &mut S, mgr: &mut EM, input: &I) -> Result<ExitKind, Error> {
        self.evm_executor.execute(
            input.get_contract(),
            input.get_caller(),
            input.get_state(),
            input.to_bytes().clone()
        );
        // todo: run oracle here
        Ok(ExitKind::Ok)
    }
}


#[cfg(test)]
mod tests {
    use revm::AccountInfo;
    use super::*;

    #[test]
    fn it_works() {

    }
}
