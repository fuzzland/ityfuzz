pub mod pair;

use std::{fmt::Debug, fs::File};

use libafl::schedulers::Scheduler;
use serde::{Deserialize, Deserializer};

use super::types::EVMFuzzState;
use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput, EVMInputT},
        types::EVMAddress,
        vm::EVMExecutor,
    },
    generic_vm::vm_state::VMStateT,
    input::VMInputT,
};

pub trait Preset<I, VS, SC>
where
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    fn presets(
        &self,
        function_sig: [u8; 4],
        input: &EVMInput,
        evm_executor: &EVMExecutor<VS, ConciseEVMInput, SC>,
    ) -> Vec<EVMInput>;
}

#[derive(Debug, PartialEq, Clone, serde::Serialize)]
pub struct FunctionSig {
    pub value: [u8; 4],
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct ExploitTemplate {
    pub exploit_name: String,
    pub function_sigs: Vec<FunctionSig>,
    pub calls: Vec<FunctionSig>,
}

impl ExploitTemplate {
    pub fn from_filename(filename: String) -> Vec<Self> {
        let file = File::open(filename).unwrap();
        let exploit_templates: Vec<Self> = serde_json::from_reader(file).unwrap();
        exploit_templates
    }
}

impl<'de> Deserialize<'de> for FunctionSig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let mut function_sig = [0u8; 4];
        function_sig.copy_from_slice(&hex::decode(&s[2..]).unwrap()[..4]);
        Ok(FunctionSig { value: function_sig })
    }
}
