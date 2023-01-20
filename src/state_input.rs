use crate::VMState;
use libafl::inputs::Input;
use libafl::Error;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ItyVMState(pub VMState);

impl ItyVMState {
    pub fn new() -> Self {
        Self(VMState::new())
    }
}

impl Input for ItyVMState {
    fn generate_name(&self, idx: usize) -> String {
        format!("input-{}.state", idx)
    }
}
