use crate::VMState;
use libafl::inputs::Input;

use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StagedVMState {
    pub state: VMState,
    pub stage: u64,
    pub initialized: bool,
}

impl StagedVMState {
    pub fn new(state: VMState, stage: u64) -> Self {
        Self {
            state,
            stage,
            initialized: true,
        }
    }

    pub fn new_with_state(state: VMState) -> Self {
        Self {
            state,
            stage: 0,
            initialized: true,
        }
    }

    pub fn new_uninitialized() -> Self {
        Self {
            state: VMState::new(),
            stage: 0,
            initialized: false,
        }
    }

    pub fn with_stage(&self, stage: u64) -> Self {
        Self {
            state: self.state.clone(),
            stage,
            initialized: true,
        }
    }

    pub fn with_state(&self, state: VMState) -> Self {
        Self {
            state,
            stage: self.stage,
            initialized: self.initialized,
        }
    }

    pub fn update_stage(&mut self, stage: u64) {
        self.stage = stage;
        self.initialized = true;
    }
}

impl Input for StagedVMState {
    fn generate_name(&self, idx: usize) -> String {
        format!("input-{}.state", idx)
    }
}
