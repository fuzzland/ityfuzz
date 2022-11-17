use bytes::Bytes;
use crate::VMState;
use libafl::inputs::Input;
use primitive_types::H160;

use serde::{Deserialize, Serialize};
use crate::abi::BoxedABI;
use crate::input::{VMInput, VMInputT};


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BasicTxn {
    pub caller: H160,
    pub contract: H160,
    pub data: Option<BoxedABI>,
    pub txn_value: usize,
}

pub fn build_basic_txn<I>(v: &I) -> BasicTxn
where I: VMInputT {
    BasicTxn {
        caller: v.get_caller(),
        contract: v.get_contract(),
        data: v.get_abi_cloned(),
        txn_value: v.get_txn_value(),
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxnTrace {
    pub transactions: Vec<BasicTxn>,
    pub from_idx: usize,
}

impl TxnTrace {
    fn new() -> Self {
        Self {
            transactions: Vec::new(),
            from_idx: 0,
        }
    }
}

impl Default for TxnTrace {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StagedVMState {
    pub state: VMState,
    pub stage: u64,
    pub initialized: bool,
    pub trace: TxnTrace,
}

impl StagedVMState {
    pub fn new(state: VMState, stage: u64) -> Self {
        Self {
            state,
            stage,
            initialized: true,
            trace: TxnTrace::new(),
        }
    }

    pub fn new_with_state(state: VMState) -> Self {
        Self {
            state,
            stage: 0,
            initialized: true,
            trace: TxnTrace::new(),
        }
    }

    pub fn new_uninitialized() -> Self {
        Self {
            state: VMState::new(),
            stage: 0,
            initialized: false,
            trace: TxnTrace::new(),
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
