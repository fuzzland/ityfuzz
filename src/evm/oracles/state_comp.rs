use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracle::{dummy_precondition, EVMBugResult};
use crate::evm::producers::pair::PairProducer;
use crate::evm::types::{bytes_to_u64, EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256};
use crate::evm::vm::EVMState;
use crate::oracle::{Oracle, OracleCtx, Producer};
use crate::state::HasExecutionResult;
use bytes::Bytes;
use revm_primitives::Bytecode;
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::rc::Rc;
use crate::evm::host::STATE_CHANGE;
use crate::evm::oracles::{STATE_COMP_BUG_IDX};
use crate::fuzzer::ORACLE_OUTPUT;
use crate::generic_vm::vm_state::VMStateT;

pub enum StateCompMatching {
    Exact,
    DesiredContain,
    StateContain,
}

impl StateCompMatching {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "Exact" => Some(StateCompMatching::Exact),
            "DesiredContain" => Some(StateCompMatching::DesiredContain),
            "StateContain" => Some(StateCompMatching::StateContain),
            _ => None,
        }
    }
}

pub struct StateCompOracle {
    pub desired_state: EVMState,
    pub matching_style: StateCompMatching,
}

impl StateCompOracle {
    pub fn new(desired_state: EVMState, matching_style: String) -> Self {
        Self {
            desired_state,
            matching_style: StateCompMatching::from_str(matching_style.as_str()).expect("invalid state comp matching style"),
        }
    }
}

impl Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState, ConciseEVMInput>
for StateCompOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(
        &self,
        ctx: &mut OracleCtx<
            EVMState,
            EVMAddress,
            Bytecode,
            Bytes,
            EVMAddress,
            EVMU256,
            Vec<u8>,
            EVMInput,
            EVMFuzzState,
            ConciseEVMInput
        >,
        stage: u64,
    ) -> Vec<u64> {

        let comp = |state1: &EVMState, state2: &EVMState| -> bool {
            match self.matching_style {
                StateCompMatching::Exact => state1.eq(state2),
                StateCompMatching::DesiredContain => state1.is_subset_of(state2),
                StateCompMatching::StateContain => state2.is_subset_of(state1),
            }
        };

        unsafe {
            if STATE_CHANGE && comp(&ctx.post_state, &self.desired_state) {
                EVMBugResult::new_simple(
                    "state_comp".to_string(),
                    STATE_COMP_BUG_IDX,
                    "Found equivalent state".to_string(),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                ).push_to_output();
                vec![STATE_COMP_BUG_IDX]
            } else {
                vec![]
            }
        }

    }
}
