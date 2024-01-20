use std::str::FromStr;

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        host::STATE_CHANGE,
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::STATE_COMP_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::vm_state::VMStateT,
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

pub enum StateCompMatching {
    Exact,
    DesiredContain,
    StateContain,
}

impl FromStr for StateCompMatching {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Exact" => Ok(StateCompMatching::Exact),
            "DesiredContain" => Ok(StateCompMatching::DesiredContain),
            "StateContain" => Ok(StateCompMatching::StateContain),
            _ => Err(()),
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
            matching_style: StateCompMatching::from_str(matching_style.as_str())
                .expect("invalid state comp matching style"),
        }
    }
}

impl
    Oracle<
        EVMState,
        EVMAddress,
        Bytecode,
        Bytes,
        EVMAddress,
        EVMU256,
        Vec<u8>,
        EVMInput,
        EVMFuzzState,
        ConciseEVMInput,
        EVMQueueExecutor,
    > for StateCompOracle
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
            ConciseEVMInput,
            EVMQueueExecutor,
        >,
        _stage: u64,
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
                )
                .push_to_output();
                vec![STATE_COMP_BUG_IDX]
            } else {
                vec![]
            }
        }
    }
}
