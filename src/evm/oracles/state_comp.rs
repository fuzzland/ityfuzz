use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracle::dummy_precondition;
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

pub struct StateCompOracle {
    pub desired_state: EVMState,
}

impl StateCompOracle {
    pub fn new(desired_state: EVMState) -> Self {
        Self { desired_state }
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
        unsafe {
            if STATE_CHANGE && ctx.post_state.eq(&self.desired_state) {
                ORACLE_OUTPUT += "[state_comp] found equivalent state\n";
                vec![STATE_COMP_BUG_IDX]
            } else {
                vec![]
            }
        }

    }
}
