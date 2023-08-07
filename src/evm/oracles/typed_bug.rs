use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracle::dummy_precondition;
use crate::evm::producers::pair::PairProducer;
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256};
use crate::evm::vm::EVMState;
use crate::oracle::{Oracle, OracleCtx, Producer};
use crate::state::HasExecutionResult;
use bytes::Bytes;
use primitive_types::{H160, H256, U256};
use revm_primitives::Bytecode;
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::rc::Rc;
use itertools::Itertools;
use crate::evm::oracles::TYPED_BUG_BUG_IDX;
use crate::fuzzer::ORACLE_OUTPUT;

pub struct TypedBugOracle;

impl TypedBugOracle {
    pub fn new() -> Self {
        Self {}
    }
}



impl Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState, ConciseEVMInput>
    for TypedBugOracle
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
        if ctx.post_state.typed_bug.len() > 0 {
            unsafe {
                ORACLE_OUTPUT += format!(
                    "[typed_bug] {:?} hit at contract {:?}\n",
                    ctx.post_state.typed_bug,
                    ctx.input.contract
                ).as_str();
            }
            ctx.post_state.typed_bug.iter().map(|bug_id| {
                let mut hasher = DefaultHasher::new();
                bug_id.hash(&mut hasher);
                (hasher.finish() as u64) << 8 + TYPED_BUG_BUG_IDX
            }).collect_vec()
        } else {
            vec![]
        }
    }
}
