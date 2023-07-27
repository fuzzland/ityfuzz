use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracle::dummy_precondition;
use crate::evm::oracles::erc20::ORACLE_OUTPUT;
use crate::evm::producers::pair::PairProducer;
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256};
use crate::evm::vm::EVMState;
use crate::oracle::{Oracle, OracleCtx, Producer};
use crate::state::HasExecutionResult;
use bytes::Bytes;
use revm_primitives::Bytecode;
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Deref;
use std::rc::Rc;
use crate::evm::oracles::SELFDESTRUCT_BUG_IDX;

pub struct SelfdestructOracle;

impl SelfdestructOracle {
    pub fn new() -> Self {
        Self {}
    }

}

impl Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState, ConciseEVMInput>
for SelfdestructOracle
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
        let is_hit = ctx.post_state.selfdestruct_hit;
        if is_hit {
            unsafe {
                ORACLE_OUTPUT = format!(
                    "[selfdestruct] selfdestruct() hit at contract {:?}",
                    ctx.input.contract
                )
            }
            vec![SELFDESTRUCT_BUG_IDX]
        }
        else {
            vec![]
        }
    }
}
