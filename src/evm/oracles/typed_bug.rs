use crate::evm::input::EVMInput;
use crate::evm::oracle::dummy_precondition;
use crate::evm::oracles::erc20::ORACLE_OUTPUT;
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
use std::collections::HashMap;
use std::ops::Deref;
use std::rc::Rc;

pub struct TypedBugOracle;

impl TypedBugOracle {
    pub fn new() -> Self {
        Self {}
    }

    fn HToStrHex(&self, list: H256) -> String {
        // get list bytes
        let tmp = list.to_fixed_bytes();
        let mut index = 0;
        for i in tmp.iter() {
            if *i != 0 {
                break;
            }
            index += 1;
        }
        format!("0x{}", hex::encode(tmp[index..].to_vec()))
    }

}



impl Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState>
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
        >,
        stage: u64,
    ) -> bool {
        let is_hit = ctx.post_state.typed_bug.is_zero() == false;
        if is_hit {
            unsafe {
                let typed_bug_hash = self.HToStrHex(ctx.post_state.typed_bug);
                ORACLE_OUTPUT = format!(
                    "[typed_bug] typed_bug({}) hit at contract {:?}",
                    typed_bug_hash,
                    ctx.input.contract
                )
            }
        }
        return is_hit;
    }
}
