/// Dummy oracle for testing
use crate::evm::input::{EVMInput, EVMInputT};
use std::collections::HashMap;

use crate::evm::types::{EVMFuzzState, EVMOracleCtx};

use crate::evm::vm::EVMState;

use crate::oracle::{Oracle, OracleCtx};
use crate::state::HasExecutionResult;

use bytes::Bytes;

use crate::evm::uniswap::{liquidate_all_token, TokenContext};
use primitive_types::{H160, U256, U512};
use revm::Bytecode;

pub struct NoOracle {}

impl Oracle<EVMState, H160, Bytecode, Bytes, H160, U256, Vec<u8>, EVMInput, EVMFuzzState>
    for NoOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> bool {
        false
    }
}

pub fn dummy_precondition(_ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
    99
}
