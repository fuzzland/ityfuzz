/// Dummy oracle for testing
use crate::evm::input::{EVMInput, EVMInputT};
use std::collections::{HashMap, HashSet};

use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256};

use crate::evm::vm::EVMState;

use crate::oracle::{Oracle, OracleCtx};
use crate::state::HasExecutionResult;

use bytes::Bytes;
use libafl::impl_serdeany;

use crate::evm::uniswap::{liquidate_all_token, TokenContext};
use revm_primitives::Bytecode;
use serde::{Deserialize, Serialize};

pub struct NoOracle {}

impl Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState>
    for NoOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        vec![]
    }
}

pub fn dummy_precondition(_ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
    99
}

