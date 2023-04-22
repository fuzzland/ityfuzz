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

pub struct IERC20Oracle {
    pub address: H160,
    pub precondition: fn(ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64,

    balance_of: Vec<u8>,
}

pub fn dummy_precondition(_ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
    99
}

impl IERC20Oracle {
    pub fn new(
        address: H160,
        precondition: fn(ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64,
    ) -> Self {
        Self {
            address,
            precondition,
            balance_of: hex::decode("70a08231").unwrap(),
        }
    }

    pub fn new_no_condition(address: H160) -> Self {
        Self {
            address,
            precondition: dummy_precondition,
            balance_of: hex::decode("70a08231").unwrap(),
        }
    }
}

impl Oracle<EVMState, H160, Bytecode, Bytes, H160, U256, Vec<u8>, EVMInput, EVMFuzzState>
    for IERC20Oracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        (self.precondition)(_ctx, _stage)
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> bool {
        if _stage == 99 {
            let _balance_of_txn =
                Bytes::from([self.balance_of.clone(), ctx.input.caller.0.to_vec()].concat());

            // get caller balance
            // let pre_balance = _ctx
            //     .call_pre(self.address, _ctx.input.caller, balance_of_txn.clone())
            //     .output;
            //
            // let post_balance = _ctx
            //     .call_post(self.address, _ctx.input.caller, balance_of_txn)
            //     .output;
            // has balance increased?
            // post_balance > pre_balance
            false
        } else {
            false
        }
    }
}

