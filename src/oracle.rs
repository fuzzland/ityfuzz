use crate::evm::ExecutionResult;
use crate::input::{VMInput, VMInputT};
use crate::state::FuzzState;
use crate::{EVMExecutor, VMState};
use bytes::Bytes;
use hex;
use libafl::prelude::{tuple_list, SerdeAnyMap};
use primitive_types::H160;

pub struct OracleCtx<'a, I, S>
where
    I: VMInputT,
{
    pub pre_state: &'a VMState,
    pub post_state: &'a VMState,
    pub metadata: SerdeAnyMap,
    pub executor: &'a mut EVMExecutor<I, S>,
    pub input: &'a I,
}

impl<'a, I, S> OracleCtx<'a, I, S>
where
    I: VMInputT,
{
    pub fn new(
        pre_state: &'a VMState,
        post_state: &'a VMState,
        executor: &'a mut EVMExecutor<I, S>,
        input: &'a I,
    ) -> Self {
        Self {
            pre_state,
            post_state,
            metadata: SerdeAnyMap::new(),
            executor,
            input,
        }
    }

    fn call_pre(&mut self, contract_address: H160, address: H160, data: Bytes) -> ExecutionResult {
        self.executor.execute(
            contract_address,
            address,
            &mut self.pre_state,
            data,
            &mut tuple_list!(),
        )
    }

    fn call_post(&mut self, contract_address: H160, address: H160, data: Bytes) -> ExecutionResult {
        self.executor.execute(
            contract_address,
            address,
            &mut self.post_state,
            data,
            &mut tuple_list!(),
        )
    }
}

pub trait Oracle<I, S>
where
    I: VMInputT,
{
    fn transition(&self, ctx: &mut OracleCtx<I, S>, stage: u64) -> u64;
    fn oracle(&self, ctx: &mut OracleCtx<I, S>, stage: u64) -> bool;
}

pub struct NoOracle {}

impl Oracle<VMInput, FuzzState> for NoOracle {
    fn transition(&self, _ctx: &mut OracleCtx<VMInput, FuzzState>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, _ctx: &mut OracleCtx<VMInput, FuzzState>, _stage: u64) -> bool {
        false
    }
}

pub struct IERC20Oracle {
    pub address: H160,
    pub precondition: fn(ctx: &mut OracleCtx<VMInput, FuzzState>, stage: u64) -> u64,

    balance_of: Vec<u8>,
}

impl IERC20Oracle {
    pub fn new(
        address: H160,
        precondition: fn(ctx: &mut OracleCtx<VMInput, FuzzState>, stage: u64) -> u64,
    ) -> Self {
        Self {
            address,
            precondition,
            balance_of: hex::decode("70a08231").unwrap(),
        }
    }
}

impl Oracle<VMInput, FuzzState> for IERC20Oracle {
    fn transition(&self, _ctx: &mut OracleCtx<VMInput, FuzzState>, _stage: u64) -> u64 {
        (self.precondition)(_ctx, _stage)
    }

    fn oracle(&self, _ctx: &mut OracleCtx<VMInput, FuzzState>, _stage: u64) -> bool {
        let balance_of_txn =
            Bytes::from([self.balance_of.clone(), _ctx.input.caller.0.to_vec()].concat());

        // get caller balance
        let pre_balance = _ctx
            .call_pre(self.address, _ctx.input.caller, balance_of_txn.clone())
            .output;

        let post_balance = _ctx
            .call_post(self.address, _ctx.input.caller, balance_of_txn)
            .output;
        // has balance increased?
        post_balance > pre_balance
    }
}
