use crate::evm::ExecutionResult;
use crate::input::{VMInput, VMInputT};
use crate::onchain::flashloan::FlashloanData;
use crate::state::{FuzzState, HasItyState};
use crate::{EVMExecutor, VMState};
use bytes::Bytes;
use hex;
use libafl::prelude::{tuple_list, HasCorpus, HasMetadata, SerdeAnyMap};
use libafl::state::State;
use primitive_types::H160;

pub struct OracleCtx<'a, I, S: 'static>
where
    I: VMInputT,
{
    pub fuzz_state: &'a S,
    pub pre_state: &'a VMState,
    pub post_state: &'a VMState,
    pub metadata: SerdeAnyMap,
    pub executor: &'a mut EVMExecutor<I, S>,
    pub input: &'a I,
}

impl<'a, I, S> OracleCtx<'a, I, S>
where
    I: VMInputT + 'static,
    S: State + HasCorpus<I> + HasMetadata + HasItyState,
{
    pub fn new(
        fuzz_state: &'a S,
        pre_state: &'a VMState,
        post_state: &'a VMState,
        executor: &'a mut EVMExecutor<I, S>,
        input: &'a I,
    ) -> Self {
        Self {
            fuzz_state,
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
            0,
            false,
            &mut tuple_list!(),
            None,
        )
    }

    fn call_post(&mut self, contract_address: H160, address: H160, data: Bytes) -> ExecutionResult {
        self.executor.execute(
            contract_address,
            address,
            &mut self.post_state,
            data,
            0,
            false,
            &mut tuple_list!(),
            None,
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

pub fn dummy_precondition(_ctx: &mut OracleCtx<VMInput, FuzzState>, _stage: u64) -> u64 {
    99
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

    pub fn new_no_condition(address: H160) -> Self {
        Self {
            address,
            precondition: dummy_precondition,
            balance_of: hex::decode("70a08231").unwrap(),
        }
    }
}

impl Oracle<VMInput, FuzzState> for IERC20Oracle {
    fn transition(&self, _ctx: &mut OracleCtx<VMInput, FuzzState>, _stage: u64) -> u64 {
        (self.precondition)(_ctx, _stage)
    }

    fn oracle(&self, _ctx: &mut OracleCtx<VMInput, FuzzState>, _stage: u64) -> bool {
        if _stage == 99 {
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
        } else {
            false
        }
    }
}

pub struct IERC20OracleFlashloan {}

impl IERC20OracleFlashloan {
    pub fn new() -> Self {
        Self {}
    }
}

impl Oracle<VMInput, FuzzState> for IERC20OracleFlashloan {
    fn transition(&self, _ctx: &mut OracleCtx<VMInput, FuzzState>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut OracleCtx<VMInput, FuzzState>, _stage: u64) -> bool {
        // has balance increased?
        match ctx.post_state.metadata().get::<FlashloanData>() {
            Some(flashloan_info) => flashloan_info.earned > flashloan_info.owed,
            None => false,
        }
    }
}

pub struct FunctionHarnessOracle {
    pub address: H160,
    harness_func: Vec<u8>,
    precondition: fn(ctx: &mut OracleCtx<VMInput, FuzzState>, stage: u64) -> u64,
}

impl FunctionHarnessOracle {
    pub fn new(
        address: H160,
        harness_func: Vec<u8>,
        precondition: fn(ctx: &mut OracleCtx<VMInput, FuzzState>, stage: u64) -> u64,
    ) -> Self {
        Self {
            address,
            harness_func,
            precondition,
        }
    }

    pub fn new_no_condition(address: H160, harness_func: Vec<u8>) -> Self {
        Self {
            address,
            precondition: dummy_precondition,
            harness_func,
        }
    }
}

impl Oracle<VMInput, FuzzState> for FunctionHarnessOracle {
    fn transition(&self, ctx: &mut OracleCtx<VMInput, FuzzState>, stage: u64) -> u64 {
        (self.precondition)(ctx, stage)
    }

    fn oracle(&self, ctx: &mut OracleCtx<VMInput, FuzzState>, stage: u64) -> bool {
        if stage == 99 {
            let harness_txn = Bytes::from(self.harness_func.clone());
            let res = ctx
                .call_post(
                    if self.address.is_zero() {
                        ctx.input.contract
                    } else {
                        self.address
                    },
                    ctx.input.caller,
                    harness_txn,
                )
                .output;
            !res.iter().map(|x| *x == 0).all(|x| x)
        } else {
            false
        }
    }
}
