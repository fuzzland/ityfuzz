use crate::evm::input::EVMInput;
use crate::evm::onchain::flashloan::FlashloanData;
use crate::evm::types::{EVMFuzzState, EVMOracleCtx};
use crate::evm::vm::EVMState;
use crate::generic_vm::vm_state::VMStateT;
use crate::oracle::{Oracle, OracleCtx};
use crate::state::FuzzState;
use bytes::Bytes;
use libafl::state::HasMetadata;
use primitive_types::{H160, U256};
use revm::Bytecode;

pub struct NoOracle {}

impl Oracle<EVMState, H160, Bytecode, Bytes, H160, U256, EVMInput, EVMFuzzState> for NoOracle {
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

impl Oracle<EVMState, H160, Bytecode, Bytes, H160, U256, EVMInput, EVMFuzzState> for IERC20Oracle {
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        (self.precondition)(_ctx, _stage)
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> bool {
        if _stage == 99 {
            let balance_of_txn =
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

pub struct IERC20OracleFlashloan {}

impl IERC20OracleFlashloan {
    pub fn new() -> Self {
        Self {}
    }
}

impl Oracle<EVMState, H160, Bytecode, Bytes, H160, U256, EVMInput, EVMFuzzState>
    for IERC20OracleFlashloan
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> bool {
        // has balance increased?
        if ctx.post_state.flashloan_data.earned > ctx.post_state.flashloan_data.owed {
            println!(
                "[Flashloan] Earned {} more than owed {}",
                ctx.post_state.flashloan_data.earned, ctx.post_state.flashloan_data.owed
            );
            true
        } else {
            false
        }
    }
}

pub struct FunctionHarnessOracle {
    pub address: H160,
    harness_func: Vec<u8>,
    precondition: fn(
        ctx: &mut OracleCtx<EVMState, H160, Bytecode, Bytes, H160, U256, EVMInput, EVMFuzzState>,
        stage: u64,
    ) -> u64,
}

impl FunctionHarnessOracle {
    pub fn new(
        address: H160,
        harness_func: Vec<u8>,
        precondition: fn(ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64,
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

impl Oracle<EVMState, H160, Bytecode, Bytes, H160, U256, EVMInput, EVMFuzzState>
    for FunctionHarnessOracle
{
    fn transition(&self, ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64 {
        (self.precondition)(ctx, stage)
    }

    fn oracle(
        &self,
        ctx: &mut OracleCtx<EVMState, H160, Bytecode, Bytes, H160, U256, EVMInput, EVMFuzzState>,
        stage: u64,
    ) -> bool {
        if stage == 99 {
            let harness_txn = Bytes::from(self.harness_func.clone());
            // let res = ctx
            //     .call_post(
            //         if self.address.is_zero() {
            //             ctx.input.contract
            //         } else {
            //             self.address
            //         },
            //         ctx.input.caller,
            //         harness_txn,
            //     )
            //     .output;
            // !res.iter().map(|x| *x == 0).all(|x| x)
            false
        } else {
            false
        }
    }
}
