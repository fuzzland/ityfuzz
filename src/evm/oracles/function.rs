use bytes::Bytes;
use primitive_types::{H160, U256};
use revm::Bytecode;
use crate::evm::input::EVMInput;
use crate::evm::oracle::dummy_precondition;
use crate::evm::types::{EVMFuzzState, EVMOracleCtx};
use crate::evm::vm::EVMState;
use crate::oracle::{Oracle, OracleCtx};

pub struct FunctionHarnessOracle {
    pub address: H160,
    harness_func: Vec<u8>,
    precondition: fn(ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64,
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

impl Oracle<EVMState, H160, Bytecode, Bytes, H160, U256, Vec<u8>, EVMInput, EVMFuzzState>
for FunctionHarnessOracle
{
    fn transition(&self, ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64 {
        (self.precondition)(ctx, stage)
    }

    fn oracle(
        &self,
        _ctx: &mut OracleCtx<
            EVMState,
            H160,
            Bytecode,
            Bytes,
            H160,
            U256,
            Vec<u8>,
            EVMInput,
            EVMFuzzState,
        >,
        stage: u64,
    ) -> bool {
        if stage == 99 {
            let _harness_txn = Bytes::from(self.harness_func.clone());
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
