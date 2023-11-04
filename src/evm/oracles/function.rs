use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::dummy_precondition,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
};

pub struct FunctionHarnessOracle {
    pub address: EVMAddress,
    harness_func: Vec<u8>,
    precondition: fn(ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64,
}

impl FunctionHarnessOracle {
    pub fn new(
        address: EVMAddress,
        harness_func: Vec<u8>,
        precondition: fn(ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64,
    ) -> Self {
        Self {
            address,
            harness_func,
            precondition,
        }
    }

    pub fn new_no_condition(address: EVMAddress, harness_func: Vec<u8>) -> Self {
        Self {
            address,
            precondition: dummy_precondition,
            harness_func,
        }
    }
}

impl
    Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState, ConciseEVMInput>
    for FunctionHarnessOracle
{
    fn transition(&self, ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64 {
        (self.precondition)(ctx, stage)
    }

    fn oracle(
        &self,
        _ctx: &mut OracleCtx<
            EVMState,
            EVMAddress,
            Bytecode,
            Bytes,
            EVMAddress,
            EVMU256,
            Vec<u8>,
            EVMInput,
            EVMFuzzState,
            ConciseEVMInput,
        >,
        _stage: u64,
    ) -> Vec<u64> {
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
        unimplemented!()
    }
}
