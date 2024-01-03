use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
};

use bytes::Bytes;
use itertools::Itertools;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::MATH_CALCULATE_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

pub struct MathCalculateOracle {
    pub address_to_name: HashMap<EVMAddress, String>,
}

impl MathCalculateOracle {
    pub fn new(address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self { address_to_name }
    }
}

impl
    Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState, ConciseEVMInput>
    for MathCalculateOracle
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
            ConciseEVMInput,
        >,
        _stage: u64,
    ) -> Vec<u64> {
        let mut bug_indexes = Vec::new();
        for (addr, pc, op) in ctx.post_state.math_error.clone().into_iter() {
            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let real_bug_idx = hasher.finish() << (8 + MATH_CALCULATE_BUG_IDX);
            let name = self
                .address_to_name
                .get(&addr)
                .unwrap_or(&format!("{:?}", addr))
                .clone();
            if op == "/" {
                EVMBugResult::new(
                    "Loss of Accuracy".to_string(),
                    real_bug_idx,
                    format!("PrecisionLoss: {addr:?} , PC: {pc:x}, OP: {op:?}"),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                    None,
                    Some(name.clone()),
                )
                .push_to_output();
                bug_indexes.push(real_bug_idx);
                continue;
            }

            EVMBugResult::new(
                "IntegerOverflow".to_string(),
                real_bug_idx,
                format!("IntegerOverflow: {addr:?} , PC: {pc:x}, OP: {op:?} "),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                None,
                Some(name.clone()),
            )
            .push_to_output();
            bug_indexes.push(real_bug_idx);
        }
        bug_indexes.into_iter().unique().filter(|x| *x != 0).collect_vec()
    }
}
