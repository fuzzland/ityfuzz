use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
};

use bytes::Bytes;
use itertools::Itertools;
use libafl::prelude::HasMetadata;
use revm_primitives::{Bytecode, HashSet};

use crate::{
    evm::{
        blaz::builder::{ArtifactInfoMetadata},
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::INTEGER_OVERFLOW_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, ProjectSourceMapTy, EVMU256, EVMQueueExecutor},
        vm::EVMState, srcmap::parser::read_source_code,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

pub struct IntegerOverflowOracle {
    pub sourcemap: ProjectSourceMapTy,
    pub address_to_name: HashMap<EVMAddress, String>,
    solc_genereted_fp: HashSet<u64>
}

impl IntegerOverflowOracle {
    pub fn new(sourcemap: ProjectSourceMapTy, address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self {
            sourcemap,
            address_to_name,
            solc_genereted_fp: HashSet::new()
        }
    }
}

impl
    Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState, ConciseEVMInput>
    for IntegerOverflowOracle
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
        ctx.post_state
            .integer_overflow
            .iter()
            .map(|(addr, pc, op)| {
                let mut hasher = DefaultHasher::new();
                addr.hash(&mut hasher);
                pc.hash(&mut hasher);
                let real_bug_idx = hasher.finish() << (8 + INTEGER_OVERFLOW_BUG_IDX);
                if self.solc_genereted_fp.contains(&real_bug_idx) {
                    return 0;
                }
                

                let name = self.address_to_name.get(addr).unwrap_or(&format!("{:?}", addr)).clone();

                let build_job_result = ctx.fuzz_state
                .metadata_map_mut()
                .get_mut::<ArtifactInfoMetadata>()
                .expect("get metadata failed")
                .get_mut(addr);
                
                if build_job_result.is_none() {
                    EVMBugResult::new(
                        "IntegerOverflow".to_string(),
                        real_bug_idx,
                        format!("IntegerOverflow on Contract: {addr:?} , PC: {pc:x}, OP: {op:?} (no build_job_result)"),
                        ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                        None,
                        Some(name.clone()),
                    )
                    .push_to_output();
                    return real_bug_idx;
                }
                let bytecode = Vec::from(
                    (**ctx.executor)
                        .borrow_mut()
                        .as_any()
                        .downcast_ref::<EVMQueueExecutor>()
                        .unwrap()
                        .host
                        .code
                        .get(addr)
                        .unwrap()
                        .clone()
                        .bytecode(),
                );
                let build_job_result = build_job_result.unwrap();
                let srcmap = &build_job_result.get_sourcemap(bytecode);
                if  srcmap.get(pc).is_none() {
                    EVMBugResult::new(
                        "IntegerOverflow".to_string(),
                        real_bug_idx,
                        format!("IntegerOverflow on Contract: {addr:?} , PC: {pc:x}, OP: {op:?} (no srcmap)"),
                        ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                        None,
                        Some(name.clone()),
                    )
                    .push_to_output();
                    return real_bug_idx;
                }

                let file_blob = &build_job_result.sources;
                // println!("file_blob: {:?}", file_blob);
                println!("addr: {:?}, pc: {:x}, op: {:?}", addr, pc, op);
                let loc =srcmap.get(pc).unwrap();
                println!("loc: {:?}", loc);
                let source_code = read_source_code(loc, file_blob);
                println!("source_code: {:?}", source_code);

                real_bug_idx
            })
            .filter(|x| *x != 0)
            .collect_vec()
    }
}
