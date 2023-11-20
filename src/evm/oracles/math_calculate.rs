use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
};

use bytes::Bytes;
use itertools::Itertools;
use libafl::prelude::HasMetadata;
use revm_primitives::Bytecode;
use tracing::debug;

use crate::{
    evm::{
        blaz::builder::ArtifactInfoMetadata,
        corpus_initializer::SourceMapMap,
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::INTEGER_OVERFLOW_BUG_IDX,
        srcmap::parser::read_source_code,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, ProjectSourceMapTy, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

// whether real_bug_idx is FP
// static mut FP: Option<HashSet<u64>> = None;

pub struct MathCalculateOracle {
    pub sourcemap: ProjectSourceMapTy,
    pub address_to_name: HashMap<EVMAddress, String>,
}

impl MathCalculateOracle {
    pub fn new(sourcemap: ProjectSourceMapTy, address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self {
            sourcemap,
            address_to_name,
        }
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
        for (addr, pc, op) in ctx.post_state.integer_overflow.clone().into_iter() {
            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let real_bug_idx = hasher.finish() << (8 + INTEGER_OVERFLOW_BUG_IDX);
            // if unsafe { FP.get_or_insert_with(HashSet::new).contains(&real_bug_idx) } {
            //     println!("existing FP: {:?}", real_bug_idx);
            //     continue;
            // }

            let name = self
                .address_to_name
                .get(&addr)
                .unwrap_or(&format!("{:?}", addr))
                .clone();

            /*
            1. no code/unverifyed -> maybe_fp
            2. no sourcemap, has sourcecode -> maybe_fp
            3. has sourcecode but sourcemap cannot match code(solc generated)  -> fp
            4. has sourcecode and match the logic code -> bug / fp
            */

            let build_job_result = ctx
                .fuzz_state
                .metadata_map()
                .get::<ArtifactInfoMetadata>()
                .expect("get metadata failed")
                .get(&addr);
            if build_job_result.is_none() {
                // case 1/2
                EVMBugResult::new(
                    "IntegerOverflow".to_string(),
                    real_bug_idx,
                    format!("IntegerOverflow on Contract: {addr:?} , PC: {pc:x}, OP: {op:?} (no build_job_result)"),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                    None,
                    Some(name.clone()),
                )
                .push_to_output();
                bug_indexes.push(real_bug_idx);
                println!("addr: {:?}, pc: {:x}, op: {:?} {real_bug_idx}", addr, pc, op);
                println!("no build_job_result");
                continue;
            }

            let src_map = ctx.fuzz_state.metadata_map().get::<SourceMapMap>().unwrap().get(&addr);
            if src_map.is_none() {
                // case 1/2
                EVMBugResult::new(
                    "IntegerOverflow".to_string(),
                    real_bug_idx,
                    format!("IntegerOverflow on Contract: {addr:?} , PC: {pc:x}, OP: {op:?} (no src_map)"),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                    None,
                    Some(name.clone()),
                )
                .push_to_output();
                bug_indexes.push(real_bug_idx);
                println!("addr: {:?}, pc: {:x}, op: {:?} {real_bug_idx}", addr, pc, op);
                println!("no src_map");
                continue;
            }

            let file_blob = &build_job_result.unwrap().sources;

            let binding = src_map.unwrap().clone().unwrap();
            let loc = binding.get(&pc).unwrap();
            if loc.file.is_none() {
                // case 3, fp
                // self.middleware.borrow_mut().fp.insert((addr, pc));
                debug!("new FP: loc.file.is_none");
                ctx.post_state.integer_overflow.remove(&(addr, pc, op));
                continue;
            }
            let source_code = read_source_code(loc, file_blob, false).code;
            debug!("source_code: {:?}", source_code);
            // case 4
            if !source_code.contains(op) {
                // case 4 fp
                // self.middleware.borrow_mut().fp.insert((addr, pc));
                debug!("new FP: !source_code.contains(op)");
                ctx.post_state.integer_overflow.remove(&(addr, pc, op));
                continue;
            }
            if op == "/" {
                EVMBugResult::new(
                    "Loss of Accuracy".to_string(),
                    real_bug_idx,
                    format!(
                        "Loss of accuracy on Contract: {addr:?} , PC: {pc:x}, OP: {op:?} (real logic)\n\t{source_code}"
                    ),
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
                format!("IntegerOverflow on Contract: {addr:?} , PC: {pc:x}, OP: {op:?} (real logic overflow)\n\t{source_code}"),
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
