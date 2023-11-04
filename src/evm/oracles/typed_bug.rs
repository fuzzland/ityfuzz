use std::{
    borrow::Borrow,
    cell::RefCell,
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    ops::Deref,
    rc::Rc,
};

use bytes::Bytes;
use itertools::Itertools;
use libafl::state::HasMetadata;
use primitive_types::{H160, H256, U256};
use revm_primitives::Bytecode;

use crate::{
    evm::{
        blaz::builder::{ArtifactInfoMetadata, BuildJobResult},
        input::{ConciseEVMInput, EVMInput},
        oracle::{dummy_precondition, EVMBugResult},
        oracles::TYPED_BUG_BUG_IDX,
        srcmap::parser::{decode_instructions, SourceMapLocation},
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMStagedVMState, ProjectSourceMapTy, EVMU256},
        vm::{EVMExecutor, EVMState},
    },
    fuzzer::ORACLE_OUTPUT,
    oracle::{BugMetadata, Oracle, OracleCtx, Producer},
    state::HasExecutionResult,
};

pub struct TypedBugOracle {
    sourcemap: ProjectSourceMapTy,
    address_to_name: HashMap<EVMAddress, String>,
}

impl TypedBugOracle {
    pub fn new(sourcemap: ProjectSourceMapTy, address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self {
            sourcemap,
            address_to_name,
        }
    }
}

impl
    Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState, ConciseEVMInput>
    for TypedBugOracle
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
        stage: u64,
    ) -> Vec<u64> {
        if ctx.post_state.typed_bug.len() > 0 {
            ctx.post_state
                .typed_bug
                .iter()
                .map(|(bug_id, (addr, pc))| {
                    let mut hasher = DefaultHasher::new();
                    bug_id.hash(&mut hasher);
                    pc.hash(&mut hasher);
                    let mut name = self.address_to_name.get(addr).unwrap_or(&format!("{:?}", addr)).clone();

                    let real_bug_idx = (hasher.finish() as u64) << 8 + TYPED_BUG_BUG_IDX;
                    let srcmap = BuildJobResult::get_sourcemap_executor(
                        ctx.fuzz_state
                            .metadata_map_mut()
                            .get_mut::<ArtifactInfoMetadata>()
                            .expect("get metadata failed")
                            .get_mut(addr),
                        ctx.executor,
                        addr,
                        &self.sourcemap,
                        *pc,
                    );
                    EVMBugResult::new(
                        "typed_bug".to_string(),
                        real_bug_idx,
                        format!("{:?} violated", bug_id,),
                        ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                        srcmap,
                        Some(name.clone()),
                    )
                    .push_to_output();
                    real_bug_idx
                })
                .collect_vec()
        } else {
            vec![]
        }
    }
}
