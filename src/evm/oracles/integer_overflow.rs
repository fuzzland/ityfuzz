use crate::evm::blaz::builder::{ArtifactInfoMetadata, BuildJobResult};
use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracle::EVMBugResult;
use crate::evm::oracles::INTEGER_OVERFLOW_BUG_IDX;
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, ProjectSourceMapTy, EVMU256};
use crate::evm::vm::EVMState;
use crate::oracle::{Oracle, OracleCtx};
use crate::state::HasExecutionResult;
use bytes::Bytes;
use itertools::Itertools;
use libafl::prelude::HasMetadata;
use revm_primitives::Bytecode;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

pub struct IntegerOverflowOracle {
    pub sourcemap: ProjectSourceMapTy,
    pub address_to_name: HashMap<EVMAddress, String>,
}

impl IntegerOverflowOracle {
    pub fn new(
        sourcemap: ProjectSourceMapTy,
        address_to_name: HashMap<EVMAddress, String>,
    ) -> Self {
        Self {
            sourcemap,
            address_to_name,
        }
    }
}

impl
    Oracle<
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
    > for IntegerOverflowOracle
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
            .map(|(addr, pc)| {
                let mut hasher = DefaultHasher::new();
                addr.hash(&mut hasher);
                pc.hash(&mut hasher);
                let real_bug_idx = hasher.finish() << (8 + INTEGER_OVERFLOW_BUG_IDX);

                let name = self
                    .address_to_name
                    .get(addr)
                    .unwrap_or(&format!("{:?}", addr))
                    .clone();

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
                    "IntegerOverflow".to_string(),
                    real_bug_idx,
                    format!("IntegerOverflow on Contract: {addr:?} , PC: {pc:?}"),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                    srcmap,
                    Some(name.clone()),
                )
                .push_to_output();
                real_bug_idx
            })
            .collect_vec()
    }
}
