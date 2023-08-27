use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracle::{dummy_precondition, EVMBugResult};
use crate::evm::producers::pair::PairProducer;
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMStagedVMState, EVMU256, ProjectSourceMapTy};
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::oracle::{BugMetadata, Oracle, OracleCtx, Producer};
use crate::state::HasExecutionResult;
use bytes::Bytes;
use primitive_types::{H160, H256, U256};
use revm_primitives::Bytecode;
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::rc::Rc;
use itertools::Itertools;
use libafl::state::HasMetadata;
use crate::evm::blaz::builder::{ArtifactInfoMetadata, BuildJobResult};
use crate::evm::oracles::TYPED_BUG_BUG_IDX;
use crate::evm::srcmap::parser::{decode_instructions, SourceMapLocation};
use crate::fuzzer::ORACLE_OUTPUT;

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


impl Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState, ConciseEVMInput>
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
            ConciseEVMInput
        >,
        stage: u64,
    ) -> Vec<u64> {
        if ctx.post_state.typed_bug.len() > 0 {
            ctx.post_state.typed_bug.iter().map(|(bug_id, (addr, pc))| {
                let mut hasher = DefaultHasher::new();
                bug_id.hash(&mut hasher);
                pc.hash(&mut hasher);
                let mut name = self.address_to_name
                    .get(addr)
                    .unwrap_or(&format!("{:?}", addr))
                    .clone();

                let real_bug_idx = (hasher.finish() as u64) << 8 + TYPED_BUG_BUG_IDX;
                let srcmap = BuildJobResult::get_sourcemap_executor(
                    ctx.fuzz_state.metadata_mut().get_mut::<ArtifactInfoMetadata>().expect("get metadata failed")
                        .get_mut(addr),
                    ctx.executor,
                    addr,
                    &self.sourcemap,
                    *pc
                );
                EVMBugResult::new(
                    "typed_bug".to_string(),
                    real_bug_idx,
                    format!(
                        "{:?} violated",
                        bug_id,
                    ),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                    srcmap,
                    Some(name.clone())
                ).push_to_output();
                real_bug_idx
            }).collect_vec()
        } else {
            vec![]
        }
    }
}
