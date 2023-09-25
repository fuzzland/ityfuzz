use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracles::{ARB_CALL_BUG_IDX};
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256, ProjectSourceMapTy};
use crate::evm::vm::EVMState;
use crate::oracle::{Oracle, OracleCtx};
use bytes::Bytes;
use itertools::Itertools;
use libafl::impl_serdeany;
use libafl::prelude::HasMetadata;
use revm_primitives::{Bytecode, HashSet};
use serde::{Deserialize, Serialize};
use crate::evm::blaz::builder::{ArtifactInfoMetadata, BuildJobResult};
use crate::evm::oracle::EVMBugResult;
use crate::fuzzer::ORACLE_OUTPUT;
use crate::state::HasExecutionResult;

pub struct ArbitraryCallOracle {
    pub sourcemap: ProjectSourceMapTy,
    pub address_to_name: HashMap<EVMAddress, String>,
}

impl ArbitraryCallOracle {
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

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ArbitraryCallMetadata {
    pub known_calls: HashMap<(EVMAddress, usize), HashSet<EVMAddress>>,
}

impl_serdeany!(ArbitraryCallMetadata);

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
    ConciseEVMInput
> for ArbitraryCallOracle
{
    fn transition(&self, ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64 {
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
        if ctx.post_state.arbitrary_calls.len() > 0 {
            let mut res = vec![];
            for (caller, target, pc) in ctx.post_state.arbitrary_calls.iter() {
                if !ctx.fuzz_state.has_metadata::<ArbitraryCallMetadata>() {
                    ctx.fuzz_state.metadata_mut().insert(ArbitraryCallMetadata {
                        known_calls: HashMap::new(),
                    });
                }

                let mut metadata = ctx.fuzz_state.metadata_mut().get_mut::<ArbitraryCallMetadata>().unwrap();
                let entry = metadata.known_calls.entry((*caller, *pc)).or_insert(HashSet::new());
                if entry.len() > 3 {
                    continue;
                }
                entry.insert(*target);
                let mut hasher = DefaultHasher::new();
                caller.hash(&mut hasher);
                target.hash(&mut hasher);
                pc.hash(&mut hasher);
                let real_bug_idx = (hasher.finish() as u64) << 8 + ARB_CALL_BUG_IDX;

                let mut name = self.address_to_name
                    .get(caller)
                    .unwrap_or(&format!("{:?}", caller))
                    .clone();

                let srcmap = BuildJobResult::get_sourcemap_executor(
                    ctx.fuzz_state.metadata_mut().get_mut::<ArtifactInfoMetadata>().expect("get metadata failed")
                        .get_mut(caller),
                    ctx.executor,
                    caller,
                    &self.sourcemap,
                    *pc
                );
                EVMBugResult::new(
                    "Arbitrary Call".to_string(),
                    real_bug_idx,
                    format!(
                        "Arbitrary call from {:?} to {:?}",
                        name, target
                    ),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                    srcmap,
                    Some(name.clone())
                ).push_to_output();
                res.push(real_bug_idx);
            }
            res
        } else {
            vec![]
        }
    }
}
