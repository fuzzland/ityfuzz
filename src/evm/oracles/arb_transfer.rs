use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracles::{ARB_CALL_BUG_IDX, ARB_TRANSFER_BUG_IDX};
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

pub struct ArbitraryERC20TransferOracle {
    pub sourcemap: ProjectSourceMapTy,
    pub address_to_name: HashMap<EVMAddress, String>,
}

impl ArbitraryERC20TransferOracle {
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
    ConciseEVMInput
> for ArbitraryERC20TransferOracle
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
        if ctx.post_state.arbitrary_transfers.len() > 0 {
            let mut res = vec![];
            for (caller, pc) in ctx.post_state.arbitrary_transfers.iter() {
                let mut hasher = DefaultHasher::new();
                caller.hash(&mut hasher);
                pc.hash(&mut hasher);
                let real_bug_idx = (hasher.finish() as u64) << 8 + ARB_TRANSFER_BUG_IDX;

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
                    "Arbitrary Transfer".to_string(),
                    real_bug_idx,
                    format!(
                        "Arbitrary transfer from {:?}",
                        name
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
