use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use itertools::Itertools;
use move_binary_format::CompiledModule;
use move_core_types::language_storage::ModuleId;
use serde_json::json;

use crate::{
    fuzzer::ORACLE_OUTPUT,
    oracle::Oracle,
    r#move::{
        input::{ConciseMoveInput, MoveFunctionInput},
        movevm::MoveVM,
        oracles::TYPED_BUG_BUG_IDX,
        types::{MoveAddress, MoveFuzzState, MoveOracleCtx, MoveOutput, MoveSlotTy},
        vm_state::MoveVMState,
    },
};
pub struct TypedBugOracle;

impl Default for TypedBugOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl TypedBugOracle {
    pub fn new() -> Self {
        Self {}
    }
}

impl
    Oracle<
        MoveVMState,
        MoveAddress,
        CompiledModule,
        MoveFunctionInput,
        ModuleId,
        MoveSlotTy,
        MoveOutput,
        MoveFunctionInput,
        MoveFuzzState,
        ConciseMoveInput,
        MoveVM<MoveFunctionInput, MoveFuzzState>,
    > for TypedBugOracle
{
    fn transition(&self, _ctx: &mut MoveOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut MoveOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        if !ctx.post_state.typed_bug.is_empty() {
            ctx.post_state
                .typed_bug
                .iter()
                .map(|bug_id| {
                    let mut hasher = DefaultHasher::new();
                    bug_id.hash(&mut hasher);
                    let real_bug_idx = (hasher.finish() << 8) + TYPED_BUG_BUG_IDX;
                    let msg = json!({
                        "bug_type": "Bug".to_string(),
                        "bug_info": format!("{:?} violated", bug_id),
                        "bug_idx": real_bug_idx,
                    });
                    unsafe {
                        ORACLE_OUTPUT.push(msg);
                    }

                    real_bug_idx
                })
                .collect_vec()
        } else {
            vec![]
        }
    }
}
