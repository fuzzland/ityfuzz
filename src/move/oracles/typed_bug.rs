use crate::oracle::{Oracle, OracleCtx, Producer};
use crate::state::HasExecutionResult;
use bytes::Bytes;
use primitive_types::{H160, H256, U256};
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::rc::Rc;
use itertools::Itertools;
use move_binary_format::CompiledModule;
use move_core_types::language_storage::ModuleId;
use crate::evm::oracles::TYPED_BUG_BUG_IDX;
use crate::r#move::input::{ConciseMoveInput, MoveFunctionInput};

use crate::r#move::types::{MoveAddress, MoveFuzzState, MoveOracleCtx, MoveOutput, MoveSlotTy};
use crate::r#move::vm_state::MoveVMState;

pub struct TypedBugOracle;

impl TypedBugOracle {
    pub fn new() -> Self {
        Self {}
    }
}



impl Oracle<MoveVMState, MoveAddress, CompiledModule, MoveFunctionInput, ModuleId, MoveSlotTy, MoveOutput, MoveFunctionInput, MoveFuzzState, ConciseMoveInput>
for TypedBugOracle {
    fn transition(&self, _ctx: &mut MoveOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(
        &self,
        ctx: &mut MoveOracleCtx<'_>,
        stage: u64,
    ) -> Vec<u64> {
        vec![]
    }
}
