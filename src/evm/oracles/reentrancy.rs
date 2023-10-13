use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracle::EVMBugResult;
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, ProjectSourceMapTy, EVMU256};
use crate::evm::vm::EVMState;
use crate::generic_vm::vm_state::VMStateT;
use crate::oracle::{Oracle, OracleCtx};
use crate::state::HasExecutionResult;
use bytes::Bytes;
use itertools::Itertools;
use revm_primitives::Bytecode;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use super::REENTRANCY_BUG_IDX;

pub struct ReentrancyOracle {
    pub sourcemap: ProjectSourceMapTy,
    pub address_to_name: HashMap<EVMAddress, String>,
}

impl ReentrancyOracle {
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
    > for ReentrancyOracle
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
        let reetrancy_metadata = unsafe {
            &ctx.post_state
                .as_any()
                .downcast_ref_unchecked::<EVMState>()
                .reentrancy_metadata
        };
        if reetrancy_metadata.found.is_empty() {
            return vec![];
        }
        reetrancy_metadata
            .found
            .iter()
            .map(|(addr, slot)| {
                let mut hasher = DefaultHasher::new();
                addr.hash(&mut hasher);
                let real_bug_idx = hasher.finish() << (8 + REENTRANCY_BUG_IDX);

                let name = self
                    .address_to_name
                    .get(addr)
                    .unwrap_or(&format!("{:?}", addr))
                    .clone();
                EVMBugResult::new(
                    "reentrancy".to_string(),
                    real_bug_idx,
                    format!("Reentrancy on {:?} at slot {:?}", name, slot),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                    None,
                    Some(name.clone()),
                )
                .push_to_output();
                real_bug_idx
            })
            .collect_vec()
    }
}
