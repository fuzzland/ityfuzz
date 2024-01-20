use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
};

use bytes::Bytes;
use itertools::Itertools;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::TYPED_BUG_BUG_IDX,
        srcmap::SOURCE_MAP_PROVIDER,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

pub struct TypedBugOracle {
    address_to_name: HashMap<EVMAddress, String>,
}

impl TypedBugOracle {
    pub fn new(address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self { address_to_name }
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
        EVMQueueExecutor,
    > for TypedBugOracle
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
            EVMQueueExecutor,
        >,
        _stage: u64,
    ) -> Vec<u64> {
        if !ctx.post_state.typed_bug.is_empty() {
            ctx.post_state
                .typed_bug
                .iter()
                .map(|(bug_id, (addr, pc))| {
                    let mut hasher = DefaultHasher::new();
                    bug_id.hash(&mut hasher);
                    pc.hash(&mut hasher);
                    let name = self.address_to_name.get(addr).unwrap_or(&format!("{:?}", addr)).clone();

                    let real_bug_idx = (hasher.finish() << 8) + TYPED_BUG_BUG_IDX;

                    EVMBugResult::new(
                        "Bug".to_string(),
                        real_bug_idx,
                        format!("Invariant {:?} violated", bug_id,),
                        ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                        SOURCE_MAP_PROVIDER.lock().unwrap().get_raw_source_map_info(addr, *pc),
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
