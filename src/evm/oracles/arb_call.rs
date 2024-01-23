use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
};

use bytes::Bytes;
use libafl::prelude::HasMetadata;
use libafl_bolts::impl_serdeany;
use revm_primitives::{Bytecode, HashSet};
use serde::{Deserialize, Serialize};

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::ARB_CALL_BUG_IDX,
        srcmap::SOURCE_MAP_PROVIDER,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

pub struct ArbitraryCallOracle {
    pub address_to_name: HashMap<EVMAddress, String>,
}

impl ArbitraryCallOracle {
    pub fn new(address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self { address_to_name }
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
        ConciseEVMInput,
        EVMQueueExecutor,
    > for ArbitraryCallOracle
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
        if !ctx.post_state.arbitrary_calls.is_empty() {
            let mut res = vec![];
            for (caller, target, pc) in ctx.post_state.arbitrary_calls.iter() {
                if !ctx.fuzz_state.has_metadata::<ArbitraryCallMetadata>() {
                    ctx.fuzz_state.metadata_map_mut().insert(ArbitraryCallMetadata {
                        known_calls: HashMap::new(),
                    });
                }

                let metadata = ctx
                    .fuzz_state
                    .metadata_map_mut()
                    .get_mut::<ArbitraryCallMetadata>()
                    .unwrap();
                let entry = metadata.known_calls.entry((*caller, *pc)).or_default();
                if entry.len() > 3 {
                    continue;
                }
                entry.insert(*target);
                let mut hasher = DefaultHasher::new();
                caller.hash(&mut hasher);
                target.hash(&mut hasher);
                pc.hash(&mut hasher);
                let real_bug_idx = (hasher.finish() << 8) + ARB_CALL_BUG_IDX;

                let name = self
                    .address_to_name
                    .get(caller)
                    .unwrap_or(&format!("{:?}", caller))
                    .clone();

                EVMBugResult::new(
                    "Arbitrary Call".to_string(),
                    real_bug_idx,
                    format!("Arbitrary call from {:?} to {:?}", name, target),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                    SOURCE_MAP_PROVIDER.lock().unwrap().get_raw_source_map_info(caller, *pc),
                    Some(name.clone()),
                )
                .push_to_output();
                res.push(real_bug_idx);
            }
            res
        } else {
            vec![]
        }
    }
}
