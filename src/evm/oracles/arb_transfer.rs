use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
};

use bytes::Bytes;
use itertools::Itertools;
use libafl::prelude::HasMetadata;
use libafl_bolts::impl_serdeany;
use revm_primitives::{Bytecode, HashSet};
use serde::{Deserialize, Serialize};

use crate::{
    evm::{
        blaz::builder::{ArtifactInfoMetadata, BuildJobResult},
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::{ARB_CALL_BUG_IDX, ARB_TRANSFER_BUG_IDX},
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256},
        vm::EVMState,
    },
    fuzzer::ORACLE_OUTPUT,
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

pub struct ArbitraryERC20TransferOracle {
    pub address_to_name: HashMap<EVMAddress, String>,
}

impl ArbitraryERC20TransferOracle {
    pub fn new(address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self { address_to_name }
    }
}

impl
    Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState, ConciseEVMInput>
    for ArbitraryERC20TransferOracle
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
            ConciseEVMInput,
            EVMQueueExecutor,
        >,
        stage: u64,
    ) -> Vec<u64> {
        if ctx.post_state.arbitrary_transfers.len() > 0 {
            let mut res = vec![];
            for (caller, pc) in ctx.post_state.arbitrary_transfers.iter() {
                let mut hasher = DefaultHasher::new();
                caller.hash(&mut hasher);
                pc.hash(&mut hasher);
                let real_bug_idx = (hasher.finish() << 8 as u64) + ARB_TRANSFER_BUG_IDX;

                let mut name = self
                    .address_to_name
                    .get(caller)
                    .unwrap_or(&format!("{:?}", caller))
                    .clone();

                EVMBugResult::new(
                    "Arbitrary Transfer".to_string(),
                    real_bug_idx,
                    format!("Arbitrary transfer from {:?}", name),
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
