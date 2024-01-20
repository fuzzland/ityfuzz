use std::collections::HashMap;

use bytes::Bytes;
use itertools::Itertools;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::ECHIDNA_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

pub struct EchidnaOracle {
    pub batch_call_txs: Vec<(EVMAddress, Bytes)>,
    pub names: HashMap<Vec<u8>, String>,
}

impl EchidnaOracle {
    pub fn new(echidna_funcs: Vec<(EVMAddress, Vec<u8>)>, names: HashMap<Vec<u8>, String>) -> Self {
        Self {
            batch_call_txs: echidna_funcs
                .iter()
                .map(|(address, echidna_func)| {
                    let echidna_txn = Bytes::from(echidna_func.clone());
                    (*address, echidna_txn)
                })
                .collect_vec(),
            names,
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
        EVMQueueExecutor,
    > for EchidnaOracle
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
        ctx.call_post_batch(&self.batch_call_txs)
            .iter()
            .map(|out| out.iter().map(|x| *x == 0).all(|x| x))
            .enumerate()
            .map(|(idx, x)| {
                if x {
                    let name = self.names.get(&self.batch_call_txs[idx].1.to_vec()).unwrap();
                    let bug_idx = (idx << 8) as u64 + ECHIDNA_BUG_IDX;
                    EVMBugResult::new(
                        "Echidna".to_string(),
                        bug_idx,
                        format!("Invariant {:?} violated", name),
                        ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                        None,
                        Some(name.clone()),
                    )
                    .push_to_output();
                    bug_idx
                } else {
                    0
                }
            })
            .filter(|x| *x != 0)
            .collect_vec()
    }
}
