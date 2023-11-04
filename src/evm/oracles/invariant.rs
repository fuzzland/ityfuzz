use std::{collections::HashMap, str::FromStr};

use bytes::Bytes;
use itertools::Itertools;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::INVARIANT_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256},
        vm::EVMState,
    },
    fuzzer::ORACLE_OUTPUT,
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

pub struct InvariantOracle {
    pub batch_call_txs: Vec<(EVMAddress, EVMAddress, Bytes)>,
    pub names: HashMap<Vec<u8>, String>,
}

impl InvariantOracle {
    pub fn new(invariant_funcs: Vec<(EVMAddress, Vec<u8>)>, names: HashMap<Vec<u8>, String>) -> Self {
        Self {
            batch_call_txs: invariant_funcs
                .iter()
                .map(|(address, invariant_func)| {
                    let invariant_tx = Bytes::from(invariant_func.clone());
                    (
                        EVMAddress::from_str("0x0000000000000000000000000000000000007777").unwrap(),
                        *address,
                        invariant_tx,
                    )
                })
                .collect_vec(),
            names,
        }
    }
}

impl
    Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState, ConciseEVMInput>
    for InvariantOracle
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
        ctx.call_post_batch_dyn(&self.batch_call_txs)
            .0
            .iter()
            .enumerate()
            .map(|(idx, (_, succ))| {
                let name = self.names.get(&self.batch_call_txs[idx].2.to_vec()).unwrap();
                if *succ {
                    0
                } else {
                    let bug_idx = (idx << 8) as u64 + INVARIANT_BUG_IDX;
                    EVMBugResult::new(
                        "invariant".to_string(),
                        bug_idx,
                        format!("{:?} violated", name),
                        ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                        None,
                        Some(name.clone()),
                    )
                    .push_to_output();
                    bug_idx
                }
            })
            .filter(|x| *x != 0)
            .collect_vec()
    }
}
