use std::collections::HashMap;
use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracles::{ECHIDNA_BUG_IDX, FUNCTION_BUG_IDX};
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256};
use crate::evm::vm::EVMState;
use crate::oracle::{Oracle, OracleCtx};
use bytes::Bytes;
use itertools::Itertools;
use revm_primitives::Bytecode;
use crate::evm::oracle::EVMBugResult;
use crate::fuzzer::ORACLE_OUTPUT;
use crate::state::HasExecutionResult;

pub struct EchidnaOracle {
    pub batch_call_txs: Vec<(EVMAddress, Bytes)>,
    pub names: HashMap<Vec<u8>, String>
}

impl EchidnaOracle {
    pub fn new(echidna_funcs: Vec<(EVMAddress, Vec<u8>)>, names: HashMap<Vec<u8>, String>) -> Self {
        Self {
            batch_call_txs: echidna_funcs.iter().map(
                |(address, echidna_func)| {
                    let echidna_txn = Bytes::from(echidna_func.clone());
                    (address.clone(), echidna_txn)
                }
            ).collect_vec(),
            names
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
    > for EchidnaOracle
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
        ctx.call_post_batch(&self.batch_call_txs)
            .iter()
            .map(|out| out.iter().map(|x| *x == 0).all(|x| x))
            .enumerate()
            .map(|(idx, x)| {
                if x {
                    let name = self.names.get(&self.batch_call_txs[idx].1.to_vec()).unwrap();
                    let bug_idx = (idx << 8) as u64 + ECHIDNA_BUG_IDX;
                    EVMBugResult::new(
                        "echidna".to_string(),
                        bug_idx,
                        format!("{:?} violated", name),
                        ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                        None,
                        Some(name.clone())
                    ).push_to_output();
                    bug_idx
                } else { 0 }
            })
            .filter(|x| *x != 0)
            .collect_vec()
    }
}
