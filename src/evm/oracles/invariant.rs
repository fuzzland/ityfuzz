use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracle::EVMBugResult;
use crate::evm::oracles::INVARIANT_BUG_IDX;
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256};
use crate::evm::vm::EVMState;
use crate::oracle::{Oracle, OracleCtx};
use crate::state::HasExecutionResult;
use bytes::Bytes;
use itertools::Itertools;
use revm_primitives::Bytecode;
use std::collections::HashMap;
use std::str::FromStr;

pub struct InvariantOracle {
    pub batch_call_txs: Vec<(EVMAddress, EVMAddress, Bytes)>,
    pub names: HashMap<Vec<u8>, String>,
}

impl InvariantOracle {
    pub fn new(
        invariant_funcs: Vec<(EVMAddress, Vec<u8>)>,
        names: HashMap<Vec<u8>, String>,
    ) -> Self {
        Self {
            batch_call_txs: invariant_funcs
                .iter()
                .map(|(address, invariant_func)| {
                    let echidna_txn = Bytes::from(invariant_func.clone());
                    (
                        EVMAddress::from_str("0x0000000000000000000000000000000000007777").unwrap(),
                        *address,
                        echidna_txn,
                    )
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
    > for InvariantOracle
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
            .map(|(idx, (returns, succ))| {
                let name = self
                    .names
                    .get(&self.batch_call_txs[idx].2.to_vec())
                    .unwrap();
                println!("{} {name}  {succ}", idx);
                if *succ {
                    0
                } else {
                    let bug_idx = (idx << 8) as u64 + INVARIANT_BUG_IDX;
                    println!("{} violated {bug_idx}", name);
                    EVMBugResult::new(
                        "invariant".to_string(),
                        bug_idx,
                        format!("{:?} violated", name),
                        ConciseEVMInput::from_input(
                            ctx.input,
                            ctx.fuzz_state.get_execution_result(),
                        ),
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
