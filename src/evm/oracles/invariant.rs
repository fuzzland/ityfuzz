use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    str::FromStr,
};

use bytes::Bytes;
use itertools::Itertools;
use libafl::state::HasMetadata;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        middlewares::cheatcode::CHEATCODE_ADDRESS,
        oracle::EVMBugResult,
        oracles::INVARIANT_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{BugMetadata, Oracle, OracleCtx},
    oracle_should_skip,
    state::HasExecutionResult,
};

pub struct InvariantOracle {
    pub batch_call_txs: Vec<(EVMAddress, EVMAddress, Bytes)>,
    pub names: HashMap<Vec<u8>, (String, u64)>,
    pub failed_slot: EVMU256,
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
            names: names
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        (v.clone(), {
                            let mut hasher = DefaultHasher::new();
                            k.hash(&mut hasher);
                            hasher.finish()
                        }),
                    )
                })
                .collect::<HashMap<_, _>>(),
            failed_slot: EVMU256::from_str_radix(
                "6661696c65640000000000000000000000000000000000000000000000000000",
                16,
            )
            .unwrap(),
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
            EVMQueueExecutor,
        >,
        _stage: u64,
    ) -> Vec<u64> {
        let mut res = vec![];
        for (nth, tx) in self.batch_call_txs.iter().enumerate() {
            let bug_idx = (nth << 8) as u64 + INVARIANT_BUG_IDX;
            if oracle_should_skip!(ctx, bug_idx) {
                continue;
            }
            let (call_res, new_state) = ctx.call_post_batch_dyn(&[tx.clone()]);
            let (msg, succ) = &call_res[0];
            if *succ &&
                !{
                    // assertTrue in Foundry writes to slot
                    // 0x6661696c65640000000000000000000000000000000000000000000000000000
                    // if the invariant is violated in cheatcode cotract.
                    // @shou: tbh, i feel its dumb and wasteful
                    new_state
                        .get(&CHEATCODE_ADDRESS)
                        .map(|data| {
                            data.get(&self.failed_slot)
                                .map(|v| v == &EVMU256::from(1))
                                .unwrap_or(false)
                        })
                        .unwrap_or(false)
                }
            {
                continue;
            }
            let (name, _) = self.names.get(&tx.2.to_vec()).unwrap();
            EVMBugResult::new(
                "Invariant".to_string(),
                bug_idx,
                format!(
                    "Invariant {:?} violated, {:?}",
                    name,
                    String::from_utf8(msg.iter().filter(|&c| *c > 0).cloned().collect::<Vec<u8>>())
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                None,
                Some(name.clone()),
            )
            .push_to_output();
            res.push(bug_idx);
        }
        res
    }
}
