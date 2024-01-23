use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::V2_PAIR_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

pub struct PairBalanceOracle {}

impl Default for PairBalanceOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl PairBalanceOracle {
    pub fn new() -> Self {
        Self {}
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
    > for PairBalanceOracle
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
        let mut violations = vec![];
        {
            let to_check = ctx
                .fuzz_state
                .get_execution_result()
                .new_state
                .state
                .flashloan_data
                .oracle_recheck_reserve
                .clone();

            for addr in to_check {
                macro_rules! get_slot_allow_empty {
                    ($state: ident) => {
                        ctx.$state
                            .state
                            .get(&addr)
                            .map(|data| data.get(&EVMU256::from(8)))
                            .unwrap_or(None)
                    };
                }

                let prev_reserve_slot = get_slot_allow_empty!(pre_state);
                let new_reserve_slot = get_slot_allow_empty!(post_state);
                if prev_reserve_slot.is_none() || new_reserve_slot.is_none() {
                    continue;
                }
                let (pre_r0, pre_r1) = reserve_parser(prev_reserve_slot.unwrap());
                let (r0, r1) = reserve_parser(new_reserve_slot.unwrap());

                if pre_r0 == r0 && pre_r1 > r1 || pre_r1 == r1 && pre_r0 > r0 {
                    // calculate hash in u64 of pair address (addr) using DefaultHasher
                    let mut hasher = DefaultHasher::new();
                    addr.hash(&mut hasher);
                    let hash = hasher.finish();
                    let bug_idx = (hash << 8) + V2_PAIR_BUG_IDX;

                    EVMBugResult::new_simple(
                        "Imbalanced Uniswap Pair".to_string(),
                        bug_idx,
                        format!(
                            "In Uniswap pair {:?}, reserves has changed from {:?} to {:?}. It is likely the token contract has incorrectly burned that token in the pair.\n",
                            addr,
                            (r0, r1),
                            (pre_r0, pre_r1)
                        ),
                        ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                    )
                    .push_to_output();

                    violations.push(bug_idx);
                }
            }
        }
        violations
    }
}

pub fn reserve_parser(reserve_slot: &EVMU256) -> (EVMU256, EVMU256) {
    let reserve_bytes: [u8; 32] = reserve_slot.to_be_bytes();
    let reserve_1 = EVMU256::try_from_be_slice(&reserve_bytes[4..18]).unwrap();
    let reserve_0 = EVMU256::try_from_be_slice(&reserve_bytes[18..32]).unwrap();
    (reserve_0, reserve_1)
}
