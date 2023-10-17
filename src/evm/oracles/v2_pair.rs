use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracle::{dummy_precondition, EVMBugResult};
use crate::evm::producers::pair::PairProducer;
use crate::evm::types::{bytes_to_u64, EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256};
use crate::evm::uniswap::reserve_parser;
use crate::evm::vm::EVMState;
use crate::oracle::{Oracle, OracleCtx, Producer};
use crate::state::HasExecutionResult;
use revm::EVM;
use revm_primitives::{Bytecode, Bytes};
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::rc::Rc;
use crate::evm::oracles::V2_PAIR_BUG_IDX;
use crate::fuzzer::ORACLE_OUTPUT;

pub struct PairBalanceOracle {
    pub pair_producer: Rc<RefCell<PairProducer>>,
}

impl PairBalanceOracle {
    pub fn new(pair_producer: Rc<RefCell<PairProducer>>) -> Self {
        Self { pair_producer }
    }
}

impl Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState, ConciseEVMInput>
    for PairBalanceOracle
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
            ConciseEVMInput
        >,
        stage: u64,
    ) -> Vec<u64> {
        let mut violations = vec![];
        #[cfg(feature = "flashloan_v2")]
        {
            let to_check = ctx
                .fuzz_state
                .get_execution_result()
                .new_state
                .state
                .flashloan_data
                .oracle_recheck_reserve.clone();

            for addr in to_check {
                macro_rules! get_slot_allow_empty {
                    ($state: ident) => {
                        ctx
                            .$state
                            .state
                            .get(&addr)
                            .map(|data| {
                                data.get(&EVMU256::from(8))
                            }).unwrap_or(None)
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
                    let bug_idx = hash << 8 + V2_PAIR_BUG_IDX;

                    EVMBugResult::new_simple(
                        "imbalanced_pair".to_string(),
                        bug_idx,
                        format!(
                            "{:?}, Reserves changed from {:?} to {:?}\n",
                            addr,
                            (r0, r1),
                            (pre_r0, pre_r1)
                        ),
                        ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                    ).push_to_output();

                    violations.push(bug_idx);
                }

            }

            // for (addr, (r0, r1)) in &self.pair_producer.deref().borrow().reserves {
            //     match ctx
            //         .fuzz_state
            //         .get_execution_result()
            //         .new_state
            //         .state
            //         .flashloan_data
            //         .prev_reserves.get(addr) {
            //         Some((pre_r0, pre_r1)) => {

            //             println!(
            //                 "Pair: {:?}, Reserves changed from {:?} to {:?}\n",
            //                 addr,
            //                 (r0, r1),
            //                 (pre_r0, pre_r1)
            //             );

            //             if *pre_r0 == *r0 && *pre_r1 > *r1 || *pre_r1 == *r1 && *pre_r0 > *r0 {
            //                 // calculate hash in u64 of pair address (addr) using DefaultHasher
            //                 let mut hasher = DefaultHasher::new();
            //                 addr.hash(&mut hasher);
            //                 let hash = hasher.finish();
            //                 let bug_idx = hash << 8 + V2_PAIR_BUG_IDX;

            //                 EVMBugResult::new_simple(
            //                     "imbalanced_pair".to_string(),
            //                     bug_idx,
            //                     format!(
            //                         "{:?}, Reserves changed from {:?} to {:?}\n",
            //                         addr,
            //                         (r0, r1),
            //                         (pre_r0, pre_r1)
            //                     ),
            //                     ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            //                 ).push_to_output();

            //                 violations.push(bug_idx);
            //             }
            //         }
            //         None => {
            //             continue;
            //         }
            //     }
            // }
        }
        #[cfg(not(feature = "flashloan_v2"))]
        {
            panic!("Flashloan v2 required to use pair (-p).")
        }
        violations
    }
}
