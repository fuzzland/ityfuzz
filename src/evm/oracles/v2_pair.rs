use crate::evm::input::EVMInput;
use crate::evm::oracle::dummy_precondition;
use crate::evm::oracles::erc20::ORACLE_OUTPUT;
use crate::evm::producers::pair::PairProducer;
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256};
use crate::evm::vm::EVMState;
use crate::oracle::{Oracle, OracleCtx, Producer};
use crate::state::HasExecutionResult;
use bytes::Bytes;
use revm_primitives::Bytecode;
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Deref;
use std::rc::Rc;

pub struct PairBalanceOracle {
    pub pair_producer: Rc<RefCell<PairProducer>>,
}

impl PairBalanceOracle {
    pub fn new(pair_producer: Rc<RefCell<PairProducer>>) -> Self {
        Self { pair_producer }
    }
}

impl Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState>
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
        >,
        stage: u64,
    ) -> bool {
        #[cfg(feature = "flashloan_v2")]
        {
            for (addr, (r0, r1)) in &self.pair_producer.deref().borrow().reserves {
                match ctx
                    .fuzz_state
                    .get_execution_result()
                    .new_state
                    .state
                    .flashloan_data
                    .prev_reserves.get(addr) {
                    Some((pre_r0, pre_r1)) => {
                        if *pre_r0 == *r0 && *pre_r1 > *r1 || *pre_r1 == *r1 && *pre_r0 > *r0 {
                            unsafe {
                                ORACLE_OUTPUT = format!(
                                    "Imbalanced Pair: {:?}, Reserves: {:?} => {:?}",
                                    addr,
                                    (r0, r1),
                                    (pre_r0, pre_r1)
                                );
                            }
                            return true;
                        }
                    }
                    None => {
                        continue;
                    }
                }
            }
        }
        #[cfg(not(feature = "flashloan_v2"))]
        {
            panic!("Flashloan v2 required to use pair (-p).")
        }
        false
    }
}
