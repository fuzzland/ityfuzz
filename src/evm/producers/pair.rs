use crate::evm::input::EVMInput;
use crate::evm::types::EVMFuzzState;
use crate::evm::vm::EVMState;
use crate::oracle::{OracleCtx, Producer};
use crate::state::HasExecutionResult;
use bytes::Bytes;
use primitive_types::{H160, U256};
use revm::Bytecode;
use std::collections::HashMap;

pub struct PairProducer {
    pub reserves: HashMap<H160, (U256, U256)>,
}

impl PairProducer {
    pub fn new() -> Self {
        Self {
            reserves: HashMap::new(),
        }
    }
}

impl Producer<EVMState, H160, Bytecode, Bytes, H160, U256, Vec<u8>, EVMInput, EVMFuzzState>
    for PairProducer
{
    fn produce(
        &mut self,
        ctx: &mut OracleCtx<
            EVMState,
            H160,
            Bytecode,
            Bytes,
            H160,
            U256,
            Vec<u8>,
            EVMInput,
            EVMFuzzState,
        >,
    ) {
        #[cfg(feature = "flashloan_v2")]
        {
            let reserves = ctx
                .fuzz_state
                .get_execution_result()
                .new_state
                .state
                .flashloan_data
                .oracle_recheck_reserve
                .clone();
            for pair_address in reserves {
                // todo: bring this back
                // let reserve_slot = ctx.fuzz_state.get_execution_result().new_state.state.get(&pair_address)
                //     .expect("Pair not found")
                //     .get(&U256::from(8))
                //     .expect("Reserve not found");
                // println!("Reserve slot: {}: {:?}", pair_address, ctx.fuzz_state.get_execution_result().new_state.state.get(&pair_address));
                // new_reserves.insert(pair_address, reserve_parser(reserve_slot));
                let output = ctx.call_post(pair_address, Bytes::from(vec![0x09, 0x02, 0xf1, 0xac]));
                let reserve0 = U256::from_big_endian(&output[0..32]);
                let reserve1 = U256::from_big_endian(&output[32..64]);
                self.reserves.insert(pair_address, (reserve0, reserve1));
            }
        }
        #[cfg(not(feature = "flashloan_v2"))]
        {
            panic!("Flashloan v2 required to use pair (-p).")
        }
    }

    fn notify_end(
        &mut self,
        ctx: &mut OracleCtx<
            EVMState,
            H160,
            Bytecode,
            Bytes,
            H160,
            U256,
            Vec<u8>,
            EVMInput,
            EVMFuzzState,
        >,
    ) {
        self.reserves.clear();
    }
}
