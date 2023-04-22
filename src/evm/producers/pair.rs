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
    pub fetch_reserve: Bytes,
}

impl PairProducer {
    pub fn new() -> Self {
        Self {
            reserves: HashMap::new(),
            fetch_reserve: Bytes::from(vec![0x09, 0x02, 0xf1, 0xac]),
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
            let mut query_reserves_batch = reserves.iter().map(
                |pair_address| {
                    (*pair_address, self.fetch_reserve.clone())
                }
            ).collect::<Vec<(H160, Bytes)>>();

            ctx.call_post_batch(&query_reserves_batch).iter().zip(
                reserves.iter()
            ).for_each(
                |(output, pair_address)| {
                    let reserve0 = U256::from_big_endian(&output[0..32]);
                    let reserve1 = U256::from_big_endian(&output[32..64]);
                    self.reserves.insert(*pair_address, (reserve0, reserve1));
                }
            );
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
