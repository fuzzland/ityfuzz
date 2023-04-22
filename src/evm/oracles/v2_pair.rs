use bytes::Bytes;
use primitive_types::{H160, U256};
use revm::Bytecode;
use crate::evm::input::EVMInput;
use crate::evm::oracle::dummy_precondition;
use crate::evm::oracles::erc20::ORACLE_OUTPUT;
use crate::evm::types::{EVMFuzzState, EVMOracleCtx};
use crate::evm::vm::EVMState;
use crate::oracle::{Oracle, OracleCtx};
use crate::state::HasExecutionResult;

pub struct PairBalanceOracle {}

impl PairBalanceOracle {
    pub fn new() -> Self {
        Self {}
    }
}

impl Oracle<EVMState, H160, Bytecode, Bytes, H160, U256, Vec<u8>, EVMInput, EVMFuzzState>
for PairBalanceOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(
        &self,
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
        stage: u64,
    ) -> bool {
        let reserves = ctx
            .fuzz_state
            .get_execution_result()
            .new_state
            .state
            .flashloan_data
            .oracle_recheck_reserve
            .clone();
        let prev_reserves = ctx
            .fuzz_state
            .get_execution_result()
            .new_state
            .state
            .flashloan_data
            .prev_reserves
            .clone();
        for pair_address in reserves {
            // todo: bring this back
            // let reserve_slot = ctx.fuzz_state.get_execution_result().new_state.state.get(&pair_address)
            //     .expect("Pair not found")
            //     .get(&U256::from(8))
            //     .expect("Reserve not found");
            // println!("Reserve slot: {}: {:?}", pair_address, ctx.fuzz_state.get_execution_result().new_state.state.get(&pair_address));
            // new_reserves.insert(pair_address, reserve_parser(reserve_slot));
            let (pre_r0, pre_r1) = prev_reserves.get(&pair_address).expect("Pair not found");
            let output = ctx.call_post(pair_address, Bytes::from(vec![0x09, 0x02, 0xf1, 0xac]));
            let reserve0 = U256::from_big_endian(&output[0..32]);
            let reserve1 = U256::from_big_endian(&output[32..64]);
            if *pre_r0 == reserve0 && *pre_r1 > reserve1 || *pre_r1 == reserve1 && *pre_r0 > reserve0 {
                unsafe {
                    ORACLE_OUTPUT = format!("Imbalanced Pair: {:?}, Reserves: {:?} => {:?}", pair_address, (reserve0, reserve1), (pre_r0, pre_r1));
                }
                return true;
            }
        }
        false

    }
}
