use std::collections::HashMap;

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        types::{EVMAddress, EVMFuzzState, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{OracleCtx, Producer},
    state::HasExecutionResult,
};

pub struct ERC20Producer {
    // (caller, token) -> (pre_balance, post_balance)
    pub balances: HashMap<(EVMAddress, EVMAddress), EVMU256>,
    pub balance_of: Vec<u8>,
}

impl Default for ERC20Producer {
    fn default() -> Self {
        Self::new()
    }
}

impl ERC20Producer {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
            balance_of: hex::decode("70a08231").unwrap(),
        }
    }
}

impl
    Producer<
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
    > for ERC20Producer
{
    fn produce(
        &mut self,
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
    ) {
        {
            let tokens = ctx
                .fuzz_state
                .get_execution_result()
                .new_state
                .state
                .flashloan_data
                .oracle_recheck_balance
                .clone();

            let callers = ctx.fuzz_state.callers_pool.clone();
            let query_balance_batch = callers
                .iter()
                .flat_map(|caller| {
                    let mut extended_address = vec![0; 12];
                    extended_address.extend_from_slice(caller.0.as_slice());
                    let call_data = Bytes::from([self.balance_of.clone(), extended_address].concat());
                    tokens
                        .iter()
                        .map(|token| (*token, call_data.clone()))
                        .collect::<Vec<(EVMAddress, Bytes)>>()
                })
                .collect::<Vec<(EVMAddress, Bytes)>>();
            let post_balance_res = ctx.call_post_batch(&query_balance_batch);

            let mut idx = 0;

            for caller in &callers {
                for token in &tokens {
                    let token = *token;
                    let post_balance = &post_balance_res[idx];
                    let new_balance = EVMU256::try_from_be_slice(post_balance.as_slice()).unwrap_or(EVMU256::ZERO);
                    self.balances.insert((*caller, token), new_balance);
                    idx += 1;
                }
            }
        }
    }

    fn notify_end(
        &mut self,
        _ctx: &mut OracleCtx<
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
    ) {
        self.balances.clear();
    }
}
