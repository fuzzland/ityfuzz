use crate::evm::input::EVMInput;
use crate::evm::types::EVMFuzzState;
use crate::evm::vm::EVMState;
use crate::oracle::{OracleCtx, Producer};
use crate::state::HasExecutionResult;
use bytes::Bytes;
use primitive_types::{H160, U256};
use revm::Bytecode;
use std::collections::HashMap;

pub struct ERC20Producer {
    pub prev_balances: HashMap<(H160, H160), U256>,
    pub post_balances: HashMap<(H160, H160), U256>,
    pub balance_of: Vec<u8>,
}

impl ERC20Producer {
    pub fn new() -> Self {
        Self {
            prev_balances: HashMap::new(),
            post_balances: HashMap::new(),
            balance_of: hex::decode("70a08231").unwrap(),
        }
    }
}

impl Producer<EVMState, H160, Bytecode, Bytes, H160, U256, Vec<u8>, EVMInput, EVMFuzzState>
    for ERC20Producer
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
            let tokens = ctx
                .fuzz_state
                .get_execution_result()
                .new_state
                .state
                .flashloan_data
                .oracle_recheck_balance
                .clone();

            let callers = ctx.fuzz_state.callers_pool.clone();
            let query_balance_batch = callers.iter().map(
                |caller| {
                    let mut extended_address = vec![0; 12];
                    extended_address.extend_from_slice(caller.0.as_slice());
                    let call_data = Bytes::from([self.balance_of.clone(), extended_address].concat());
                    tokens.iter().map(
                        |token| {
                            (*token, call_data.clone())
                        }
                    ).collect::<Vec<(H160, Bytes)>>()
                }
            ).flatten().collect::<Vec<(H160, Bytes)>>();
            let post_balance_res = ctx.call_post_batch(&query_balance_batch);
            let pre_balance_res = ctx.call_pre_batch(&query_balance_batch);

            let mut idx = 0;

            for caller in &callers {
                for token in &tokens {
                    let token = *token;
                    let post_balance = &post_balance_res[idx];
                    let pre_balance = &pre_balance_res[idx];
                    let new_balance = U256::try_from(post_balance.as_slice()).unwrap_or(U256::zero());
                    let prev_balance = U256::try_from(pre_balance.as_slice()).unwrap_or(U256::zero());

                    self.prev_balances.insert((*caller, token), prev_balance);
                    self.post_balances.insert((*caller, token), new_balance);
                    idx += 1;
                }
            }
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
        self.prev_balances.clear();
        self.post_balances.clear();
    }
}
