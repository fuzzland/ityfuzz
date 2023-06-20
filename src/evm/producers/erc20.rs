use crate::evm::input::EVMInput;
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMU256};
use crate::evm::vm::EVMState;
use crate::oracle::{OracleCtx, Producer};
use crate::state::HasExecutionResult;
use bytes::Bytes;
use revm_primitives::Bytecode;
use std::collections::HashMap;

pub struct ERC20Producer {
    // (caller, token) -> (pre_balance, post_balance)
    pub balances: HashMap<(EVMAddress, EVMAddress), (EVMU256, EVMU256)>,
    pub balance_of: Vec<u8>,
}

impl ERC20Producer {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
            balance_of: hex::decode("70a08231").unwrap(),
        }
    }
}

impl Producer<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState>
    for ERC20Producer
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
                    ).collect::<Vec<(EVMAddress, Bytes)>>()
                }
            ).flatten().collect::<Vec<(EVMAddress, Bytes)>>();
            let post_balance_res = ctx.call_post_batch(&query_balance_batch);
            let pre_balance_res = ctx.call_pre_batch(&query_balance_batch);

            let mut idx = 0;

            for caller in &callers {
                for token in &tokens {
                    let token = *token;
                    let pre_balance = &pre_balance_res[idx];
                    let post_balance = &post_balance_res[idx];
                    let prev_balance = EVMU256::try_from_be_slice(pre_balance.as_slice()).unwrap_or(EVMU256::ZERO);
                    let new_balance = EVMU256::try_from_be_slice(post_balance.as_slice()).unwrap_or(EVMU256::ZERO);

                    self.balances.insert((*caller, token), (prev_balance, new_balance));
                    idx += 1;
                }
            }
        }
    }

    fn notify_end(
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
        >,
    ) {
        self.balances.clear();
    }
}
