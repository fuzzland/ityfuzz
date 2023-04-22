use crate::evm::input::{EVMInput, EVMInputT};
use crate::evm::producers::pair::PairProducer;
use crate::evm::types::{EVMFuzzState, EVMOracleCtx};
use crate::evm::uniswap::{liquidate_all_token, TokenContext};
use crate::evm::vm::EVMState;
use crate::oracle::Oracle;
use crate::state::HasExecutionResult;
use bytes::Bytes;
use primitive_types::{H160, U256, U512};
use revm::Bytecode;
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Deref;
use std::rc::Rc;

pub struct IERC20OracleFlashloan {
    pub balance_of: Vec<u8>,
    #[cfg(feature = "flashloan_v2")]
    pub known_tokens: HashMap<H160, TokenContext>,
    #[cfg(feature = "flashloan_v2")]
    pub known_pair_reserve_slot: HashMap<H160, U256>,
    #[cfg(feature = "flashloan_v2")]
    pub pair_producer: Rc<RefCell<PairProducer>>,
}

impl IERC20OracleFlashloan {
    #[cfg(not(feature = "flashloan_v2"))]
    pub fn new(_: Rc<RefCell<PairProducer>>) -> Self {
        Self {
            balance_of: hex::decode("70a08231").unwrap(),
        }
    }

    #[cfg(feature = "flashloan_v2")]
    pub fn new(pair_producer: Rc<RefCell<PairProducer>>) -> Self {
        Self {
            balance_of: hex::decode("70a08231").unwrap(),
            known_tokens: HashMap::new(),
            known_pair_reserve_slot: HashMap::new(),
            pair_producer,
        }
    }

    #[cfg(feature = "flashloan_v2")]
    pub fn register_token(&mut self, token: H160, token_ctx: TokenContext) {
        self.known_tokens.insert(token, token_ctx);
    }

    #[cfg(feature = "flashloan_v2")]
    pub fn register_pair_reserve_slot(&mut self, pair: H160, slot: U256) {
        self.known_pair_reserve_slot.insert(pair, slot);
    }
}

pub static mut ORACLE_OUTPUT: String = String::new();

impl Oracle<EVMState, H160, Bytecode, Bytes, H160, U256, Vec<u8>, EVMInput, EVMFuzzState>
    for IERC20OracleFlashloan
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    #[cfg(not(feature = "flashloan_v2"))]
    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> bool {
        // has balance increased?
        let exec_res = &ctx.fuzz_state.get_execution_result().new_state.state;
        if exec_res.flashloan_data.earned > exec_res.flashloan_data.owed {
            unsafe {
                ORACLE_OUTPUT = format!(
                    "[Flashloan] Earned {} more than owed {}",
                    exec_res.flashloan_data.earned, exec_res.flashloan_data.owed
                );
            }
            true
        } else {
            false
        }
    }

    #[cfg(feature = "flashloan_v2")]
    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> bool {
        let tokens = ctx
            .fuzz_state
            .get_execution_result()
            .new_state
            .state
            .flashloan_data
            .oracle_recheck_balance
            .clone();
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
        let unliquidated_tokens = ctx
            .fuzz_state
            .get_execution_result()
            .new_state
            .state
            .flashloan_data
            .unliquidated_tokens
            .clone();
        let callers = ctx.fuzz_state.callers_pool.clone();

        let mut new_reserves = prev_reserves.clone();

        for (pair_address, reserve) in &self.pair_producer.deref().borrow().reserves {
            new_reserves.insert(*pair_address, *reserve);
        }

        let mut liquidations_owed = Vec::new();
        let mut liquidations_earned = Vec::new();

        #[cfg(feature = "debug")]
        {
            // ctx.fuzz_state
            //     .get_execution_result_mut()
            //     .new_state
            //     .state
            //     .flashloan_data
            //     .extra_info += format!("\n\n\n\n=========== New =============\n").as_str();
        }
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


        for _ in &callers {
            for token in &tokens {
                let token = *token;
                let post_balance = &post_balance_res[idx];
                let pre_balance = &pre_balance_res[idx];
                let new_balance = U256::try_from(post_balance.as_slice()).unwrap_or(U256::zero());
                let prev_balance = U256::try_from(pre_balance.as_slice()).unwrap_or(U256::zero());
                let token_info = self.known_tokens.get(&token).expect("Token not found");
                // ctx.fuzz_state.get_execution_result_mut().new_state.state.flashloan_data.extra_info += format!("Balance: {} -> {} for {:?} @ {:?}\n", prev_balance, new_balance, caller, token).as_str();

                if prev_balance > new_balance {
                    liquidations_owed.push((token_info, prev_balance - new_balance));
                } else if prev_balance < new_balance {
                    let to_liquidate = (new_balance - prev_balance)
                        * U256::from(ctx.input.get_liquidation_percent())
                        / U256::from(10);

                    let unliquidated = new_balance - prev_balance - to_liquidate;
                    if to_liquidate > U256::from(0) {
                        liquidations_earned.push((token_info, to_liquidate));
                    }
                    // insert if not exists or increase if exists
                    if unliquidated > U256::from(0) {
                        let entry = ctx
                            .fuzz_state
                            .get_execution_result_mut()
                            .new_state
                            .state
                            .flashloan_data
                            .unliquidated_tokens
                            .entry(token)
                            .or_insert(U256::from(0));
                        *entry += unliquidated;
                    }
                }
            }
        }

        let exec_res = ctx.fuzz_state.get_execution_result_mut();

        let (liquidation_owed, _) =
            liquidate_all_token(liquidations_owed.clone(), prev_reserves.clone());
        #[cfg(feature = "debug")]
        {
            // exec_res.new_state.state.flashloan_data.extra_info += format!(
            //     "Liquidations owed: {:?} total: {}, old_reserve: {:?}\n",
            //     liquidations_owed, liquidation_owed, prev_reserves
            // )
            // .as_str();
        }

        unliquidated_tokens.iter().for_each(|(token, amount)| {
            let token_info = self.known_tokens.get(token).expect("Token not found");
            let liq = *amount * U256::from(ctx.input.get_liquidation_percent()) / U256::from(10);
            if liq != U256::from(0) {
                liquidations_earned.push((token_info, liq));
                exec_res
                    .new_state
                    .state
                    .flashloan_data
                    .unliquidated_tokens
                    .insert(*token, *amount - liq);
            }
        });

        let (liquidation_earned, adjusted_reserves) =
            liquidate_all_token(liquidations_earned, new_reserves);

        // println!("Liquidation earned: {}", liquidation_earned);
        exec_res.new_state.state.flashloan_data.prev_reserves = adjusted_reserves;

        if liquidation_earned > liquidation_owed {
            exec_res.new_state.state.flashloan_data.earned +=
                U512::from(liquidation_earned - liquidation_owed);
        } else {
            exec_res.new_state.state.flashloan_data.owed +=
                U512::from(liquidation_owed - liquidation_earned);
        }

        exec_res
            .new_state
            .state
            .flashloan_data
            .oracle_recheck_balance
            .clear();
        exec_res
            .new_state
            .state
            .flashloan_data
            .oracle_recheck_reserve
            .clear();

        if exec_res.new_state.state.flashloan_data.earned
            > exec_res.new_state.state.flashloan_data.owed
        {
            let net = exec_res.new_state.state.flashloan_data.earned
                - exec_res.new_state.state.flashloan_data.owed;
            // we scaled by 1e23, so divide by 1e23 to get ETH
            let net_eth = net / U512::from(1_000_000_000_000_000_000_000_00u128);
            unsafe {
                #[cfg(not(feature = "debug"))]
                {
                    ORACLE_OUTPUT = format!(
                        "💰[Flashloan] Earned {} more than owed {}, net earned = {}wei ({}ETH)",
                        exec_res.new_state.state.flashloan_data.earned,
                        exec_res.new_state.state.flashloan_data.owed,
                        net,
                        net_eth
                    );
                }

                #[cfg(feature = "debug")]
                {
                    ORACLE_OUTPUT = format!(
                        "💰[Flashloan] Earned {} more than owed {}, net earned = {}wei ({}ETH), extra: {:?}",
                        exec_res.new_state.state.flashloan_data.earned,
                        exec_res.new_state.state.flashloan_data.owed,
                        net,
                        net_eth,
                        exec_res.new_state.state.flashloan_data.extra_info
                    );
                }
            }
            true
        } else {
            false
        }
    }
}
