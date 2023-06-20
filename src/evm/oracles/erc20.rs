use crate::evm::input::{EVMInput, EVMInputT};
use crate::evm::producers::pair::PairProducer;
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256, EVMU512};
use crate::evm::uniswap::{liquidate_all_token, TokenContext};
use crate::evm::vm::EVMState;
use crate::oracle::Oracle;
use crate::state::HasExecutionResult;
use bytes::Bytes;
use revm_primitives::Bytecode;
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Deref;
use std::rc::Rc;
use crate::evm::producers::erc20::ERC20Producer;

pub struct IERC20OracleFlashloan {
    pub balance_of: Vec<u8>,
    #[cfg(feature = "flashloan_v2")]
    pub known_tokens: HashMap<EVMAddress, TokenContext>,
    #[cfg(feature = "flashloan_v2")]
    pub known_pair_reserve_slot: HashMap<EVMAddress, EVMU256>,
    #[cfg(feature = "flashloan_v2")]
    pub pair_producer: Rc<RefCell<PairProducer>>,
    #[cfg(feature = "flashloan_v2")]
    pub erc20_producer: Rc<RefCell<ERC20Producer>>,
}

impl IERC20OracleFlashloan {
    #[cfg(not(feature = "flashloan_v2"))]
    pub fn new(_: Rc<RefCell<PairProducer>>, _: Rc<RefCell<ERC20Producer>>) -> Self {
        Self {
            balance_of: hex::decode("70a08231").unwrap(),
        }
    }

    #[cfg(feature = "flashloan_v2")]
    pub fn new(pair_producer: Rc<RefCell<PairProducer>>, erc20_producer: Rc<RefCell<ERC20Producer>>) -> Self {
        Self {
            balance_of: hex::decode("70a08231").unwrap(),
            known_tokens: HashMap::new(),
            known_pair_reserve_slot: HashMap::new(),
            pair_producer,
            erc20_producer
        }
    }

    #[cfg(feature = "flashloan_v2")]
    pub fn register_token(&mut self, token: EVMAddress, token_ctx: TokenContext) {
        self.known_tokens.insert(token, token_ctx);
    }

    #[cfg(feature = "flashloan_v2")]
    pub fn register_pair_reserve_slot(&mut self, pair: EVMAddress, slot: EVMU256) {
        self.known_pair_reserve_slot.insert(pair, slot);
    }
}

pub static mut ORACLE_OUTPUT: String = String::new();

impl Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState>
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

        let mut new_reserves = prev_reserves.clone();

        for (pair_address, reserve) in &self.pair_producer.deref().borrow().reserves {
            new_reserves.insert(*pair_address, *reserve);
        }

        let mut liquidations_owed = Vec::new();
        let mut liquidations_earned = Vec::new();

        for ((_, token), (prev_balance, new_balance)) in self.erc20_producer.deref().borrow().balances.iter() {
            let token_info = self.known_tokens.get(token).expect("Token not found");
            // ctx.fuzz_state.get_execution_result_mut().new_state.state.flashloan_data.extra_info += format!("Balance: {} -> {} for {:?} @ {:?}\n", prev_balance, new_balance, caller, token).as_str();

            if prev_balance > new_balance {
                liquidations_owed.push((token_info, prev_balance - new_balance));
            } else if prev_balance < new_balance {
                let to_liquidate = (new_balance - prev_balance)
                    * EVMU256::from(ctx.input.get_liquidation_percent())
                    / EVMU256::from(10);

                let unliquidated = new_balance - prev_balance - to_liquidate;
                if to_liquidate > EVMU256::from(0) {
                    liquidations_earned.push((token_info, to_liquidate));
                }
                // insert if not exists or increase if exists
                if unliquidated > EVMU256::from(0) {
                    let entry = ctx
                        .fuzz_state
                        .get_execution_result_mut()
                        .new_state
                        .state
                        .flashloan_data
                        .unliquidated_tokens
                        .entry(*token)
                        .or_insert(EVMU256::from(0));
                    *entry += unliquidated;
                }
            }
        }
        let exec_res = ctx.fuzz_state.get_execution_result_mut();

        let (liquidation_owed, _) =
            liquidate_all_token(liquidations_owed.clone(), prev_reserves.clone());

        unliquidated_tokens.iter().for_each(|(token, amount)| {
            let token_info = self.known_tokens.get(token).expect("Token not found");
            let liq = *amount * EVMU256::from(ctx.input.get_liquidation_percent()) / EVMU256::from(10);
            if liq != EVMU256::from(0) {
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
                EVMU512::from(liquidation_earned - liquidation_owed);
        } else {
            exec_res.new_state.state.flashloan_data.owed +=
                EVMU512::from(liquidation_owed - liquidation_earned);
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
            // we scaled by 1e24, so divide by 1e24 to get ETH
            let net_eth = net / EVMU512::from(10_000_000_000_000_000_000_000_00u128);
            unsafe {


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
