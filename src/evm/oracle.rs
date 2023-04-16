use std::collections::HashMap;
use crate::evm::input::{EVMInput, EVMInputT};



use crate::evm::types::{EVMFuzzState, EVMOracleCtx};

use crate::evm::vm::EVMState;


use crate::oracle::{Oracle, OracleCtx};
use crate::state::{HasExecutionResult};

use bytes::Bytes;

use primitive_types::{H160, U256, U512};
use revm::Bytecode;
use crate::evm::uniswap::{liquidate_all_token, TokenContext};


pub struct NoOracle {}

impl Oracle<EVMState, H160, Bytecode, Bytes, H160, U256, Vec<u8>, EVMInput, EVMFuzzState>
    for NoOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> bool {
        false
    }
}

pub struct IERC20Oracle {
    pub address: H160,
    pub precondition: fn(ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64,

    balance_of: Vec<u8>,
}

pub fn dummy_precondition(_ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
    99
}

impl IERC20Oracle {
    pub fn new(
        address: H160,
        precondition: fn(ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64,
    ) -> Self {
        Self {
            address,
            precondition,
            balance_of: hex::decode("70a08231").unwrap(),
        }
    }

    pub fn new_no_condition(address: H160) -> Self {
        Self {
            address,
            precondition: dummy_precondition,
            balance_of: hex::decode("70a08231").unwrap(),
        }
    }
}

impl Oracle<EVMState, H160, Bytecode, Bytes, H160, U256, Vec<u8>, EVMInput, EVMFuzzState>
    for IERC20Oracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        (self.precondition)(_ctx, _stage)
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> bool {
        if _stage == 99 {
            let _balance_of_txn =
                Bytes::from([self.balance_of.clone(), ctx.input.caller.0.to_vec()].concat());

            // get caller balance
            // let pre_balance = _ctx
            //     .call_pre(self.address, _ctx.input.caller, balance_of_txn.clone())
            //     .output;
            //
            // let post_balance = _ctx
            //     .call_post(self.address, _ctx.input.caller, balance_of_txn)
            //     .output;
            // has balance increased?
            // post_balance > pre_balance
            false
        } else {
            false
        }
    }
}

pub struct IERC20OracleFlashloan {
    pub balance_of: Vec<u8>,
    #[cfg(feature = "flashloan_v2")]
    pub known_tokens: HashMap<H160, TokenContext>,
    #[cfg(feature = "flashloan_v2")]
    pub known_pair_reserve_slot: HashMap<H160, U256>,
}

impl IERC20OracleFlashloan {
    pub fn new() -> Self {
        Self {
            balance_of: hex::decode("70a08231").unwrap(),
            #[cfg(feature = "flashloan_v2")]
            known_tokens: HashMap::new(),
            #[cfg(feature = "flashloan_v2")]
            known_pair_reserve_slot: HashMap::new(),
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

pub static mut FL_DATA: String = String::new();

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
                FL_DATA = format!(
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
            new_reserves.insert(pair_address, (reserve0, reserve1));
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
        for caller in &callers {
            let mut extended_address = vec![0; 12];
            extended_address.extend_from_slice(caller.0.as_slice());
            let call_data = Bytes::from([self.balance_of.clone(), extended_address].concat());

            for token in &tokens {
                let token = *token;
                let res_pre = ctx.call_pre(token, call_data.clone());

                let res_post = ctx.call_post(token, call_data.clone());

                let new_balance = U256::from(res_post.as_slice());
                let prev_balance = U256::from(res_pre.as_slice());

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
            liquidations_earned.push((token_info, liq));
            exec_res
                .new_state
                .state
                .flashloan_data
                .unliquidated_tokens
                .insert(*token, *amount - liq);
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
                    FL_DATA = format!(
                        "💰[Flashloan] Earned {} more than owed {}, net earned = {}wei ({}ETH)",
                        exec_res.new_state.state.flashloan_data.earned,
                        exec_res.new_state.state.flashloan_data.owed,
                        net,
                        net_eth
                    );
                }

                #[cfg(feature = "debug")]
                {
                    FL_DATA = format!(
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

pub struct FunctionHarnessOracle {
    pub address: H160,
    harness_func: Vec<u8>,
    precondition: fn(ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64,
}

impl FunctionHarnessOracle {
    pub fn new(
        address: H160,
        harness_func: Vec<u8>,
        precondition: fn(ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64,
    ) -> Self {
        Self {
            address,
            harness_func,
            precondition,
        }
    }

    pub fn new_no_condition(address: H160, harness_func: Vec<u8>) -> Self {
        Self {
            address,
            precondition: dummy_precondition,
            harness_func,
        }
    }
}

impl Oracle<EVMState, H160, Bytecode, Bytes, H160, U256, Vec<u8>, EVMInput, EVMFuzzState>
    for FunctionHarnessOracle
{
    fn transition(&self, ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64 {
        (self.precondition)(ctx, stage)
    }

    fn oracle(
        &self,
        _ctx: &mut OracleCtx<
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
        if stage == 99 {
            let _harness_txn = Bytes::from(self.harness_func.clone());
            // let res = ctx
            //     .call_post(
            //         if self.address.is_zero() {
            //             ctx.input.contract
            //         } else {
            //             self.address
            //         },
            //         ctx.input.caller,
            //         harness_txn,
            //     )
            //     .output;
            // !res.iter().map(|x| *x == 0).all(|x| x)
            false
        } else {
            false
        }
    }
}
