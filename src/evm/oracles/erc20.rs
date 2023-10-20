use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::oracle::EVMBugResult;
use crate::evm::oracles::ERC20_BUG_IDX;
use crate::evm::producers::erc20::ERC20Producer;
use crate::evm::producers::pair::PairProducer;
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256, EVMU512};
#[cfg(feature = "flashloan_v2")]
use crate::evm::uniswap::TokenContext;
use crate::evm::vm::EVMState;
use crate::oracle::Oracle;
use crate::state::HasExecutionResult;
use bytes::Bytes;
use revm_primitives::Bytecode;
use std::cell::RefCell;
#[cfg(feature = "flashloan_v2")]
use std::collections::HashMap;
#[cfg(feature = "flashloan_v2")]
use std::ops::Deref;
use std::rc::Rc;

#[cfg(not(feature = "flashloan_v2"))]
pub struct IERC20OracleFlashloan {
    pub balance_of: Vec<u8>,
}

#[cfg(feature = "flashloan_v2")]
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
    pub fn new(
        pair_producer: Rc<RefCell<PairProducer>>,
        erc20_producer: Rc<RefCell<ERC20Producer>>,
    ) -> Self {
        Self {
            balance_of: hex::decode("70a08231").unwrap(),
            known_tokens: HashMap::new(),
            known_pair_reserve_slot: HashMap::new(),
            pair_producer,
            erc20_producer,
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

impl
    Oracle<
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
    > for IERC20OracleFlashloan
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    #[cfg(not(feature = "flashloan_v2"))]
    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        // has balance increased?
        let exec_res = &ctx.fuzz_state.get_execution_result().new_state.state;
        if exec_res.flashloan_data.earned > exec_res.flashloan_data.owed {
            EVMBugResult::new_simple(
                "erc20".to_string(),
                ERC20_BUG_IDX,
                format!(
                    "Earned {}wei more than owed {}wei",
                    exec_res.flashloan_data.earned, exec_res.flashloan_data.owed
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            vec![ERC20_BUG_IDX]
        } else {
            vec![]
        }
    }

    #[cfg(feature = "flashloan_v2")]
    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        use crate::evm::{input::EVMInputT, uniswap::generate_uniswap_router_sell};

        let liquidation_percent = ctx.input.get_liquidation_percent();
        if liquidation_percent > 0 {
            let liquidation_percent = EVMU256::from(liquidation_percent);
            let mut liquidations_earned = Vec::new();

            for ((caller, token), (prev_balance, new_balance)) in
                self.erc20_producer.deref().borrow().balances.iter()
            {
                let token_info = self.known_tokens.get(token).expect("Token not found");

                #[cfg(feature = "flashloan_debug")]
                println!(
                    "Balance: {} -> {} for {:?} @ {:?}",
                    prev_balance, new_balance, caller, token
                );

                if *new_balance > EVMU256::ZERO {
                    let liq_amount = *new_balance * liquidation_percent / EVMU256::from(10);
                    liquidations_earned.push((*caller, token_info, liq_amount));
                }
            }

            let path_idx = ctx.input.get_randomness()[0] as usize;

            let mut liquidation_txs = vec![];

            // println!("Liquidations earned: {:?}", liquidations_earned);
            for (caller, token_info, amount) in liquidations_earned {
                let txs = generate_uniswap_router_sell(
                    token_info,
                    path_idx,
                    amount,
                    ctx.fuzz_state.callers_pool[0],
                );
                if txs.is_none() {
                    continue;
                }

                liquidation_txs.extend(
                    txs.unwrap()
                        .iter()
                        .map(|(abi, _, addr)| (caller, *addr, Bytes::from(abi.get_bytes()))),
                );
            }
            // println!(
            //     "Liquidation txs: {:?}",
            //     liquidation_txs
            // );

            // println!("Earned before liquidation: {:?}", ctx.fuzz_state.get_execution_result().new_state.state.flashloan_data.earned);
            let (_out, state) = ctx.call_post_batch_dyn(&liquidation_txs);
            // println!("results: {:?}", out);
            // println!("result state: {:?}", state.flashloan_data);
            ctx.fuzz_state.get_execution_result_mut().new_state.state = state;
        }

        let exec_res = ctx.fuzz_state.get_execution_result_mut();
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
            && exec_res.new_state.state.flashloan_data.earned
                - exec_res.new_state.state.flashloan_data.owed
                > EVMU512::from(100_000_000_000_000_000_000_000_u128)
        // > 0.1ETH
        {
            let net = exec_res.new_state.state.flashloan_data.earned
                - exec_res.new_state.state.flashloan_data.owed;
            // we scaled by 1e24, so divide by 1e24 to get ETH
            let net_eth = net / EVMU512::from(1_000_000_000_000_000_000_000_000_u128);
            EVMBugResult::new_simple(
                "erc20".to_string(),
                ERC20_BUG_IDX,
                format!(
                    "Earned {} more than owed {}, net earned = {}wei ({}ETH)\n",
                    exec_res.new_state.state.flashloan_data.earned,
                    exec_res.new_state.state.flashloan_data.owed,
                    net,
                    net_eth,
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            vec![ERC20_BUG_IDX]
        } else {
            vec![]
        }
    }
}
