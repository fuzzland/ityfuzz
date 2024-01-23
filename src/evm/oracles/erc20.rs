use std::{cell::RefCell, collections::HashMap, ops::Deref, rc::Rc};

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        onchain::flashloan::CAN_LIQUIDATE,
        oracle::EVMBugResult,
        oracles::{u512_div_float, ERC20_BUG_IDX},
        producers::erc20::ERC20Producer,
        tokens::TokenContext,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256, EVMU512},
        vm::EVMState,
    },
    generic_vm::vm_state::VMStateT,
    oracle::Oracle,
    state::HasExecutionResult,
};

pub struct IERC20OracleFlashloan {
    pub balance_of: Vec<u8>,
    pub known_tokens: HashMap<EVMAddress, TokenContext>,
    pub known_pair_reserve_slot: HashMap<EVMAddress, EVMU256>,
    pub erc20_producer: Rc<RefCell<ERC20Producer>>,
}

impl IERC20OracleFlashloan {
    pub fn new(erc20_producer: Rc<RefCell<ERC20Producer>>) -> Self {
        Self {
            balance_of: hex::decode("70a08231").unwrap(),
            known_tokens: HashMap::new(),
            known_pair_reserve_slot: HashMap::new(),
            erc20_producer,
        }
    }

    pub fn register_token(&mut self, token: EVMAddress, token_ctx: TokenContext, can_liquidate: bool) {
        // setting can_liquidate to true to turn on liquidation
        unsafe {
            CAN_LIQUIDATE |= can_liquidate;
        }
        self.known_tokens.insert(token, token_ctx);
    }

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
        EVMQueueExecutor,
    > for IERC20OracleFlashloan
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        use crate::evm::input::EVMInputT;
        ctx.fuzz_state
            .get_execution_result_mut()
            .new_state
            .state
            .flashloan_data
            .oracle_recheck_balance
            .clear();
        ctx.fuzz_state
            .get_execution_result_mut()
            .new_state
            .state
            .flashloan_data
            .oracle_recheck_reserve
            .clear();
        let liquidation_percent = ctx.input.get_liquidation_percent();
        if liquidation_percent > 0 {
            // println!("Liquidation percent: {}", liquidation_percent);
            let liquidation_percent = EVMU256::from(liquidation_percent);
            let mut liquidations_earned = Vec::new();

            for ((caller, token), new_balance) in self.erc20_producer.deref().borrow().balances.iter() {
                // println!("token: {:?}, user: {:?}, new_balance: {:?}", token, caller,
                // new_balance);
                if *new_balance > EVMU256::ZERO &&
                    let Some(token_info) = self.known_tokens.get(token)
                {
                    let liq_amount = *new_balance * liquidation_percent / EVMU256::from(10);
                    liquidations_earned.push((*caller, token_info, liq_amount));
                }
            }

            let _path_idx = ctx.input.get_randomness()[0] as usize;

            {
                ctx.executor.deref().borrow_mut().host.evmstate = ctx.post_state.clone();
            }
            let mut failed = false;
            for (caller, _token_info, _amount) in liquidations_earned {
                let backup = ctx.executor.deref().borrow_mut().host.evmstate.clone();
                if _token_info
                    .sell(
                        _amount,
                        caller,
                        ctx.fuzz_state,
                        &mut *ctx.executor.deref().borrow_mut(),
                        ctx.input.get_randomness().as_slice(),
                    )
                    .is_none()
                {
                    ctx.executor.deref().borrow_mut().host.evmstate = backup;
                    continue;
                }
            }
            if !failed {
                ctx.fuzz_state.get_execution_result_mut().new_state.state =
                    ctx.executor.deref().borrow_mut().host.evmstate.clone();
            }
        }

        let exec_res = ctx.fuzz_state.get_execution_result_mut();

        if exec_res.new_state.state.has_post_execution() {
            return vec![];
        }

        // println!(
        //     "balance: {:?} - {:?}",
        //     exec_res.new_state.state.flashloan_data.earned,
        // exec_res.new_state.state.flashloan_data.owed );

        if exec_res.new_state.state.flashloan_data.earned > exec_res.new_state.state.flashloan_data.owed &&
            exec_res.new_state.state.flashloan_data.earned - exec_res.new_state.state.flashloan_data.owed >
                EVMU512::from(10_000_000_000_000_000_000_000_u128)
        // > 0.01ETH
        {
            let net = exec_res.new_state.state.flashloan_data.earned - exec_res.new_state.state.flashloan_data.owed;
            // we scaled by 1e24, so divide by 1e24 to get ETH
            let net_eth = u512_div_float(net, EVMU512::from(1_000_000_000_000_000_000_000_u128), 3);

            EVMBugResult::new_simple(
                "Fund Loss".to_string(),
                ERC20_BUG_IDX,
                format!(
                    "Anyone can earn {} ETH by interacting with the provided contracts\n",
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
