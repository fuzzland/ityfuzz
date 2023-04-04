use crate::evm::abi::{BoxedABI, A256};
use crate::evm::input::{EVMInput, EVMInputT};
use crate::evm::mutator::AccessPattern;
use crate::evm::onchain::endpoints::OnChainConfig;
use crate::evm::onchain::flashloan::FlashloanData;
use crate::evm::types::{EVMFuzzState, EVMOracleCtx};
use crate::evm::uniswap::{liquidate_all_token, reserve_parser, PairContext, TokenContext};
use crate::evm::vm::EVMState;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::oracle::{Oracle, OracleCtx};
use crate::state::{FuzzState, HasExecutionResult, HasInfantStateState};
use crate::state_input::StagedVMState;
use bytes::Bytes;
use libafl::state::HasMetadata;
use primitive_types::{H160, U256, U512};
use revm::Bytecode;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

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
            let balance_of_txn =
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
}

impl IERC20OracleFlashloan {
    pub fn new() -> Self {
        Self {
            balance_of: hex::decode("70a08231").unwrap(),
            #[cfg(feature = "flashloan_v2")]
            known_tokens: HashMap::new(),
        }
    }

    #[cfg(feature = "flashloan_v2")]
    pub fn register_token(&mut self, token: H160, token_ctx: TokenContext) {
        self.known_tokens.insert(token, token_ctx);
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
        use std::time::Instant;
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

        let mut new_reserves = prev_reserves.clone();

        for pair_address in reserves {
            let reserve_slot = ctx
                .fuzz_state
                .get_execution_result()
                .new_state
                .state
                .get(&pair_address)
                .expect("Pair not found")
                .get(&U256::from(8))
                .expect("Reserve not found");

            new_reserves.insert(pair_address, reserve_parser(reserve_slot));
        }

        let caller = ctx.input.get_caller();

        let mut liquidations_owed = Vec::new();
        let mut liquidations_earned = Vec::new();

        for token in tokens {
            let mut extended_address = vec![0; 12];
            extended_address.extend_from_slice(caller.0.as_slice());
            let mut abi = BoxedABI::new(Box::new(A256 {
                data: extended_address,
                is_address: false,
            }));
            abi.function.copy_from_slice(self.balance_of.as_slice());

            let res_pre = ctx.call_pre(&mut EVMInput {
                caller: Default::default(),
                contract: token,
                data: Some(abi.clone()),
                sstate: StagedVMState::new_uninitialized(),
                sstate_idx: 0,
                txn_value: None,
                step: false,
                env: Default::default(),
                access_pattern: ctx.input.get_access_pattern().clone(),
                #[cfg(any(test, feature = "debug"))]
                direct_data: Default::default(),
            });

            let res_post = ctx.call_post(&mut EVMInput {
                caller: Default::default(),
                contract: token,
                data: Some(abi),
                sstate: StagedVMState::new_uninitialized(),
                sstate_idx: 0,
                txn_value: None,
                step: false,
                env: Default::default(),
                access_pattern: ctx.input.get_access_pattern().clone(),
                #[cfg(any(test, feature = "debug"))]
                direct_data: Default::default(),
            });

            let new_balance = U256::from(res_post.output.as_slice());
            let prev_balance = U256::from(res_pre.output.as_slice());

            let token_info = self.known_tokens.get(&token).expect("Token not found");

            if prev_balance > new_balance {
                liquidations_owed.push((token_info, prev_balance - new_balance));
            } else if prev_balance < new_balance {
                liquidations_earned.push((token_info, new_balance - prev_balance));
            }
        }

        let exec_res = ctx.fuzz_state.get_execution_result_mut();
        exec_res.new_state.state.flashloan_data.prev_reserves = new_reserves.clone();

        let liquidation_owed = liquidate_all_token(liquidations_owed, prev_reserves);
        let liquidation_earned = liquidate_all_token(liquidations_earned, new_reserves);

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
            unsafe {
                FL_DATA = format!(
                    "[Flashloan] Earned {} more than owed {}",
                    exec_res.new_state.state.flashloan_data.earned,
                    exec_res.new_state.state.flashloan_data.owed
                );
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
        if stage == 99 {
            let harness_txn = Bytes::from(self.harness_func.clone());
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
