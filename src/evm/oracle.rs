use crate::evm::input::EVMInput;
use crate::evm::onchain::flashloan::FlashloanData;
use crate::evm::types::{EVMFuzzState, EVMOracleCtx};
use crate::evm::vm::EVMState;
use crate::generic_vm::vm_state::VMStateT;
use crate::oracle::{Oracle, OracleCtx};
use crate::state::{FuzzState, HasExecutionResult, HasInfantStateState};
use bytes::Bytes;
use libafl::state::HasMetadata;
use primitive_types::{H160, U256, U512};
use revm::Bytecode;
use crate::evm::abi::{A256, BoxedABI};
use crate::input::VMInputT;
use crate::state_input::StagedVMState;

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
}

impl IERC20OracleFlashloan {

    pub fn new() -> Self {
        Self {
            balance_of: hex::decode("70a08231").unwrap(),
        }
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
        if ctx.post_state.flashloan_data.earned > ctx.post_state.flashloan_data.owed {
            unsafe {
                FL_DATA = format!(
                    "[Flashloan] Earned {} more than owed {}",
                    ctx.post_state.flashloan_data.earned, ctx.post_state.flashloan_data.owed
                );
            }
            true
        } else {
            false
        }
    }

    #[cfg(feature = "flashloan_v2")]
    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> bool {
        let need_recheck = ctx.fuzz_state.get_execution_result().new_state.state.flashloan_data.oracle_recheck_balance.clone();
        let zero = U256::zero();
        let caller = ctx.input.get_caller();
        for token in need_recheck {
            let mut extended_address = vec![0; 12];
            extended_address.extend_from_slice(caller.0.as_slice());
            let mut abi = BoxedABI::new(Box::new(
                A256 {
                    data: extended_address,
                    is_address: false
                }
            ));
            abi.function.copy_from_slice(self.balance_of.as_slice());
            let res = ctx.call_post(&mut EVMInput {
                caller: Default::default(),
                contract: token,
                data: Some(abi),
                sstate: StagedVMState::new_uninitialized(),
                sstate_idx: 0,
                txn_value: None,
                step: false,
                #[cfg(test)]
                direct_data: Default::default()
            });
            let exec_res = ctx.fuzz_state.get_execution_result_mut();
            let new_balance = U256::from(res.output.as_slice());
            let prev_balance = exec_res.new_state.state.flashloan_data.account_balances.get(&token).unwrap_or(&zero);

            if new_balance > *prev_balance {
                exec_res.new_state.state.flashloan_data.earned += U512::from(new_balance - *prev_balance);
                println!("{} earned {} more", token, new_balance - *prev_balance);
            } else {
                exec_res.new_state.state.flashloan_data.owed += U512::from(*prev_balance - new_balance);
                println!("{} owed {} more", token, *prev_balance - new_balance);
            }

            exec_res.new_state.state.flashloan_data.account_balances.insert(token, new_balance);
        };

        let exec_res = ctx.fuzz_state.get_execution_result_mut();
        exec_res.new_state.state.flashloan_data.oracle_recheck_balance.clear();
        exec_res.new_state.state.flashloan_data.earned > exec_res.new_state.state.flashloan_data.owed
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
