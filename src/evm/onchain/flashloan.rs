// on_call
// when approval, balanceof, give 2000e18 token
// when transfer, transferFrom, and src is our, return success, add owed
// when transfer, transferFrom, and src is not our, return success, reduce owed

use crate::evm::middleware::{CanHandleDeferredActions, Middleware, MiddlewareOp, MiddlewareType};
use crate::evm::onchain::endpoints::{OnChainConfig, PriceOracle};
use crate::evm::vm::IntermediateExecutionResult;
use crate::generic_vm::vm_state::VMStateT;
use crate::oracle::Oracle;
use crate::state::HasItyState;
use crate::types::{convert_u256_to_h160, float_scale_to_u512};
use bytes::Bytes;
use libafl::impl_serdeany;
use libafl::prelude::State;
use libafl::state::HasMetadata;
use primitive_types::{H160, U256, U512};
use revm::Interpreter;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::process::exit;
use std::str::FromStr;

#[derive(Debug)]
pub struct Flashloan<S> {
    phantom: PhantomData<S>,
    oracle: Box<dyn PriceOracle>,
    use_contract_value: bool,
}

#[derive(Clone, Debug)]
pub struct DummyPriceOracle;

impl PriceOracle for DummyPriceOracle {
    fn fetch_token_price(&self, token_address: H160) -> Option<(f64, u32)> {
        return Some((1.0, 18));
    }
}

impl<S> Flashloan<S> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
            oracle: Box::new(DummyPriceOracle {}),
            use_contract_value: false,
        }
    }

    pub fn new_with_oracle(oracle: Box<dyn PriceOracle>) -> Self {
        Self {
            phantom: PhantomData,
            oracle,
            use_contract_value: false,
        }
    }

    fn calculate_usd_value((usd_price, decimals): (f64, u32), amount: U256) -> U512 {
        let amount = if decimals > 18 {
            amount / U256::from(10u64.pow(decimals - 18))
        } else {
            amount * U256::from(10u64.pow(18 - decimals))
        };
        // it should work for now as price of token is always less than 1e5
        return U512::from(amount) * float_scale_to_u512(usd_price, 5);
    }

    fn calculate_usd_value_from_addr(&self, addr: H160, amount: U256) -> Option<U512> {
        match self.oracle.fetch_token_price(addr) {
            Some(price) => Some(Self::calculate_usd_value(price, amount)),
            _ => None,
        }
    }
}

impl<S> Middleware for Flashloan<S>
where
    S: State + Debug + Clone + 'static,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter) -> Vec<MiddlewareOp> {
        let offset_of_arg_offset: usize = match *interp.instruction_pointer {
            0xf1 | 0xf2 => 3,
            0xf4 | 0xfa => 2,
            _ => {
                return vec![];
            }
        };

        let value_transfer = match *interp.instruction_pointer {
            0xf1 | 0xf2 => interp.stack.peek(2).unwrap(),
            _ => U256::zero(),
        };

        // todo: fix for delegatecall
        let call_target: H160 = convert_u256_to_h160(interp.stack.peek(1).unwrap());

        let value_transfer_ops = if value_transfer > U256::zero() {
            if call_target == interp.contract.caller {
                vec![MiddlewareOp::Earned(
                    MiddlewareType::Flashloan,
                    U512::from(value_transfer) * float_scale_to_u512(1.0, 5),
                )]
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        let offset = interp.stack.peek(offset_of_arg_offset).unwrap();
        let size = interp.stack.peek(offset_of_arg_offset + 1).unwrap();
        if size < U256::from(4) {
            return vec![];
        }
        let data = interp.memory.get_slice(offset.as_usize(), size.as_usize());
        // println!("Calling address: {:?} {:?}", hex::encode(call_target), hex::encode(data));

        macro_rules! earned {
            ($amount:expr) => {
                MiddlewareOp::Earned(MiddlewareType::Flashloan, $amount)
            };
        }

        macro_rules! handle_contract_contract_transfer {
            () => {
                if self.use_contract_value {
                    vec![]
                } else {
                    vec![MiddlewareOp::MakeSubsequentCallSuccess(Bytes::from(
                        [vec![0x0; 31], vec![0x1]].concat(),
                    ))]
                }
            };
        }

        macro_rules! handle_dst_is_attacker {
            ($amount:expr) => {
                if self.use_contract_value {
                    // if we use contract value, we make attacker earns amount for oracle proc
                    // we assume the subsequent would revert if no enough balance
                    vec![earned!($amount)]
                } else {
                    vec![
                        earned!($amount),
                        MiddlewareOp::MakeSubsequentCallSuccess(Bytes::from(
                            [vec![0x0; 31], vec![0x1]].concat(),
                        )),
                    ]
                }
            };
        }
        let erc20_ops = match data[0..4] {
            // balanceOf / approval
            [0x70, 0xa0, 0x82, 0x31] | [0x09, 0x5e, 0xa7, 0xb3] => {
                if !self.use_contract_value {
                    vec![MiddlewareOp::MakeSubsequentCallSuccess(Bytes::from(
                        vec![0xff; 32],
                    ))]
                } else {
                    vec![]
                }
            }
            // transfer
            [0xa9, 0x05, 0x9c, 0xbb] => {
                let dst = H160::from_slice(&data[16..36]);
                let amount = U256::from_big_endian(&data[36..68]);
                // println!(
                //     "transfer from {:?} to {:?} amount {:?}",
                //     interp.contract.address, dst, amount
                // );

                let make_success = MiddlewareOp::MakeSubsequentCallSuccess(Bytes::from(
                    [vec![0x0; 31], vec![0x1]].concat(),
                ));
                match self.calculate_usd_value_from_addr(call_target, amount) {
                    Some(value) => {
                        if dst == interp.contract.caller {
                            return handle_dst_is_attacker!(value);
                        }
                    }
                    // if no value, we can't borrow it!
                    // bypass by explicitly returning value for every token
                    _ => {}
                }
                handle_contract_contract_transfer!()
            }
            // transferFrom
            [0x23, 0xb8, 0x72, 0xdd] => {
                let src = H160::from_slice(&data[16..36]);
                let dst = H160::from_slice(&data[48..68]);
                let amount = U256::from_big_endian(&data[68..100]);
                let make_success = MiddlewareOp::MakeSubsequentCallSuccess(Bytes::from(
                    [vec![0x0; 31], vec![0x1]].concat(),
                ));
                match self.calculate_usd_value_from_addr(call_target, amount) {
                    Some(value) => {
                        if src == interp.contract.caller {
                            return vec![
                                make_success,
                                MiddlewareOp::Owed(MiddlewareType::Flashloan, value),
                            ];
                        } else if dst == interp.contract.caller {
                            return handle_dst_is_attacker!(value);
                        }
                    }
                    // if no value, we can't borrow it!
                    // bypass by explicitly returning value for every token
                    _ => {}
                }
                if src != interp.contract.caller && dst != interp.contract.caller {
                    handle_contract_contract_transfer!()
                } else {
                    vec![]
                }
            }
            _ => {
                vec![]
            }
        };
        [value_transfer_ops, erc20_ops].concat()
    }

    fn get_type(&self) -> MiddlewareType {
        return MiddlewareType::Flashloan;
    }

    fn as_any(&mut self) -> &mut (dyn Any + 'static) {
        return self;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlashloanData {
    pub owed: U512,
    pub earned: U512,
}

impl FlashloanData {
    pub fn new() -> Self {
        Self {
            owed: U512::from(0),
            earned: U512::from(0),
        }
    }
}

impl_serdeany!(FlashloanData);

impl<VS, S> CanHandleDeferredActions<VS, S> for Flashloan<S>
where
    S: HasItyState<VS>,
    VS: VMStateT + Default,
{
    fn handle_deferred_actions(
        &self,
        op: &MiddlewareOp,
        state: &mut S,
        result: &mut IntermediateExecutionResult,
    ) {
        match op {
            MiddlewareOp::Owed(.., amount) => {
                result.new_state.flashloan_data.owed += *amount;
            }
            MiddlewareOp::Earned(.., amount) => {
                result.new_state.flashloan_data.earned += *amount;
            }
            _ => {}
        }
    }
}
