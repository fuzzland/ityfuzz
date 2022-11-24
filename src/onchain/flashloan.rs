// on_call
// when approval, balanceof, give 2000e18 token
// when transfer, transferFrom, and src is our, return success, add owed
// when transfer, transferFrom, and src is not our, return success, reduce owed

use crate::evm::IntermediateExecutionResult;
use crate::middleware::{CanHandleDeferredActions, Middleware, MiddlewareOp, MiddlewareType};
use crate::onchain::endpoints::{OnChainConfig, PriceOracle};
use crate::state::HasItyState;
use crate::types::{convert_u256_to_h160, float_scale_to_u256};
use bytes::Bytes;
use libafl::impl_serdeany;
use libafl::prelude::State;
use libafl::state::HasMetadata;
use primitive_types::{H160, U256};
use revm::Interpreter;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fmt::Debug;
use std::marker::PhantomData;

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

    fn calculate_usd_value((usd_price, decimals): (f64, u32), amount: U256) -> U256 {
        let amount = if decimals > 18 {
            amount / U256::from(10u64.pow(decimals - 18))
        } else {
            amount * U256::from(10u64.pow(18 - decimals))
        };
        // it should work for now as price of token is always less than 1e5
        return amount * float_scale_to_u256(usd_price, 5);
    }

    fn calculate_usd_value_from_addr(&self, addr: H160, amount: U256) -> Option<U256> {
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
        let call_target: H160 = convert_u256_to_h160(interp.stack.peek(1).unwrap());
        let offset = interp.stack.peek(offset_of_arg_offset).unwrap();
        let size = interp.stack.peek(offset_of_arg_offset + 1).unwrap();
        if size < U256::from(4) {
            return vec![];
        }
        let data = interp.memory.get_slice(offset.as_usize(), size.as_usize());

        macro_rules! earned {
            ($amount:expr) => {
                MiddlewareOp::Earned(
                    MiddlewareType::Flashloan,
                    self.calculate_usd_value_from_addr(call_target, $amount)
                        .unwrap_or(U256::from(0)),
                )
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
        match data[0..4] {
            // balanceOf / approval
            [0x70, 0xa0, 0x82, 0x31] | [0x09, 0x5e, 0xa7, 0xb3] => {
                vec![MiddlewareOp::MakeSubsequentCallSuccess(Bytes::from(
                    vec![0xff; 32],
                ))]
            }
            // transfer
            [0xa9, 0x05, 0x9c, 0xbb] => {
                let dst = H160::from_slice(&data[16..36]);
                let amount = U256::from_big_endian(&data[36..68]);
                println!(
                    "transfer from {:?} to {:?} amount {:?}",
                    interp.contract.address, dst, amount
                );

                let make_success = MiddlewareOp::MakeSubsequentCallSuccess(Bytes::from(
                    [vec![0x0; 31], vec![0x1]].concat(),
                ));
                if dst == interp.contract.caller {
                    handle_dst_is_attacker!(amount)
                } else {
                    handle_contract_contract_transfer!()
                }
            }
            // transferFrom
            [0x23, 0xb8, 0x72, 0xdd] => {
                let src = H160::from_slice(&data[16..36]);
                let dst = H160::from_slice(&data[48..68]);
                let amount = U256::from_big_endian(&data[68..100]);
                let make_success = MiddlewareOp::MakeSubsequentCallSuccess(Bytes::from(
                    [vec![0x0; 31], vec![0x1]].concat(),
                ));
                if src == interp.contract.caller {
                    match self.calculate_usd_value_from_addr(call_target, amount) {
                        Some(value) => vec![
                            make_success,
                            MiddlewareOp::Owed(MiddlewareType::Flashloan, value),
                        ],
                        // if no value, we can't borrow it!
                        // bypass by explicitly returning value for every token
                        _ => vec![],
                    }
                } else if dst == interp.contract.caller {
                    handle_dst_is_attacker!(amount)
                } else {
                    handle_contract_contract_transfer!()
                }
            }
            _ => {
                vec![]
            }
        }
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
    pub owed: U256,
    pub earned: U256,
}

impl_serdeany!(FlashloanData);

impl<S> CanHandleDeferredActions<S> for Flashloan<S>
where
    S: HasItyState,
{
    fn handle_deferred_actions(
        &self,
        op: &MiddlewareOp,
        state: &mut S,
        result: &mut IntermediateExecutionResult,
    ) {
        // todo(shou): move init to else where to avoid overhead
        if !result.new_state.has_metadata::<FlashloanData>() {
            result.new_state.add_metadata(FlashloanData {
                owed: U256::from(0),
                earned: U256::from(0),
            });
        }
        match op {
            MiddlewareOp::Owed(.., amount) => {
                let mut data = result.new_state.metadata_mut().get_mut::<FlashloanData>();
                data.as_mut().unwrap().owed += *amount;
            }
            MiddlewareOp::Earned(.., amount) => {
                let mut data = result.new_state.metadata_mut().get_mut::<FlashloanData>();
                data.as_mut().unwrap().earned += *amount;
            }
            _ => {}
        }
    }
}
