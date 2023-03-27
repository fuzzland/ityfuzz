// on_call
// when approval, balanceof, give 2000e18 token
// when transfer, transferFrom, and src is our, return success, add owed
// when transfer, transferFrom, and src is not our, return success, reduce owed

use crate::evm::input::{EVMInput, EVMInputT};
use crate::evm::middleware::CallMiddlewareReturn::ReturnSuccess;
use crate::evm::middleware::{Middleware, MiddlewareOp, MiddlewareType};
use crate::evm::onchain::endpoints::{OnChainConfig, PriceOracle};
use crate::evm::types::{EVMFuzzState, EVMStagedVMState};
use crate::evm::vm::{EVMState, FuzzHost, IntermediateExecutionResult};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::oracle::Oracle;
use crate::state::{HasCaller, HasItyState};
use crate::types::{convert_u256_to_h160, float_scale_to_u512};
use bytes::Bytes;
use libafl::impl_serdeany;
use libafl::prelude::State;
use libafl::state::HasMetadata;
use primitive_types::{H160, U256, U512};
use revm::Interpreter;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::cmp::min;
use std::collections::HashSet;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::process::exit;
use std::str::FromStr;

#[derive(Debug)]
pub struct Flashloan<S>
where
    S: State + HasCaller<H160> + Debug + Clone + 'static,
{
    phantom: PhantomData<S>,
    oracle: Box<dyn PriceOracle>,
    use_contract_value: bool,
    #[cfg(feature = "flashloan_v2")]
    known_tokens: HashSet<H160>,
    #[cfg(feature = "flashloan_v2")]
    endpoint: OnChainConfig,
}

#[derive(Clone, Debug)]
pub struct DummyPriceOracle;

impl PriceOracle for DummyPriceOracle {
    fn fetch_token_price(&self, token_address: H160) -> Option<(f64, u32)> {
        return Some((1.0, 18));
    }
}

impl<S> Flashloan<S>
where
    S: State + HasCaller<H160> + Debug + Clone + 'static,
{
    #[cfg(not(feature = "flashloan_v2"))]
    pub fn new(use_contract_value: bool) -> Self {
        Self {
            phantom: PhantomData,
            oracle: Box::new(DummyPriceOracle {}),
            use_contract_value,
        }
    }

    #[cfg(feature = "flashloan_v2")]
    pub fn new(use_contract_value: bool, endpoint: OnChainConfig) -> Self {
        Self {
            phantom: PhantomData,
            oracle: Box::new(DummyPriceOracle {}),
            use_contract_value,
            known_tokens: Default::default(),
            endpoint,
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

#[cfg(feature = "flashloan_v2")]
impl<S> Flashloan<S>
where
    S: State + HasCaller<H160> + Debug + Clone + 'static,
{
    pub fn analyze_call<VS, I>(&self, input: &I, result: &mut IntermediateExecutionResult)
    where
        I: VMInputT<VS, H160, H160> + EVMInputT,
        VS: VMStateT,
    {
        macro_rules! scale {
            ($data: expr) => {$data * float_scale_to_u512(1.0, 23)};
        }
        if input.get_txn_value().is_some() {
            result.new_state.flashloan_data.owed += scale!(U512::from(input.get_txn_value().unwrap()));
        }
        let call_target = input.get_contract();
        match input.get_data_abi() {
            Some(ref data) => {
                let serialized_data = input.to_bytes();
                if serialized_data.len() < 4 {
                    return;
                }
                match data.function {
                    [0xa9, 0x05, 0x9c, 0xbb] => {
                        let dst = H160::from_slice(&serialized_data[16..36]);
                        let amount = U256::from_big_endian(&serialized_data[36..68]);
                        match self.calculate_usd_value_from_addr(call_target, amount) {
                            Some(value) => {
                                if dst != input.get_caller() {
                                    result.new_state.flashloan_data.owed += value;
                                }
                            }
                            _ => {}
                        }
                    }
                    // transferFrom
                    [0x23, 0xb8, 0x72, 0xdd] => {
                        let src = H160::from_slice(&serialized_data[16..36]);
                        let dst = H160::from_slice(&serialized_data[48..68]);
                        let amount = U256::from_big_endian(&serialized_data[68..100]);
                        match self.calculate_usd_value_from_addr(call_target, amount) {
                            Some(value) => {
                                // todo: replace caller with all trusted addresses
                                if src == input.get_caller() {
                                    result.new_state.flashloan_data.owed += value;
                                } else if dst == input.get_caller() {
                                    result.new_state.flashloan_data.earned += value;
                                }
                            }
                            // if no value, we can't borrow it!
                            // bypass by explicitly returning value for every token
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

impl<S> Middleware<S> for Flashloan<S>
where
    S: State + HasCaller<H160> + Debug + Clone + 'static,
{
    #[cfg(not(feature = "flashloan_v2"))]
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<S>, state: &mut S) {
        macro_rules! earned {
            ($amount:expr) => {
                host.data.flashloan_data.earned += $amount;
            };
            () => {};
        }

        macro_rules! owed {
            ($amount:expr) => {
                host.data.flashloan_data.owed += $amount;
            };
            () => {};
        }

        let offset_of_arg_offset: usize = match *interp.instruction_pointer {
            0xf1 | 0xf2 => 3,
            0xf4 | 0xfa => 2,
            _ => {
                return;
            }
        };

        let value_transfer = match *interp.instruction_pointer {
            0xf1 | 0xf2 => interp.stack.peek(2).unwrap(),
            _ => U256::zero(),
        };

        // todo: fix for delegatecall
        let call_target: H160 = convert_u256_to_h160(interp.stack.peek(1).unwrap());

        if value_transfer > U256::zero() && call_target == interp.contract.caller {
            earned!(U512::from(value_transfer) * float_scale_to_u512(1.0, 5))
        }

        let offset = interp.stack.peek(offset_of_arg_offset).unwrap();
        let size = interp.stack.peek(offset_of_arg_offset + 1).unwrap();
        if size < U256::from(4) {
            return;
        }
        let data = interp.memory.get_slice(offset.as_usize(), size.as_usize());
        // println!("Calling address: {:?} {:?}", hex::encode(call_target), hex::encode(data));

        macro_rules! make_transfer_call_success {
            () => {
                host.middlewares_latent_call_actions
                    .push(ReturnSuccess(Bytes::from(
                        [vec![0x0; 31], vec![0x1]].concat(),
                    )));
            };
        }

        macro_rules! make_balance_call_success {
            () => {
                host.middlewares_latent_call_actions
                    .push(ReturnSuccess(Bytes::from(vec![0xff; 32])));
            };
        }
        macro_rules! handle_contract_contract_transfer {
            () => {
                if !self.use_contract_value {
                    make_transfer_call_success!();
                }
            };
        }

        macro_rules! handle_dst_is_attacker {
            ($amount:expr) => {
                if self.use_contract_value {
                    // if we use contract value, we make attacker earns amount for oracle proc
                    // we assume the subsequent would revert if no enough balance
                    earned!($amount);
                } else {
                    earned!($amount);
                    make_transfer_call_success!();
                }
            };
        }
        match data[0..4] {
            // balanceOf / approval
            [0x70, 0xa0, 0x82, 0x31] | [0x09, 0x5e, 0xa7, 0xb3] => {
                if !self.use_contract_value {
                    make_balance_call_success!();
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
                            make_transfer_call_success!();
                            return owed!(value);
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
                }
            }
            _ => {}
        };
    }

    #[cfg(feature = "flashloan_v2")]
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<S>, s: &mut S)
    where
        S: HasCaller<H160>,
    {
        macro_rules! earned {
            ($amount:expr) => {
                host.data.flashloan_data.earned += $amount;
            };
            () => {};
        }

        macro_rules! owed {
            ($amount:expr) => {
                host.data.flashloan_data.owed += $amount;
            };
            () => {};
        }

        let offset_of_arg_offset: usize = match *interp.instruction_pointer {
            0xf1 | 0xf2 => 3,
            0xf4 | 0xfa => 2,
            _ => {
                return;
            }
        };

        let value_transfer = match *interp.instruction_pointer {
            0xf1 | 0xf2 => interp.stack.peek(2).unwrap(),
            _ => U256::zero(),
        };

        // todo: fix for delegatecall
        let call_target: H160 = convert_u256_to_h160(interp.stack.peek(1).unwrap());

        if value_transfer > U256::zero() {
            if call_target == interp.contract.caller {
                earned!(U512::from(value_transfer) * float_scale_to_u512(1.0, 5))
            }
        }

        let offset = interp.stack.peek(offset_of_arg_offset).unwrap();
        let size = interp.stack.peek(offset_of_arg_offset + 1).unwrap();
        if size < U256::from(4) {
            return;
        }
        let data = interp.memory.get_slice(offset.as_usize(), size.as_usize());

        macro_rules! add_rich_when_ret {
            () => {
                if !self.known_tokens.contains(&call_target) {
                    self.known_tokens.insert(call_target);
                    match self.endpoint.fetch_holders(call_target) {
                        None => {
                            println!("failed to fetch token holders for token {:?}", call_target);
                        }
                        Some(v) => {
                            // add some user funds address
                            v[0..2].into_iter().for_each(|holder| {
                                s.add_address(&holder);
                            });
                            // add rich caller
                            s.add_caller(&v.clone().get(5).unwrap().clone());
                        }
                    }
                }
            };
        }

        let erc20_ops = match data[0..4] {
            // transfer
            [0xa9, 0x05, 0x9c, 0xbb] => {
                let dst = H160::from_slice(&data[16..36]);
                let amount = U256::from_big_endian(&data[36..68]);
                match self.calculate_usd_value_from_addr(call_target, amount) {
                    Some(value) => {
                        if dst == interp.contract.caller {
                            earned!(value);
                            return add_rich_when_ret!();
                        }
                    }
                    // if no value, we can't borrow it!
                    // bypass by explicitly returning value for every token
                    _ => {}
                }
            }
            // transferFrom
            [0x23, 0xb8, 0x72, 0xdd] => {
                let src = H160::from_slice(&data[16..36]);
                let dst = H160::from_slice(&data[48..68]);
                let amount = U256::from_big_endian(&data[68..100]);
                match self.calculate_usd_value_from_addr(call_target, amount) {
                    Some(value) => {
                        // todo: replace caller with all trusted addresses
                        if src == interp.contract.caller {
                            owed!(value);
                            return add_rich_when_ret!();
                        } else if dst == interp.contract.caller {
                            earned!(value);
                            return add_rich_when_ret!();
                        }
                    }
                    // if no value, we can't borrow it!
                    // bypass by explicitly returning value for every token
                    _ => {}
                }
            }
            _ => {}
        };
    }

    fn get_type(&self) -> MiddlewareType {
        return MiddlewareType::Flashloan;
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
