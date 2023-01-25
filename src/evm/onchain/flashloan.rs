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
use std::borrow::BorrowMut;
use std::cell::{Ref, RefCell};
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Deref;
use std::process::exit;
use std::str::FromStr;
use crate::evm::contract_utils::ABIConfig;
use crate::evm::onchain::onchain::OnChain;
use std::rc::Rc;
use crate::evm::oracle::IERC20OracleFlashloan;

const UNBOUND_TRANSFER_AMT: usize = 5;

pub struct Flashloan<VS, I, S>
    where
        S: State + HasCaller<H160> + Debug + Clone + 'static,
        I: VMInputT<VS, H160, H160> + EVMInputT,
        VS: VMStateT,
{
    phantom: PhantomData<(VS, I, S)>,
    oracle: Box<dyn PriceOracle>,
    use_contract_value: bool,
    #[cfg(feature = "flashloan_v2")]
    known_addresses: HashSet<H160>,
    #[cfg(feature = "flashloan_v2")]
    endpoint: OnChainConfig,
    #[cfg(feature = "flashloan_v2")]
    erc20_address: HashSet<H160>,
    #[cfg(feature = "flashloan_v2")]
    pair_address: HashSet<H160>,
    #[cfg(feature = "flashloan_v2")]
    pub onchain_middlware: Rc<RefCell<OnChain<VS, I, S>>>,
    #[cfg(feature = "flashloan_v2")]
    pub unbound_tracker: HashMap<usize, HashSet<H160>>, // pc -> [address called]
    #[cfg(feature = "flashloan_v2")]
    pub flashloan_oracle: Rc<RefCell<IERC20OracleFlashloan>>,
}

impl<VS, I, S> Debug for Flashloan<VS, I, S>
    where
        S: State + HasCaller<H160> + Debug + Clone + 'static,
        I: VMInputT<VS, H160, H160> + EVMInputT,
        VS: VMStateT,

{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flashloan")
            .field("oracle", &self.oracle)
            .field("use_contract_value", &self.use_contract_value)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct DummyPriceOracle;

impl PriceOracle for DummyPriceOracle {
    fn fetch_token_price(&mut self, token_address: H160) -> Option<(u32, u32)> {
        return Some((10000, 18));
    }
}

impl<VS, I, S> Flashloan<VS, I, S>
    where
        S: State + HasCaller<H160> + Debug + Clone + 'static,
        I: VMInputT<VS, H160, H160> + EVMInputT,
        VS: VMStateT,
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
    pub fn new(use_contract_value: bool, endpoint: OnChainConfig,
               price_oracle: Box<dyn PriceOracle>, onchain_middleware: Rc<RefCell<OnChain<VS, I, S>>>,
               flashloan_oracle: Rc<RefCell<IERC20OracleFlashloan>>
    ) -> Self {
        Self {
            phantom: PhantomData,
            oracle: price_oracle,
            use_contract_value,
            known_addresses: Default::default(),
            endpoint,
            erc20_address: Default::default(),
            pair_address: Default::default(),
            onchain_middlware: onchain_middleware,
            unbound_tracker: Default::default(),
            flashloan_oracle
        }
    }

    fn calculate_usd_value((eth_price, decimals): (u32, u32), amount: U256) -> U512 {
        let amount = if decimals > 18 {
            U512::from(amount) / U512::from(10u64.pow(decimals - 18))
        } else {
            U512::from(amount) * U512::from(10u64.pow(18 - decimals))
        };
        // it should work for now as price of token is always less than 1e5
        return amount * U512::from(eth_price);
    }

    fn calculate_usd_value_from_addr(&mut self, addr: H160, amount: U256) -> Option<U512> {
        match self.oracle.fetch_token_price(addr) {
            Some(price) => Some(Self::calculate_usd_value(price, amount)),
            _ => None,
        }
    }

    #[cfg(feature = "flashloan_v2")]
    pub fn on_contract_insertion(&mut self, addr: &H160, abi: &Vec<ABIConfig>, state: &mut S) -> Vec<H160> {
        // should not happen, just sanity check
        if self.known_addresses.contains(addr) {
            return vec![];
        }
        self.known_addresses.insert(addr.clone());

        // if the contract is erc20, query its holders
        let abi_signatures_token = vec![
            "balanceOf".to_string(),
            "transfer".to_string(),
            "transferFrom".to_string(),
            "approve".to_string(),
        ];

        let abi_signatures_pair = vec![
            "skim".to_string(),
            "sync".to_string(),
            "swap".to_string(),
        ];
        let abi_names = abi.iter().map(|x| x.function_name.clone()).collect::<HashSet<String>>();
        let mut blacklist = vec![];

        // check abi_signatures_token is subset of abi.name
        if abi_signatures_token.iter().all(|x| abi_names.contains(x)) {
            self.flashloan_oracle.deref().borrow_mut().register_token(
                addr.clone(),
                self.endpoint.fetch_uniswap_path_cached(addr.clone()).clone()
            );
            // if the #holder > 10, then add it to the erc20_address
            match self.endpoint.fetch_holders(*addr) {
                None => {
                    println!("failed to fetch token holders for token {:?}", addr);
                }
                Some(v) => {
                    self.erc20_address.insert(addr.clone());
                    // add some user funds address
                    v[0..2].into_iter().for_each(|holder| {
                        state.add_address(&holder);
                        blacklist.push(*holder);
                    });
                    // add rich caller
                    let rich_account = v.clone().get(10).unwrap().clone();
                    state.add_caller(&rich_account);
                    blacklist.push(rich_account);
                }
            }
        }

        // if the contract is pair
        if abi_signatures_pair.iter().all(|x| abi_names.contains(x)) {
            self.pair_address.insert(addr.clone());
            println!("pair detected @ address {:?}", addr);
        }

        blacklist
    }
}

#[cfg(feature = "flashloan_v2")]
impl<VS, I, S> Flashloan<VS, I, S>
    where
        S: State + HasCaller<H160> + Debug + Clone + 'static,
        I: VMInputT<VS, H160, H160> + EVMInputT,
        VS: VMStateT,
{
    pub fn analyze_call(&self, input: &I, result: &mut IntermediateExecutionResult)
    {
        // if the txn is a transfer op, record it
        if input.get_txn_value().is_some() {
            result.new_state.flashloan_data.owed += U512::from(input.get_txn_value().unwrap());
        }
        let addr = input.get_contract();
        // dont care if the call target is not erc20
        if !self.erc20_address.contains(&addr) {
            return;
        }
        // if the target is erc20 contract, then check the balance of the caller in the oracle
        result.new_state.flashloan_data.oracle_recheck_balance.insert(addr);
    }
}

impl<VS, I, S> Middleware<VS, I, S> for Flashloan<VS, I, S>
    where
        S: State + HasCaller<H160> + Debug + Clone + 'static,
        I: VMInputT<VS, H160, H160> + EVMInputT,
        VS: VMStateT,
{
    #[cfg(not(feature = "flashloan_v2"))]
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<VS, I, S>, state: &mut S) {
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
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<VS, I, S>, s: &mut S)
        where
            S: HasCaller<H160>,
    {
        let offset_of_arg_offset = match *interp.instruction_pointer {
            // detect whether it mutates token balance
            0xf1 => 3,
            0xfa => 2,
            0x55 => {
                // detect whether it mutates pair reserve
                let key = interp.stack.peek(0).unwrap();
                if key == U256::from(8) && self.pair_address.contains(&interp.contract.address) {
                    host.data.flashloan_data.oracle_recheck_reserve.insert(
                        interp.contract.address,
                    );
                }
                return;
            }
            _ => {
                return;
            }
        };

        let value_transfer = match *interp.instruction_pointer {
            0xf1 | 0xf2 => interp.stack.peek(2).unwrap() * U256::from(100000),
            _ => U256::zero(),
        };

        // if a program counter can transfer any token, with value > 0 & dst = caller
        // then we give maximum rewards to trigger the bug
        {
            let call_target: H160 = convert_u256_to_h160(interp.stack.peek(1).unwrap());
            let offset = interp.stack.peek(offset_of_arg_offset).unwrap();
            let size = interp.stack.peek(offset_of_arg_offset + 1).unwrap();
            if size < U256::from(4) {
                return;
            }
            let data = interp.memory.get_slice(offset.as_usize(), size.as_usize());
            macro_rules! handle_transfer {
                ($dst: ident, $amount: ident) => {
                    if $amount > U256::zero() && $dst == interp.contract.caller {
                        let pc = interp.program_counter();

                        match self.unbound_tracker.get_mut(&pc) {
                            None => {
                                self.unbound_tracker.insert(
                                    pc, HashSet::from([call_target])
                                );
                            }
                            Some(set) => {
                                if set.len() > UNBOUND_TRANSFER_AMT {
                                    host.data.flashloan_data.earned += U512::max_value();
                                }
                                set.insert(call_target);
                            }
                        }
                    }
                };
            }
            match data[0..4] {
                // transfer
                [0xa9, 0x05, 0x9c, 0xbb] => {
                    let dst = H160::from_slice(&data[16..36]);
                    let amount = U256::from_big_endian(&data[36..68]);
                    handle_transfer!(dst, amount);
                }
                // transferFrom
                [0x23, 0xb8, 0x72, 0xdd] => {
                    let dst = H160::from_slice(&data[48..68]);
                    let amount = U256::from_big_endian(&data[68..100]);
                    handle_transfer!(dst, amount);
                }
                _ => {}
            };
        }


        // todo: fix for delegatecall
        let call_target: H160 = convert_u256_to_h160(interp.stack.peek(1).unwrap());

        if value_transfer > U256::zero() && call_target == interp.contract.caller {
            host.data.flashloan_data.earned += U512::from(value_transfer);
        }


        let call_target: H160 = convert_u256_to_h160(interp.stack.peek(1).unwrap());
        if self.erc20_address.contains(&call_target) {
            host.data.flashloan_data.oracle_recheck_balance.insert(call_target);
        }
    }

    fn get_type(&self) -> MiddlewareType {
        return MiddlewareType::Flashloan;
    }
}

#[cfg(not(feature = "flashloan_v2"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlashloanData {
    pub owed: U512,
    pub earned: U512,
}
#[cfg(not(feature = "flashloan_v2"))]
impl FlashloanData {
    pub fn new() -> Self {
        Self {
            owed: U512::from(0),
            earned: U512::from(0),
        }
    }
}

#[cfg(not(feature = "flashloan_v2"))]
impl_serdeany!(FlashloanData);



#[cfg(feature = "flashloan_v2")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlashloanData {
    pub oracle_recheck_reserve: HashSet<H160>,
    pub oracle_recheck_balance: HashSet<H160>,
    pub owed: U512,
    pub earned: U512,
    pub prev_reserves: HashMap<H160, (U256, U256)>,
    pub unliquidated_tokens: HashMap<H160, U256>,
}

#[cfg(feature = "flashloan_v2")]
impl FlashloanData {
    pub fn new() -> Self {
        Self {
            oracle_recheck_reserve: HashSet::new(),
            oracle_recheck_balance: HashSet::new(),
            owed: Default::default(),
            earned: Default::default(),
            prev_reserves: Default::default(),
            unliquidated_tokens: Default::default()
        }
    }
}