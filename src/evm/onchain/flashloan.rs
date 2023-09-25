// on_call
// when approval, balanceof, give 2000e18 token
// when transfer, transferFrom, and src is our, return success, add owed
// when transfer, transferFrom, and src is not our, return success, reduce owed

use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT, EVMInputTy};
use crate::evm::middlewares::middleware::CallMiddlewareReturn::ReturnSuccess;
use crate::evm::middlewares::middleware::{Middleware, MiddlewareOp, MiddlewareType};
use crate::evm::mutator::AccessPattern;
use crate::evm::onchain::endpoints::{OnChainConfig, PriceOracle};
use std::borrow::BorrowMut;
use revm_interpreter::Interpreter;
use crate::evm::host::FuzzHost;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::oracle::Oracle;
use crate::state::{HasCaller, HasItyState};
use bytes::Bytes;
use libafl::corpus::{Corpus, Testcase};
use libafl::impl_serdeany;
use libafl::inputs::Input;
use libafl::prelude::{HasCorpus, State};
use libafl::state::{HasMetadata, HasRand};
use serde::{Deserialize, Serialize};

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Deref;

use crate::evm::contract_utils::ABIConfig;
use crate::evm::onchain::onchain::OnChain;
use crate::evm::oracles::erc20::IERC20OracleFlashloan;
use crate::get_token_ctx;
use std::rc::Rc;
use std::str::FromStr;
use std::time::Duration;
use revm_primitives::Bytecode;
use crate::evm::types::{as_u64, EVMAddress, EVMU256, EVMU512};
use crate::evm::types::convert_u256_to_h160;
use crate::evm::types::float_scale_to_u512;
use crate::evm::vm::IS_FAST_CALL_STATIC;

macro_rules! scale {
    () => {
        EVMU512::from(1_000_000)
    };
}
pub struct Flashloan<VS, I, S>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    phantom: PhantomData<(VS, I, S)>,
    oracle: Box<dyn PriceOracle>,
    use_contract_value: bool,
    #[cfg(feature = "flashloan_v2")]
    known_addresses: HashSet<EVMAddress>,
    #[cfg(feature = "flashloan_v2")]
    endpoint: OnChainConfig,
    #[cfg(feature = "flashloan_v2")]
    erc20_address: HashSet<EVMAddress>,
    #[cfg(feature = "flashloan_v2")]
    pair_address: HashSet<EVMAddress>,
    #[cfg(feature = "flashloan_v2")]
    pub onchain_middlware: Rc<RefCell<OnChain<VS, I, S>>>,
    #[cfg(feature = "flashloan_v2")]
    pub unbound_tracker: HashMap<usize, HashSet<EVMAddress>>, // pc -> [address called]
    #[cfg(feature = "flashloan_v2")]
    pub flashloan_oracle: Rc<RefCell<IERC20OracleFlashloan>>,
}

impl<VS, I, S> Debug for Flashloan<VS, I, S>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
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
    fn fetch_token_price(&mut self, _token_address: EVMAddress) -> Option<(u32, u32)> {
        return Some((10000, 18));
    }
}

pub fn register_borrow_txn<VS, I, S>(host: &FuzzHost<VS, I, S>, state: &mut S, token: EVMAddress)
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCaller<EVMAddress>
        + Clone
        + Debug
        + 'static,
    VS: VMStateT + Default,
{
    let mut tc = Testcase::new(
        {
            EVMInput {
                #[cfg(feature = "flashloan_v2")]
                input_type: EVMInputTy::Borrow,
                caller: state.get_rand_caller(),
                contract: token,
                data: None,
                sstate: Default::default(),
                sstate_idx: 0,
                txn_value: Some(EVMU256::from_str("10000000000000000000").unwrap()),
                step: false,
                env: Default::default(),
                access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                #[cfg(feature = "flashloan_v2")]
                liquidation_percent: 0,
                direct_data: Default::default(),
                randomness: vec![0],
                repeat: 1,
            }
        }
        .as_any()
        .downcast_ref::<I>()
        .unwrap()
        .clone(),
    ) as Testcase<I>;
    tc.set_exec_time(Duration::from_secs(0));
    let idx = state.corpus_mut().add(tc).expect("failed to add");
    host.scheduler
        .on_add(state, idx)
        .expect("failed to call scheduler on_add");
}

impl<VS, I, S> Flashloan<VS, I, S>
where
    S: State + HasRand + HasCaller<EVMAddress> + HasCorpus<I> + Debug + Clone + HasMetadata + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput> + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
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
    pub fn new(
        use_contract_value: bool,
        endpoint: OnChainConfig,
        price_oracle: Box<dyn PriceOracle>,
        onchain_middleware: Rc<RefCell<OnChain<VS, I, S>>>,
        flashloan_oracle: Rc<RefCell<IERC20OracleFlashloan>>,
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
            flashloan_oracle,
        }
    }

    fn calculate_usd_value((eth_price, decimals): (u32, u32), amount: EVMU256) -> EVMU512 {
        let amount = if decimals > 18 {
            EVMU512::from(amount) / EVMU512::from(10u64.pow(decimals - 18))
        } else {
            EVMU512::from(amount) * EVMU512::from(10u64.pow(18 - decimals))
        };
        // it should work for now as price of token is always less than 1e5
        return amount * EVMU512::from(eth_price);
    }

    fn calculate_usd_value_from_addr(&mut self, addr: EVMAddress, amount: EVMU256) -> Option<EVMU512> {
        match self.oracle.fetch_token_price(addr) {
            Some(price) => Some(Self::calculate_usd_value(price, amount)),
            _ => None,
        }
    }

    #[cfg(feature = "flashloan_v2")]
    pub fn on_contract_insertion(
        &mut self,
        addr: &EVMAddress,
        abi: &Vec<ABIConfig>,
        state: &mut S,
    ) -> (bool, bool) {
        // should not happen, just sanity check
        if self.known_addresses.contains(addr) {
            return (false, false);
        }
        self.known_addresses.insert(addr.clone());

        // if the contract is erc20, query its holders
        let abi_signatures_token = vec![
            "balanceOf".to_string(),
            "transfer".to_string(),
            "transferFrom".to_string(),
            "approve".to_string(),
        ];

        let abi_signatures_pair = vec!["skim".to_string(), "sync".to_string(), "swap".to_string()];
        let abi_names = abi
            .iter()
            .map(|x| x.function_name.clone())
            .collect::<HashSet<String>>();

        let mut is_erc20 = false;
        let mut is_pair = false;
        // check abi_signatures_token is subset of abi.name
        {
            let mut oracle = self.flashloan_oracle.deref().try_borrow_mut();
            // avoid delegate call on token -> make oracle borrow multiple times
            if oracle.is_ok() {
                if abi_signatures_token.iter().all(|x| abi_names.contains(x)) {
                    oracle.unwrap().register_token(
                        addr.clone(),
                        self.endpoint
                            .fetch_uniswap_path_cached(addr.clone())
                            .clone(),
                    );
                    self.erc20_address.insert(addr.clone());
                    is_erc20 = true;
                }
            } else {
                println!("Ignoring token {:?}", addr);
            }
        }

        // if the contract is pair
        if abi_signatures_pair.iter().all(|x| abi_names.contains(x)) {
            self.pair_address.insert(addr.clone());
            println!("pair detected @ address {:?}", addr);
            is_pair = true;
        }

        (is_erc20, is_pair)
    }

    #[cfg(feature = "flashloan_v2")]
    pub fn on_pair_insertion(&mut self, host: &FuzzHost<VS, I, S>, state: &mut S, pair: EVMAddress) {
        let slots = host.find_static_call_read_slot(
            pair,
            Bytes::from(vec![0x09, 0x02, 0xf1, 0xac]), // getReserves
            state,
        );
        if slots.len() == 3 {
            let slot = slots[0];
            // println!("pairslots: {:?} {:?}", pair, slot);
            self.flashloan_oracle
                .deref()
                .borrow_mut()
                .register_pair_reserve_slot(pair, slot);
        }
    }
}

#[cfg(feature = "flashloan_v2")]
impl<VS, I, S> Flashloan<VS, I, S>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    pub fn analyze_call(&self, input: &I, flashloan_data: &mut FlashloanData) {
        // if the txn is a transfer op, record it
        if input.get_txn_value().is_some() {
            flashloan_data.owed += EVMU512::from(input.get_txn_value().unwrap()) * scale!();
        }
        let addr = input.get_contract();
        // dont care if the call target is not erc20
        if self.erc20_address.contains(&addr) {
            // if the target is erc20 contract, then check the balance of the caller in the oracle
            flashloan_data.oracle_recheck_balance.insert(addr);
        }

        if self.pair_address.contains(&addr) {
            // if the target is pair contract, then check the balance of the caller in the oracle
            flashloan_data.oracle_recheck_reserve.insert(addr);
        }
    }
}

impl<VS, I, S> Middleware<VS, I, S> for Flashloan<VS, I, S>
where
    S: State +HasRand+ HasCaller<EVMAddress>+ HasMetadata + HasCorpus<I> + Debug + Clone + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput> + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    VS: VMStateT,
{
    #[cfg(not(feature = "flashloan_v2"))]
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S>,
        _state: &mut S,
    ) {
        macro_rules! earned {
            ($amount:expr) => {
                host.evmstate.flashloan_data.earned += $amount;
            };
            () => {};
        }

        macro_rules! owed {
            ($amount:expr) => {
                host.evmstate.flashloan_data.owed += $amount;
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
            _ => EVMU256::ZERO,
        };

        // todo: fix for delegatecall
        let call_target: EVMAddress = convert_u256_to_h160(interp.stack.peek(1).unwrap());

        if value_transfer > EVMU256::ZERO && call_target == interp.contract.caller {
            earned!(EVMU512::from(value_transfer) * float_scale_to_u512(1.0, 5))
        }

        let offset = interp.stack.peek(offset_of_arg_offset).unwrap();
        let size = interp.stack.peek(offset_of_arg_offset + 1).unwrap();
        if size < EVMU256::from(4) {
            return;
        }
        let data = interp.memory.get_slice(as_u64(offset) as usize, as_u64(size) as usize);
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
                let dst = EVMAddress::from_slice(&data[16..36]);
                let amount = EVMU256::try_from_be_slice(&data[36..68]).unwrap();
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
                let src = EVMAddress::from_slice(&data[16..36]);
                let dst = EVMAddress::from_slice(&data[48..68]);
                let amount = EVMU256::try_from_be_slice(&data[68..100]).unwrap();
                let _make_success = MiddlewareOp::MakeSubsequentCallSuccess(Bytes::from(
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
        S: HasCaller<EVMAddress>,
    {
        // if simply static call, we dont care
        if unsafe { IS_FAST_CALL_STATIC } {
            return;
        }


        match *interp.instruction_pointer {
            // detect whether it mutates token balance
            0xf1 | 0xfa => {},
            0x55 => {
                if self.pair_address.contains(&interp.contract.address) {
                    let key = interp.stack.peek(0).unwrap();
                    if key == EVMU256::from(8) {
                        host.evmstate
                            .flashloan_data
                            .oracle_recheck_reserve
                            .insert(interp.contract.address);
                    }
                }
                return;
            }
            _ => {
                return;
            }
        };

        let value_transfer = match *interp.instruction_pointer {
            0xf1 | 0xf2 => interp.stack.peek(2).unwrap(),
            _ => EVMU256::ZERO,
        };

        // todo: fix for delegatecall
        let call_target: EVMAddress = convert_u256_to_h160(interp.stack.peek(1).unwrap());

        if value_transfer > EVMU256::ZERO && s.has_caller(&call_target) {
            host.evmstate.flashloan_data.earned += EVMU512::from(value_transfer) * scale!();
        }

        let call_target: EVMAddress = convert_u256_to_h160(interp.stack.peek(1).unwrap());
        if self.erc20_address.contains(&call_target) {
            host.evmstate
                .flashloan_data
                .oracle_recheck_balance
                .insert(call_target);
        }
    }

    unsafe fn on_insert(&mut self, bytecode: &mut Bytecode, address: EVMAddress, host: &mut FuzzHost<VS, I, S>, state: &mut S) {

    }

    fn get_type(&self) -> MiddlewareType {
        return MiddlewareType::Flashloan;
    }
}

#[cfg(not(feature = "flashloan_v2"))]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FlashloanData {
    pub owed: EVMU512,
    pub earned: EVMU512,
}
#[cfg(not(feature = "flashloan_v2"))]
impl FlashloanData {
    pub fn new() -> Self {
        Self {
            owed: EVMU512::from(0),
            earned: EVMU512::from(0),
        }
    }
}

#[cfg(not(feature = "flashloan_v2"))]
impl_serdeany!(FlashloanData);

#[cfg(feature = "flashloan_v2")]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FlashloanData {
    pub oracle_recheck_reserve: HashSet<EVMAddress>,
    pub oracle_recheck_balance: HashSet<EVMAddress>,
    pub owed: EVMU512,
    pub earned: EVMU512,
    pub prev_reserves: HashMap<EVMAddress, (EVMU256, EVMU256)>,
    pub unliquidated_tokens: HashMap<EVMAddress, EVMU256>,
    pub extra_info: String,
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
            unliquidated_tokens: Default::default(),
            extra_info: Default::default(),
        }
    }
}
