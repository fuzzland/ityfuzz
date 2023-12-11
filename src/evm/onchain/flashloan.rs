// on_call
// when approval, balanceof, give 2000e18 token
// when transfer, transferFrom, and src is our, return success, add owed
// when transfer, transferFrom, and src is not our, return success, reduce owed

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt::Debug,
    ops::Deref,
    rc::Rc,
    str::FromStr,
    time::Duration,
};

use bytes::Bytes;
use libafl::{
    corpus::{Corpus, Testcase},
    inputs::Input,
    prelude::{HasCorpus, State, UsesInput},
    schedulers::Scheduler,
    state::HasMetadata,
};
use revm_interpreter::Interpreter;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    evm::{
        contract_utils::ABIConfig,
        corpus_initializer::EnvMetadata,
        host::FuzzHost,
        input::{ConciseEVMInput, EVMInput, EVMInputT, EVMInputTy},
        middlewares::middleware::{Middleware, MiddlewareType},
        mutator::AccessPattern,
        onchain::endpoints::OnChainConfig,
        oracles::erc20::IERC20OracleFlashloan,
        types::{convert_u256_to_h160, EVMAddress, EVMFuzzState, EVMU256, EVMU512},
        uniswap::UniswapTokenContext,
    },
    generic_vm::vm_state::VMStateT,
    input::VMInputT,
    state::{HasCaller, HasItyState},
};

pub static mut CAN_LIQUIDATE: bool = false;

macro_rules! scale {
    () => {
        EVMU512::from(1_000_000)
    };
}
pub struct Flashloan {
    use_contract_value: bool,
    known_addresses: HashSet<EVMAddress>,
    endpoint: Option<OnChainConfig>,
    erc20_address: HashSet<EVMAddress>,
    pair_address: HashSet<EVMAddress>,
    pub unbound_tracker: HashMap<usize, HashSet<EVMAddress>>, // pc -> [address called]
    pub flashloan_oracle: Rc<RefCell<IERC20OracleFlashloan>>,
}

impl Debug for Flashloan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flashloan")
            .field("use_contract_value", &self.use_contract_value)
            .finish()
    }
}

pub fn register_borrow_txn<VS, I, S, SC>(mut scheduler: SC, state: &mut S, token: EVMAddress)
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        + HasCorpus
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCaller<EVMAddress>
        + Clone
        + Debug
        + UsesInput<Input = I>
        + 'static,
    VS: VMStateT + Default,
    SC: Scheduler<State = S> + Clone,
{
    let mut tc = Testcase::new(
        {
            EVMInput {
                input_type: EVMInputTy::Borrow,
                caller: state.get_rand_caller(),
                contract: token,
                data: None,
                sstate: Default::default(),
                sstate_idx: 0,
                txn_value: Some(EVMU256::from_str("10000000000000000000").unwrap()),
                step: false,
                env: state.metadata_map().get::<EnvMetadata>().unwrap().env.clone(),
                access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                liquidation_percent: 0,
                direct_data: Default::default(),
                randomness: vec![0],
                repeat: 1,
                swap_data: HashMap::new(),
            }
        }
        .as_any()
        .downcast_ref::<I>()
        .unwrap()
        .clone(),
    ) as Testcase<I>;
    tc.set_exec_time(Duration::from_secs(0));
    let idx = state.corpus_mut().add(tc).expect("failed to add");
    scheduler.on_add(state, idx).expect("failed to call scheduler on_add");
}

impl Flashloan {
    pub fn new(
        use_contract_value: bool,
        endpoint: Option<OnChainConfig>,
        flashloan_oracle: Rc<RefCell<IERC20OracleFlashloan>>,
    ) -> Self {
        Self {
            use_contract_value,
            known_addresses: Default::default(),
            endpoint,
            erc20_address: Default::default(),
            pair_address: Default::default(),
            unbound_tracker: Default::default(),
            flashloan_oracle,
        }
    }

    fn get_token_context(&mut self, addr: EVMAddress) -> Option<UniswapTokenContext> {
        self.endpoint
            .as_mut()
            .map(|endpoint| endpoint.fetch_uniswap_path_cached(addr).clone())
    }

    pub fn on_contract_insertion(
        &mut self,
        addr: &EVMAddress,
        abi: &[ABIConfig],
        _state: &mut EVMFuzzState,
    ) -> (bool, bool) {
        // should not happen, just sanity check
        if self.known_addresses.contains(addr) {
            return (false, false);
        }
        self.known_addresses.insert(*addr);

        // if the contract is erc20, query its holders
        let abi_signatures_token = vec![
            "balanceOf".to_string(),
            "transfer".to_string(),
            "transferFrom".to_string(),
            "approve".to_string(),
        ];

        let abi_signatures_pair = vec!["skim".to_string(), "sync".to_string(), "swap".to_string()];
        let abi_names = abi.iter().map(|x| x.function_name.clone()).collect::<HashSet<String>>();

        let mut is_erc20 = false;
        let mut is_pair = false;
        // check abi_signatures_token is subset of abi.name
        {
            if abi_signatures_token.iter().all(|x| abi_names.contains(x)) {
                match self.get_token_context(*addr) {
                    Some(token_ctx) => {
                        let oracle = self.flashloan_oracle.deref().try_borrow_mut();
                        // avoid delegate call on token -> make oracle borrow multiple times
                        if oracle.is_ok() {
                            let can_liquidate = !token_ctx.swaps.is_empty(); // if there is more than one liquidation path, we can liquidate
                            oracle
                                .unwrap()
                                .register_token(*addr, Rc::new(RefCell::new(token_ctx)), can_liquidate);
                            self.erc20_address.insert(*addr);
                            is_erc20 = true;
                        } else {
                            debug!("Unable to liquidate token {:?}", addr);
                        }
                    }
                    None => {
                        debug!("Unable to liquidate token {:?}", addr);
                    }
                }
            }
        }

        // if the contract is pair
        if abi_signatures_pair.iter().all(|x| abi_names.contains(x)) {
            self.pair_address.insert(*addr);
            debug!("pair detected @ address {:?}", addr);
            is_pair = true;
        }

        (is_erc20, is_pair)
    }

    pub fn on_pair_insertion<SC>(&mut self, host: &FuzzHost<SC>, state: &mut EVMFuzzState, pair: EVMAddress)
    where
        SC: Scheduler<State = EVMFuzzState> + Clone,
    {
        let slots = host.find_static_call_read_slot(
            pair,
            Bytes::from(vec![0x09, 0x02, 0xf1, 0xac]), // getReserves
            state,
        );
        if slots.len() == 3 {
            let slot = slots[0];
            // debug!("pairslots: {:?} {:?}", pair, slot);
            self.flashloan_oracle
                .deref()
                .borrow_mut()
                .register_pair_reserve_slot(pair, slot);
        }
    }
}

impl Flashloan {
    pub fn analyze_call(&self, input: &EVMInput, flashloan_data: &mut FlashloanData) {
        // if the txn is a transfer op, record it
        if input.get_txn_value().is_some() {
            flashloan_data.owed += EVMU512::from(input.get_txn_value().unwrap()) * scale!();
        }
        let addr = input.get_contract();
        // dont care if the call target is not erc20
        if self.erc20_address.contains(&addr) {
            // if the target is erc20 contract, then check the balance of the caller in the
            // oracle
            flashloan_data.oracle_recheck_balance.insert(addr);
        }

        if self.pair_address.contains(&addr) {
            // if the target is pair contract, then check the balance of the caller in the
            // oracle
            flashloan_data.oracle_recheck_reserve.insert(addr);
        }
    }
}

impl<SC> Middleware<SC> for Flashloan
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, s: &mut EVMFuzzState) {
        // if simply static call, we dont care
        // if unsafe { IS_FAST_CALL_STATIC } {
        //     return;
        // }

        match *interp.instruction_pointer {
            // detect whether it mutates token balance
            0xf1 | 0xfa => {}
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
            host.evmstate.flashloan_data.oracle_recheck_balance.insert(call_target);
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::Flashloan
    }
}

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
