use std::{cell::RefCell, fmt::Debug, ops::Deref, rc::Rc};

use bytes::Bytes;
use colored::{ColoredString, Colorize};
use libafl::{
    inputs::Input,
    mutators::MutationResult,
    prelude::{HasBytesVec, HasMaxSize, HasMetadata, HasRand, State},
};
use libafl_bolts::{prelude::Rand, HasLen};
use revm_primitives::Env;
use serde::{Deserialize, Deserializer, Serialize};

use super::{
    onchain::flashloan::CAN_LIQUIDATE,
    utils::{colored_address, colored_sender, prettify_value},
};
use crate::{
    evm::{
        abi::{AEmpty, AUnknown, BoxedABI},
        mutator::AccessPattern,
        types::{checksum, EVMAddress, EVMStagedVMState, EVMU256, EVMU512},
        vm::EVMState,
    },
    generic_vm::{vm_executor::ExecutionResult, vm_state::VMStateT},
    input::{ConciseSerde, SolutionTx, VMInputT},
    mutation_utils::byte_mutator,
    state::{HasCaller, HasItyState},
    state_input::StagedVMState,
};

/// EVM Input Types
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub enum EVMInputTy {
    /// A normal transaction
    #[default]
    ABI,
    /// A flashloan transaction
    Borrow,
    /// An arbitrary external call with same address tx
    ArbitraryCallBoundedAddr,
    /// [Depreciated] A liquidation transaction
    Liquidate,
}

/// EVM Input Trait
pub trait EVMInputT {
    /// Set the contract and ABI
    fn set_contract_and_abi(&mut self, contract: EVMAddress, abi: Option<BoxedABI>);

    /// Set the caller
    fn set_caller_evm(&mut self, caller: EVMAddress);

    /// Get the ABI encoded input
    fn to_bytes(&self) -> Vec<u8>;

    /// Get revm environment (block, timestamp, etc.)
    fn get_vm_env(&self) -> &Env;

    /// Get revm environment (block, timestamp, etc.) mutably
    fn get_vm_env_mut(&mut self) -> &mut Env;

    /// Get the access pattern of the input, used by the mutator to determine
    /// what to mutate
    fn get_access_pattern(&self) -> &Rc<RefCell<AccessPattern>>;

    /// Get the transaction value in wei
    fn get_txn_value(&self) -> Option<EVMU256>;

    /// Set the transaction value in wei
    fn set_txn_value(&mut self, v: EVMU256);

    /// Get input type
    fn get_input_type(&self) -> EVMInputTy;

    /// Get additional random bytes for mutator
    fn get_randomness(&self) -> Vec<u8>;

    /// Set additional random bytes for mutator
    fn set_randomness(&mut self, v: Vec<u8>);

    /// Get the percentage of the token amount in all callers' account to
    /// liquidate
    fn get_liquidation_percent(&self) -> u8;

    /// Set the percentage of the token amount in all callers' account to
    /// liquidate
    fn set_liquidation_percent(&mut self, v: u8);

    fn get_repeat(&self) -> usize;
}

/// EVM Input
#[derive(Serialize, Deserialize, Clone)]
pub struct EVMInput {
    /// Input type
    pub input_type: EVMInputTy,

    /// Caller address
    pub caller: EVMAddress,

    /// Contract address
    pub contract: EVMAddress,

    /// Input data in ABI format
    pub data: Option<BoxedABI>,

    /// Staged VM state
    #[serde(skip_deserializing)]
    pub sstate: StagedVMState<EVMAddress, EVMAddress, EVMState, ConciseEVMInput>,

    /// Staged VM state index in the corpus
    #[serde(skip_deserializing)]
    pub sstate_idx: usize,

    /// Transaction value in wei
    pub txn_value: Option<EVMU256>,

    /// Whether to resume execution from the last control leak
    pub step: bool,

    /// Environment (block, timestamp, etc.)
    pub env: Env,

    /// Access pattern
    #[serde(skip_deserializing)]
    pub access_pattern: Rc<RefCell<AccessPattern>>,

    /// Percentage of the token amount in all callers' account to liquidate
    pub liquidation_percent: u8,

    /// If ABI is empty, use direct data, which is the raw input data
    pub direct_data: Bytes,

    /// Additional random bytes for mutator
    pub randomness: Vec<u8>,

    /// Execute the transaction multiple times
    pub repeat: usize,
}

/// EVM Input Minimum for Deserializing
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ConciseEVMInput {
    /// Input type
    pub input_type: EVMInputTy,

    /// Caller address
    pub caller: EVMAddress,

    /// Contract address
    pub contract: EVMAddress,

    /// Input data in ABI format
    #[cfg(not(feature = "debug"))]
    pub data: Option<BoxedABI>,
    #[cfg(feature = "debug")]
    pub direct_data: String,

    /// Transaction value in wei
    pub txn_value: Option<EVMU256>,

    /// Whether to resume execution from the last control leak
    pub step: bool,

    /// Environment (block, timestamp, etc.)
    pub env: Env,

    /// Percentage of the token amount in all callers' account to liquidate
    pub liquidation_percent: u8,

    /// Additional random bytes for mutator
    pub randomness: Vec<u8>,

    /// Execute the transaction multiple times
    pub repeat: usize,

    /// How many post execution steps to take
    pub layer: usize,

    /// When to control leak, after `call_leak` number of calls
    pub call_leak: u32,

    /// return data
    pub return_data: Option<Vec<u8>>,
}

impl ConciseEVMInput {
    pub fn from_input<I, Out>(
        input: &I,
        execution_result: &ExecutionResult<EVMAddress, EVMAddress, EVMState, Out, ConciseEVMInput>,
    ) -> Self
    where
        I: VMInputT<EVMState, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
        Out: Default + Into<Vec<u8>> + Clone,
    {
        let return_data = match execution_result.output.clone().into() {
            v if v.is_empty() => None,
            v => Some(v),
        };

        Self {
            input_type: input.get_input_type(),
            caller: input.get_caller(),
            contract: input.get_contract(),
            #[cfg(not(feature = "debug"))]
            data: input.get_data_abi(),
            #[cfg(feature = "debug")]
            direct_data: match &input.get_data_abi() {
                Some(v) => hex::encode(v.get_bytes()),
                None => "".to_string(),
            },
            txn_value: input.get_txn_value(),
            step: input.is_step(),
            env: input.get_vm_env().clone(),
            liquidation_percent: input.get_liquidation_percent(),
            randomness: input.get_randomness(),
            repeat: input.get_repeat(),
            layer: input.get_state().get_post_execution_len(),
            call_leak: match execution_result.additional_info {
                Some(ref info) => info[0] as u32,
                None => u32::MAX,
            },
            return_data,
        }
    }

    pub fn from_input_with_call_leak<I>(input: &I, call_leak: u32) -> Self
    where
        I: VMInputT<EVMState, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    {
        Self {
            input_type: input.get_input_type(),
            caller: input.get_caller(),
            contract: input.get_contract(),
            #[cfg(not(feature = "debug"))]
            data: input.get_data_abi(),
            #[cfg(feature = "debug")]
            direct_data: match &input.get_data_abi() {
                Some(v) => hex::encode(v.get_bytes()),
                None => "".to_string(),
            },
            txn_value: input.get_txn_value(),
            step: input.is_step(),
            env: input.get_vm_env().clone(),
            liquidation_percent: input.get_liquidation_percent(),
            randomness: input.get_randomness(),
            repeat: input.get_repeat(),
            layer: input.get_state().get_post_execution_len(),
            call_leak,
            return_data: None,
        }
    }

    pub fn to_input(&self, sstate: EVMStagedVMState) -> (EVMInput, u32) {
        (
            EVMInput {
                input_type: self.input_type.clone(),
                caller: self.caller,
                contract: self.contract,
                #[cfg(not(feature = "debug"))]
                data: self.data.clone(),
                #[cfg(feature = "debug")]
                data: None,
                sstate,
                sstate_idx: 0,
                txn_value: self.txn_value,
                step: self.step,
                env: self.env.clone(),
                access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                liquidation_percent: self.liquidation_percent,
                #[cfg(not(feature = "debug"))]
                direct_data: Bytes::new(),
                #[cfg(feature = "debug")]
                direct_data: Bytes::from(hex::decode(&self.direct_data).unwrap_or_default()),
                randomness: self.randomness.clone(),
                repeat: self.repeat,
            },
            self.call_leak,
        )
    }

    // Variable `liq` is used when `debug` feature is disabled
    #[allow(unused_variables)]
    fn pretty_txn(&self) -> Option<String> {
        #[cfg(not(feature = "debug"))]
        match self.data {
            Some(ref d) => self.as_abi_call(d.to_colored_string()),
            None => match self.input_type {
                EVMInputTy::ABI | EVMInputTy::ArbitraryCallBoundedAddr => self.as_transfer(),
                EVMInputTy::Borrow => self.as_borrow(),
                EVMInputTy::Liquidate => None,
            },
        }

        #[cfg(feature = "debug")]
        self.as_transfer()
    }

    #[allow(dead_code)]
    #[inline]
    fn as_abi_call(&self, call_str: String) -> Option<String> {
        let parts: Vec<&str> = call_str.splitn(2, '(').collect();
        if parts.len() < 2 && call_str.len() == 8 {
            return self.as_fn_selector_call();
        }

        let mut fn_call = self.colored_fn_name(parts[0]).to_string();
        let value = self.txn_value.unwrap_or_default();
        if value != EVMU256::ZERO {
            fn_call.push_str(&self.colored_value());
        }

        if parts.len() < 2 {
            fn_call.push_str("()");
        } else {
            fn_call.push_str(format!("({}", parts[1]).as_str());
        }

        Some(format!("{}.{}", colored_address(&self.contract()), fn_call))
    }

    #[inline]
    fn as_fn_selector_call(&self) -> Option<String> {
        let mut call = format!("{}.{}", colored_address(&self.contract()), self.colored_fn_name("call"));
        let value = self.txn_value.unwrap_or_default();
        if value != EVMU256::ZERO {
            call.push_str(&self.colored_value());
        }

        if self.fn_args().is_empty() {
            call.push_str(format!("({})", self.fn_selector().purple()).as_str());
        } else {
            call.push_str(
                format!(
                    "({}({}, {}))",
                    self.colored_fn_name("abi.encodeWithSelector"),
                    self.fn_selector().purple(),
                    self.fn_args()
                )
                .as_str(),
            );
        }

        Some(call)
    }

    #[inline]
    fn as_transfer(&self) -> Option<String> {
        Some(format!(
            "{}.{}{}()",
            colored_address(&self.contract()),
            self.colored_fn_name("call"),
            self.colored_value()
        ))
    }

    #[allow(dead_code)]
    #[inline]
    fn as_borrow(&self) -> Option<String> {
        Some(format!(
            "{}.{}{}(0, path:(WETH → {}), address(this), block.timestamp);",
            colored_address("Router"),
            self.colored_fn_name("swapExactETHForTokens"),
            self.colored_value(),
            colored_address(&self.contract())
        ))
    }

    #[inline]
    fn append_liquidation(&self, indent: String, call: String) -> String {
        if self.liquidation_percent == 0 || unsafe { !CAN_LIQUIDATE } {
            return call;
        }

        let liq_call = format!(
            "{}.{}(100% Balance, 0, path:(* → WETH), address(this), block.timestamp);",
            colored_address("Router"),
            self.colored_fn_name("swapExactTokensForETH"),
        );

        let mut liq = indent.clone();
        liq.push_str(format!("├─[{}] {}", self.layer + 1, liq_call).as_str());

        [call, liq].join("\n")
    }

    #[inline]
    fn colored_value(&self) -> String {
        let value = self.txn_value.unwrap_or_default();
        format!("{{value: {}}}", prettify_value(value).truecolor(0x99, 0x00, 0xcc))
    }

    #[inline]
    fn colored_fn_name(&self, fn_name: &str) -> ColoredString {
        fn_name.truecolor(0xff, 0x7b, 0x72)
    }

    #[inline]
    fn pretty_return(&self, ret: &[u8]) -> String {
        if ret.len() != 32 {
            return format!("0x{}", hex::encode(ret));
        }

        // Try to encode it as an address
        if ret.len() == 32 && ret[..12] == [0; 12] && (ret[12] != 0 || ret[13] != 0) {
            let addr = EVMAddress::from_slice(&ret[12..]);
            return colored_address(&checksum(&addr));
        }

        // Remove leading zeros
        let res = match hex::encode(ret).trim_start_matches('0') {
            "" => "00".to_string(),
            v if v.len() % 2 != 0 => format!("0{}", v),
            v => v.to_string(),
        };

        format!("0x{}", res)
    }
}

impl SolutionTx for ConciseEVMInput {
    fn caller(&self) -> String {
        checksum(&self.caller)
    }

    fn contract(&self) -> String {
        checksum(&self.contract)
    }

    #[cfg(not(feature = "debug"))]
    fn fn_signature(&self) -> String {
        match self.data {
            Some(ref d) => d.get_func_signature().unwrap_or_default(),
            None => "".to_string(),
        }
    }

    #[cfg(not(feature = "debug"))]
    fn fn_selector(&self) -> String {
        match self.data {
            Some(ref d) => format!("0x{}", hex::encode(d.function)),
            None => "".to_string(),
        }
    }

    #[cfg(not(feature = "debug"))]
    fn fn_args(&self) -> String {
        if self.data.is_none() {
            return "".to_string();
        }

        let mut args_str = self.data.as_ref().unwrap().get().to_string();
        let len = args_str.len();
        if len < 2 {
            return "".to_string();
        }
        args_str.as_mut_str()[1..len - 1].replace('(', "[").replace(')', "]")
    }

    fn value(&self) -> String {
        self.txn_value.unwrap_or_default().to_string()
    }

    fn is_borrow(&self) -> bool {
        self.input_type == EVMInputTy::Borrow
    }

    fn liq_percent(&self) -> u8 {
        self.liquidation_percent
    }
}

impl HasLen for EVMInput {
    /// Get the length of the ABI encoded input
    fn len(&self) -> usize {
        match self.data {
            Some(ref d) => d.get_bytes().len(),
            None => 0,
        }
    }
}

impl std::fmt::Debug for EVMInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VMInput")
            .field("caller", &self.caller)
            .field("contract", &self.contract)
            // .field("data", &self.data)
            .field("state", &self.sstate)
            .field("state_idx", &self.sstate_idx)
            .field("txn_value", &self.txn_value)
            .field("step", &self.step)
            .finish()
    }
}

impl EVMInputT for EVMInput {
    fn set_contract_and_abi(&mut self, contract: EVMAddress, abi: Option<BoxedABI>) {
        self.contract = contract;
        self.access_pattern = Rc::new(RefCell::new(AccessPattern::new()));
        self.data = abi;
    }

    fn set_caller_evm(&mut self, caller: EVMAddress) {
        self.caller = caller;
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self.data {
            Some(ref d) => d.get_bytes(),
            None => vec![],
        }
    }

    fn get_vm_env_mut(&mut self) -> &mut Env {
        &mut self.env
    }

    fn get_vm_env(&self) -> &Env {
        &self.env
    }

    fn get_access_pattern(&self) -> &Rc<RefCell<AccessPattern>> {
        &self.access_pattern
    }

    fn get_txn_value(&self) -> Option<EVMU256> {
        self.txn_value
    }

    fn set_txn_value(&mut self, v: EVMU256) {
        self.txn_value = Some(v);
    }

    fn get_input_type(&self) -> EVMInputTy {
        self.input_type.clone()
    }

    fn get_randomness(&self) -> Vec<u8> {
        self.randomness.clone()
    }

    fn set_randomness(&mut self, v: Vec<u8>) {
        self.randomness = v;
    }

    fn get_liquidation_percent(&self) -> u8 {
        self.liquidation_percent
    }

    fn set_liquidation_percent(&mut self, v: u8) {
        self.liquidation_percent = v;
    }

    fn get_repeat(&self) -> usize {
        self.repeat
    }
}

///
macro_rules! impl_env_mutator_u256 {
    ($item: ident, $loc: ident, $increasing_only: expr) => {
        pub fn $item<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
        where
            S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
        {
            let vm_slots = if let Some(s) = input.get_state().get(&input.get_contract()) {
                Some(s.clone())
            } else {
                None
            };
            let input_by: [u8; 32] = input.get_vm_env().$loc.$item.to_be_bytes();
            let mut input_vec = input_by.to_vec();
            let mut wrapper = MutatorInput::new(&mut input_vec);
            let res = byte_mutator(state_, &mut wrapper, vm_slots);
            if res == MutationResult::Skipped {
                return res;
            }
            let result_val = EVMU256::try_from_be_slice(&input_vec.as_slice()).unwrap();
            if $increasing_only {
                if result_val < input.get_vm_env().$loc.$item {
                    return MutationResult::Skipped;
                }
            }

            input.get_vm_env_mut().$loc.$item = result_val;
            res
        }
    };
}

macro_rules! impl_env_mutator_h160 {
    ($item: ident, $loc: ident) => {
        pub fn $item<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
        where
            S: State + HasCaller<EVMAddress> + HasRand,
        {
            let addr = state_.get_rand_caller();
            if addr == input.get_caller() {
                return MutationResult::Skipped;
            } else {
                input.get_vm_env_mut().$loc.$item = addr;
                MutationResult::Mutated
            }
        }
    };
}

// Wrapper for EVMU256 so that it represents a mutable Input in LibAFL
#[derive(Serialize)]
struct MutatorInput<'a> {
    #[serde(skip_serializing)]
    pub val_vec: &'a mut Vec<u8>,
}

impl<'a, 'de> Deserialize<'de> for MutatorInput<'a> {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        unreachable!()
    }
}

impl<'a> Clone for MutatorInput<'a> {
    fn clone(&self) -> Self {
        unreachable!()
    }
}

impl<'a> Debug for MutatorInput<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutatorInput").field("val_vec", &self.val_vec).finish()
    }
}

impl<'a> MutatorInput<'a> {
    pub fn new(val_vec: &'a mut Vec<u8>) -> Self {
        MutatorInput { val_vec }
    }
}

impl<'a> Input for MutatorInput<'a> {
    fn generate_name(&self, idx: usize) -> String {
        format!("{}_{:?}", idx, self.val_vec)
    }
}

impl<'a> HasBytesVec for MutatorInput<'a> {
    fn bytes(&self) -> &[u8] {
        self.val_vec
    }

    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        self.val_vec
    }
}

impl EVMInput {
    impl_env_mutator_u256!(basefee, block, false);
    impl_env_mutator_u256!(timestamp, block, true);
    impl_env_mutator_h160!(coinbase, block);
    impl_env_mutator_u256!(gas_limit, block, false);
    impl_env_mutator_u256!(number, block, true);
    // impl_env_mutator_u256!(chain_id, cfg, false);

    pub fn prevrandao<S>(_input: &mut EVMInput, _state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        // not supported yet
        // unreachable!();
        MutationResult::Skipped
    }

    pub fn gas_price<S>(_input: &mut EVMInput, _state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        // not supported yet
        // unreachable!();
        MutationResult::Skipped
    }

    pub fn balance<S>(_input: &mut EVMInput, _state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        // not supported yet
        // unreachable!();
        MutationResult::Skipped
    }

    pub fn caller<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        let caller = state_.get_rand_caller();
        if caller == input.get_caller() {
            MutationResult::Skipped
        } else {
            input.set_caller(caller);
            input.get_vm_env_mut().tx.caller = caller;
            MutationResult::Mutated
        }
    }

    pub fn call_value<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        let vm_slots = input.get_state().get(&input.get_contract()).cloned();
        let input_by: [u8; 32] = input.get_txn_value().unwrap_or_default().to_be_bytes();
        let mut input_vec = input_by.to_vec();
        let mut wrapper = MutatorInput::new(&mut input_vec);
        let res = byte_mutator(state_, &mut wrapper, vm_slots);
        if res == MutationResult::Skipped {
            return res;
        }
        // make set first 16 bytes to 0
        (0..16).for_each(|i| {
            input_vec[i] = 0;
        });
        input.set_txn_value(EVMU256::try_from_be_slice(input_vec.as_slice()).unwrap());
        res
    }

    pub fn mutate_env_with_access_pattern<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        let ap = self.get_access_pattern().deref().borrow().clone();
        let mut mutators = vec![];
        macro_rules! add_mutator {
            ($item: ident) => {
                if ap.$item {
                    mutators.push(&EVMInput::$item as &dyn Fn(&mut EVMInput, &mut S) -> MutationResult);
                }
            };

            ($item: ident, $cond: expr) => {
                if $cond {
                    mutators.push(&EVMInput::$item as &dyn Fn(&mut EVMInput, &mut S) -> MutationResult);
                }
            };
        }
        add_mutator!(caller);
        add_mutator!(balance, !ap.balance.is_empty());
        if self.get_txn_value().is_some() {
            mutators.push(&EVMInput::call_value as &dyn Fn(&mut EVMInput, &mut S) -> MutationResult);
        }
        add_mutator!(gas_price);
        add_mutator!(basefee);
        add_mutator!(timestamp);
        add_mutator!(coinbase);
        add_mutator!(gas_limit);
        add_mutator!(number);
        // add_mutator!(chain_id);
        add_mutator!(prevrandao);

        if mutators.is_empty() {
            return MutationResult::Skipped;
        }

        let mutator = mutators[state.rand_mut().below(mutators.len() as u64) as usize];
        mutator(self, state)
    }
}

impl ConciseSerde for ConciseEVMInput {
    fn serialize_concise(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Failed to deserialize concise input")
    }

    fn deserialize_concise(data: &[u8]) -> Self {
        serde_json::from_slice(data).expect("Failed to deserialize concise input")
    }

    fn serialize_string(&self) -> String {
        let mut indent = String::from("   ");
        let mut tree_level = 1;
        for _ in 0..self.layer {
            indent.push_str("│  │  ");
            tree_level += 2;
        }

        // Stepping with return
        if self.step {
            let res = format!("{}└─ ← ()", indent.clone());
            return self.append_liquidation(indent, res);
        }

        let mut call = indent.clone();
        call.push_str(format!("├─[{}] ", tree_level).as_str());
        call.push_str(self.pretty_txn().expect("Failed to pretty print txn").as_str());

        // Control leak
        if self.call_leak != u32::MAX {
            let mut fallback = indent.clone();
            fallback.push_str(
                format!(
                    "│  ├─[{}] {}.fallback()",
                    tree_level + 1,
                    colored_sender(&self.sender())
                )
                .as_str(),
            );
            call.push('\n');
            call.push_str(fallback.as_str());
        }

        if self.return_data.is_some() {
            let mut ret = indent.clone();
            let v = self.return_data.as_ref().unwrap();
            ret.push_str(format!("│  └─ ← {}", self.pretty_return(v)).as_str());
            call.push('\n');
            call.push_str(ret.as_str());
        }

        self.append_liquidation(indent, call)
    }

    fn sender(&self) -> String {
        checksum(&self.caller)
    }

    fn indent(&self) -> String {
        if self.layer == 0 {
            return "".to_string();
        }

        let mut indent = String::from("   │  ");
        for _ in 1..self.layer {
            indent.push_str("│  │  ");
        }

        indent
    }

    fn is_step(&self) -> bool {
        self.step
    }
}

impl VMInputT<EVMState, EVMAddress, EVMAddress, ConciseEVMInput> for EVMInput {
    fn mutate<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: State
            + HasRand
            + HasMaxSize
            + HasItyState<EVMAddress, EVMAddress, EVMState, ConciseEVMInput>
            + HasCaller<EVMAddress>
            + HasMetadata,
    {
        if state.rand_mut().next() % 100 > 87 || self.data.is_none() {
            return self.mutate_env_with_access_pattern(state);
        }
        let vm_slots = self.get_state().get(&self.get_contract()).cloned();
        match self.data {
            Some(ref mut data) => data.mutate_with_vm_slots(state, vm_slots),
            None => MutationResult::Skipped,
        }
    }

    fn get_caller_mut(&mut self) -> &mut EVMAddress {
        &mut self.caller
    }

    fn get_caller(&self) -> EVMAddress {
        self.caller
    }

    fn set_caller(&mut self, caller: EVMAddress) {
        self.caller = caller;
    }

    fn get_contract(&self) -> EVMAddress {
        self.contract
    }

    fn get_state(&self) -> &EVMState {
        &self.sstate.state
    }

    fn get_state_mut(&mut self) -> &mut EVMState {
        &mut self.sstate.state
    }

    fn set_staged_state(&mut self, state: EVMStagedVMState, idx: usize) {
        self.sstate = state;
        self.sstate_idx = idx;
    }

    fn get_state_idx(&self) -> usize {
        self.sstate_idx
    }

    fn get_staged_state(&self) -> &EVMStagedVMState {
        &self.sstate
    }

    fn set_as_post_exec(&mut self, out_size: usize) {
        self.data = Some(BoxedABI::new(Box::new(AUnknown {
            concrete: BoxedABI::new(Box::new(AEmpty {})),
            size: out_size,
        })));
    }

    fn is_step(&self) -> bool {
        self.step
    }

    fn set_step(&mut self, gate: bool) {
        self.txn_value = None;
        self.step = gate;
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn fav_factor(&self) -> f64 {
        let mut f: f64 = 0.0;
        if self.sstate.state.flashloan_data.earned > self.sstate.state.flashloan_data.owed {
            f = f64::MAX;
        }
        let owed_amount = self.sstate.state.flashloan_data.owed - self.sstate.state.flashloan_data.earned;

        if owed_amount == EVMU512::ZERO {
            f = f64::MAX;
        }

        // hacky convert from U512 -> f64
        for idx in 0..8 {
            f += owed_amount.as_limbs()[idx] as f64 * (u64::MAX as f64).powi(idx as i32 - 4);
        }

        f / self.get_staged_state().trace.derived_time as f64
    }

    #[cfg(feature = "evm")]
    fn get_data_abi(&self) -> Option<BoxedABI> {
        self.data.clone()
    }

    fn get_direct_data(&self) -> Vec<u8> {
        self.direct_data.to_vec()
    }

    #[cfg(feature = "evm")]
    fn get_data_abi_mut(&mut self) -> &mut Option<BoxedABI> {
        &mut self.data
    }

    #[cfg(feature = "evm")]
    fn get_txn_value_temp(&self) -> Option<EVMU256> {
        self.txn_value
    }

    fn get_concise<Out: Default + Into<Vec<u8>> + Clone>(
        &self,
        exec_res: &ExecutionResult<EVMAddress, EVMAddress, EVMState, Out, ConciseEVMInput>,
    ) -> ConciseEVMInput {
        ConciseEVMInput::from_input(self, exec_res)
    }
}

impl Input for EVMInput {
    fn generate_name(&self, idx: usize) -> String {
        format!("input-{:06}.bin", idx)
    }

    // fn to_file<P>(&self, path: P) -> Result<(), libafl::Error>
    //     where
    //         P: AsRef<std::path::Path>, {

    // }

    fn wrapped_as_testcase(&mut self) {
        // todo!()
    }
}
