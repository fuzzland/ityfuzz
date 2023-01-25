use crate::evm::abi::{AEmpty, AUnknown, BoxedABI};
use crate::evm::mutation_utils::{byte_mutator, mutate_with_vm_slot};
use crate::evm::mutator::AccessPattern;
use crate::evm::types::EVMStagedVMState;
use crate::evm::vm::EVMState;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasItyState};
use crate::state_input::StagedVMState;
use crate::types::convert_u256_to_h160;
use bytes::Bytes;
use libafl::bolts::HasLen;
use libafl::inputs::Input;
use libafl::mutators::MutationResult;
use libafl::prelude::{HasBytesVec, HasMaxSize, HasMetadata, HasRand, Rand, State};
use primitive_types::{H160, H256, U256, U512};
use revm::{Env, Interpreter};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_traitobject::Any;
use std::cell::RefCell;
use std::fmt::Debug;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::Arc;

pub trait EVMInputT {
    fn to_bytes(&self) -> Vec<u8>;
    fn get_vm_env(&self) -> &Env;
    fn get_vm_env_mut(&mut self) -> &mut Env;
    fn get_access_pattern(&self) -> &Rc<RefCell<AccessPattern>>;
    fn get_txn_value(&self) -> Option<U256>;
    fn set_txn_value(&mut self, v: U256);
    // scaled with 10
    #[cfg(feature = "flashloan_v2")]
    fn get_liquidation_percent(&self) -> u8;
    #[cfg(feature = "flashloan_v2")]
    fn set_liquidation_percent(&mut self, v: u8);
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EVMInput {
    pub caller: H160,
    pub contract: H160,
    pub data: Option<BoxedABI>,
    pub sstate: StagedVMState<H160, H160, EVMState>,
    pub sstate_idx: usize,
    pub txn_value: Option<U256>,
    pub step: bool,
    pub env: Env,
    pub access_pattern: Rc<RefCell<AccessPattern>>,
    #[cfg(feature = "flashloan_v2")]
    pub liquidation_percent: u8,

    #[cfg(any(test, feature = "debug"))]
    pub direct_data: Bytes,
}

impl HasLen for EVMInput {
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

    fn get_txn_value(&self) -> Option<U256> {
        self.txn_value
    }

    fn set_txn_value(&mut self, v: U256) {
        self.txn_value = Some(v);
    }

    #[cfg(feature = "flashloan_v2")]
    fn get_liquidation_percent(&self) -> u8 {
        self.liquidation_percent
    }

    #[cfg(feature = "flashloan_v2")]
    fn set_liquidation_percent(&mut self, v: u8) {
        self.liquidation_percent = v;
    }
}

macro_rules! impl_env_mutator_u256 {
    ($item: ident, $loc: ident) => {
        pub fn $item<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
        where
            S: State + HasCaller<H160> + HasRand + HasMetadata,
        {
            let vm_slots = if let Some(s) = input.get_state().get(&input.get_contract()) {
                Some(s.clone())
            } else {
                None
            };
            let mut input_by = [0; 32];
            input.get_vm_env().$loc.$item.to_big_endian(&mut input_by);
            let mut input_vec = input_by.to_vec();
            let mut wrapper = MutatorInput::new(&mut input_vec);
            let res = byte_mutator(state_, &mut wrapper, vm_slots);
            if res == MutationResult::Skipped {
                return res;
            }
            input.get_vm_env_mut().$loc.$item = U256::from_big_endian(&input_vec.as_slice());
            res
        }
    };
}

macro_rules! impl_env_mutator_h160 {
    ($item: ident, $loc: ident) => {
        pub fn $item<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
        where
            S: State + HasCaller<H160> + HasRand,
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

// Wrapper for U256 so that it represents a mutable Input in LibAFL
#[derive(Serialize)]
struct MutatorInput<'a> {
    #[serde(skip_serializing)]
    pub val_vec: &'a mut Vec<u8>,
}

impl<'a, 'de> Deserialize<'de> for MutatorInput<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
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
        f.debug_struct("MutatorInput")
            .field("val_vec", &self.val_vec)
            .finish()
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
    impl_env_mutator_u256!(basefee, block);
    impl_env_mutator_u256!(timestamp, block);
    impl_env_mutator_h160!(coinbase, block);
    impl_env_mutator_u256!(gas_limit, block);
    impl_env_mutator_u256!(number, block);
    impl_env_mutator_u256!(chain_id, cfg);

    pub fn prevrandao<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<H160> + HasRand + HasMetadata,
    {
        // not supported yet
        unreachable!();
    }

    pub fn gas_price<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<H160> + HasRand + HasMetadata,
    {
        // not supported yet
        unreachable!();
    }

    pub fn balance<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<H160> + HasRand + HasMetadata,
    {
        // not supported yet
        // unreachable!();
        return MutationResult::Skipped;
    }

    pub fn caller<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<H160> + HasRand + HasMetadata,
    {
        let caller = state_.get_rand_caller();
        if caller == input.get_caller() {
            return MutationResult::Skipped;
        } else {
            input.set_caller(caller);
            MutationResult::Mutated
        }
    }

    pub fn call_value<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<H160> + HasRand + HasMetadata,
    {
        let vm_slots = if let Some(s) = input.get_state().get(&input.get_contract()) {
            Some(s.clone())
        } else {
            None
        };
        let mut input_by = [0; 32];
        input
            .get_txn_value()
            .unwrap_or(U256::zero())
            .to_big_endian(&mut input_by);
        let mut input_vec = input_by.to_vec();
        let mut wrapper = MutatorInput::new(&mut input_vec);
        let res = byte_mutator(state_, &mut wrapper, vm_slots);
        if res == MutationResult::Skipped {
            return res;
        }
        input.set_txn_value(U256::from_big_endian(&input_vec.as_slice()));
        res
    }

    pub fn mutate_env_with_access_pattern<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: State + HasCaller<H160> + HasRand + HasMetadata,
    {
        let ap = self.get_access_pattern().deref().borrow().clone();
        let mut mutators = vec![];
        macro_rules! add_mutator {
            ($item: ident) => {
                if ap.$item {
                    mutators
                        .push(&EVMInput::$item as &dyn Fn(&mut EVMInput, &mut S) -> MutationResult);
                }
            };

            ($item: ident, $cond: expr) => {
                if $cond {
                    mutators
                        .push(&EVMInput::$item as &dyn Fn(&mut EVMInput, &mut S) -> MutationResult);
                }
            };
        }
        add_mutator!(caller);
        add_mutator!(balance, ap.balance.len() > 0);
        if ap.call_value || self.get_txn_value().is_some() {
            mutators
                .push(&EVMInput::call_value as &dyn Fn(&mut EVMInput, &mut S) -> MutationResult);
        }
        add_mutator!(gas_price);
        add_mutator!(basefee);
        add_mutator!(timestamp);
        add_mutator!(coinbase);
        add_mutator!(gas_limit);
        add_mutator!(number);
        add_mutator!(chain_id);
        add_mutator!(prevrandao);

        if mutators.len() == 0 {
            return MutationResult::Skipped;
        }

        let mutator = mutators[state.rand_mut().below(mutators.len() as u64) as usize];
        mutator(self, state)
    }
}

impl VMInputT<EVMState, H160, H160> for EVMInput {
    fn mutate<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: State
            + HasRand
            + HasMaxSize
            + HasItyState<H160, H160, EVMState>
            + HasCaller<H160>
            + HasMetadata,
    {
        if state.rand_mut().next() % 100 > 95 {
            return self.mutate_env_with_access_pattern(state);
        }
        let vm_slots = if let Some(s) = self.get_state().get(&self.get_contract()) {
            Some(s.clone())
        } else {
            None
        };
        match self.data {
            Some(ref mut data) => data.mutate_with_vm_slots(state, vm_slots),
            None => MutationResult::Skipped,
        }
    }

    fn get_caller_mut(&mut self) -> &mut H160 {
        &mut self.caller
    }

    fn get_caller(&self) -> H160 {
        self.caller.clone()
    }

    fn set_caller(&mut self, caller: H160) {
        self.caller = caller;
    }

    fn get_contract(&self) -> H160 {
        self.contract.clone()
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
            concrete_type: BoxedABI::new(Box::new(AEmpty {})),
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

    fn pretty_txn(&self) -> Option<String> {
        match self.data {
            Some(ref d) => Some(format!("{} with {:?} ETH", d.to_string(), self.txn_value)),
            None => None,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn fav_factor(&self) -> f64 {
        if self.sstate.state.flashloan_data.earned > self.sstate.state.flashloan_data.owed {
            return f64::MAX;
        }
        let owed_amount = (
            // should never < 0, otherwise it's a bug
            self.sstate.state.flashloan_data.owed - self.sstate.state.flashloan_data.earned
        );

        if owed_amount == U512::zero() {
            return f64::MAX;
        }

        // hacky convert from U512 -> f64
        let mut res = 0.0;
        for idx in 0..8 {
            res += owed_amount.0[idx] as f64 * (u64::MAX as f64).powi(idx as i32 - 4);
        }
        res
    }

    #[cfg(feature = "evm")]
    fn get_data_abi(&self) -> Option<BoxedABI> {
        self.data.clone()
    }

    #[cfg(any(test, feature = "debug"))]
    fn get_direct_data(&self) -> Vec<u8> {
        self.direct_data.to_vec()
    }

    #[cfg(feature = "evm")]
    fn get_data_abi_mut(&mut self) -> &mut Option<BoxedABI> {
        &mut self.data
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
