use std::cell::RefCell;
use std::rc::Rc;
use crate::evm::abi::{AEmpty, AUnknown, BoxedABI};
use crate::evm::types::EVMStagedVMState;
use crate::evm::vm::EVMState;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasItyState};
use crate::state_input::StagedVMState;
use bytes::Bytes;
use libafl::bolts::HasLen;
use libafl::inputs::Input;
use libafl::mutators::MutationResult;
use libafl::prelude::{HasMaxSize, HasRand, State};
use primitive_types::{H160, U512};
use revm::{Env, Interpreter};
use serde::{Deserialize, Serialize};
use serde_traitobject::Any;
use crate::types::convert_u256_to_h160;

pub trait EVMInputT {
    fn to_bytes(&self) -> Vec<u8>;
    fn set_vm_env(&mut self, env: &Env);
    fn get_vm_env(&self) -> &Env;
    fn get_access_pattern(&self) -> &Rc<RefCell<AccessPattern>>;
}

// each mutant should report to its source's access pattern
// if a new corpus item is added, it should inherit the access pattern of its source
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessPattern {
    caller: bool, // or origin
    balance: Vec<H160>, // balance queried for accounts
    call_value: bool,
    gas_price: bool,
    block_number: bool,
    coinbase: bool,
    timestamp: bool,
    prevrandao: bool,
    gas_limit: bool,
    chain_id: bool,
    base_fee: bool,
}

impl AccessPattern {
    pub fn new() -> Self {
        Self {
            balance: vec![],
            caller: false,
            call_value: false,
            gas_price: false,
            block_number: false,
            coinbase: false,
            timestamp: false,
            prevrandao: false,
            gas_limit: false,
            chain_id: false,
            base_fee: false,
        }
    }

    pub fn decode_instruction(&mut self, interp: &Interpreter) {
        match unsafe {*interp.instruction_pointer} {
            0x31 => self.balance.push(
                convert_u256_to_h160(interp.stack.peek(0).unwrap())
            ),
            0x33 => self.caller = true,
            0x34 => self.call_value = true,
            0x3a => self.gas_price = true,
            0x43 => self.block_number = true,
            0x41 => self.coinbase = true,
            0x42 => self.timestamp = true,
            0x44 => self.prevrandao = true,
            0x45 => self.gas_limit = true,
            0x46 => self.chain_id = true,
            0x48 => self.base_fee = true,
            _ => {}
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EVMInput {
    pub caller: H160,
    pub contract: H160,
    pub data: Option<BoxedABI>,
    pub sstate: StagedVMState<H160, H160, EVMState>,
    pub sstate_idx: usize,
    pub txn_value: Option<usize>,
    pub step: bool,
    pub env: Env,
    pub access_pattern: Rc<RefCell<AccessPattern>>,

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

    fn set_vm_env(&mut self, env: &Env) {
        self.env = env.clone();
    }

    fn get_vm_env(&self) -> &Env {
        &self.env
    }

    fn get_access_pattern(&self) -> &Rc<RefCell<AccessPattern>> {
        &self.access_pattern
    }
}

impl VMInputT<EVMState, H160, H160> for EVMInput {
    fn mutate<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: State + HasRand + HasMaxSize + HasItyState<H160, H160, EVMState> + HasCaller<H160>,
    {
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

    fn get_txn_value(&self) -> Option<usize> {
        self.txn_value
    }

    fn set_txn_value(&mut self, v: usize) {
        self.txn_value = Some(v);
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
