use crate::evm::abi::BoxedABI;
use crate::input::VMInputT;
use crate::r#move::types::MoveStagedVMState;
use crate::r#move::vm_state::MoveVMState;
use crate::state::{HasCaller, HasItyState};
use crate::state_input::StagedVMState;
use libafl::inputs::Input;
use libafl::prelude::{HasMaxSize, MutationResult, State};
use libafl::state::HasRand;
use move_binary_format::normalized::Module;
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::{ModuleId, TypeTag};
use move_core_types::value::MoveTypeLayout;
use move_vm_runtime::move_vm::MoveVM;
use move_vm_types::values::{Value, ValueImpl};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::any;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

pub trait MoveFunctionInputT {
    fn module_id(&self) -> &ModuleId;
    fn function_name(&self) -> &Identifier;
    fn args(&self) -> &Vec<CloneableValue>;
    fn ty_args(&self) -> &Vec<TypeTag>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveFunctionInput {
    pub module: ModuleId,
    pub function: Identifier,
    pub args: Vec<CloneableValue>,
    pub ty_args: Vec<TypeTag>,

    pub caller: AccountAddress,

    pub vm_state: MoveStagedVMState,
    pub vm_state_idx: usize,
}

impl MoveFunctionInput {}

#[derive(Debug)]
pub struct CloneableValue {
    pub value: Value,
}

impl Clone for CloneableValue {
    fn clone(&self) -> Self {
        CloneableValue {
            value: self.value.clone(),
        }
    }
}

impl Serialize for CloneableValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        unreachable!()
    }
}

impl<'de> Deserialize<'de> for CloneableValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        unreachable!()
    }
}

impl MoveFunctionInputT for MoveFunctionInput {
    fn module_id(&self) -> &ModuleId {
        &self.module
    }

    fn function_name(&self) -> &Identifier {
        &self.function
    }

    fn args(&self) -> &Vec<CloneableValue> {
        &self.args
    }

    fn ty_args(&self) -> &Vec<TypeTag> {
        &self.ty_args
    }
}

impl Input for MoveFunctionInput {
    fn generate_name(&self, idx: usize) -> String {
        format!("{}_{}_{}", idx, self.module, self.function)
    }
}

impl VMInputT<MoveVMState, ModuleId, AccountAddress> for MoveFunctionInput {
    fn mutate<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: State
            + HasRand
            + HasMaxSize
            + HasItyState<ModuleId, AccountAddress, MoveVMState>
            + HasCaller<AccountAddress>,
    {
        unimplemented!()
    }
    fn get_caller_mut(&mut self) -> &mut AccountAddress {
        &mut self.caller
    }

    fn get_caller(&self) -> AccountAddress {
        self.caller
    }

    fn set_caller(&mut self, caller: AccountAddress) {
        self.caller = caller;
    }

    fn get_contract(&self) -> AccountAddress {
        self.module.address().clone()
    }
    fn get_state(&self) -> &MoveVMState {
        &self.vm_state.state
    }

    fn get_state_mut(&mut self) -> &mut MoveVMState {
        &mut self.vm_state.state
    }

    fn set_staged_state(&mut self, state: MoveStagedVMState, idx: usize) {
        self.vm_state = state;
        self.vm_state_idx = idx;
    }
    fn get_state_idx(&self) -> usize {
        self.vm_state_idx
    }
    fn get_staged_state(&self) -> &MoveStagedVMState {
        &self.vm_state
    }
    fn get_txn_value(&self) -> Option<usize> {
        panic!("MoveVM does not have a txn value")
    }
    fn set_txn_value(&mut self, v: usize) {
        panic!("MoveVM does not have a txn value")
    }
    // fn get_abi_cloned(&self) -> Option<BoxedABI>;
    fn set_as_post_exec(&mut self, out_size: usize) {
        todo!()
    }

    fn is_step(&self) -> bool {
        todo!()
    }

    fn set_step(&mut self, gate: bool) {
        todo!()
    }

    fn pretty_txn(&self) -> Option<String> {
        Some(format!(
            "{}::{}({:?})",
            self.module, self.function, self.args
        ))
    }
    fn as_any(&self) -> &dyn any::Any {
        self
    }

    fn fav_factor(&self) -> f64 {
        todo!()
    }

    #[cfg(feature = "evm")]
    fn get_data_abi(&self) -> Option<BoxedABI> {
        unreachable!("MoveVM does not have an ABI")
    }

    #[cfg(any(test, feature = "debug"))]
    fn get_direct_data(&self) -> Vec<u8> {
        todo!()
    }
}
