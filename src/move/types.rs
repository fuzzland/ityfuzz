use crate::r#move::input::MoveFunctionInput;
use crate::r#move::vm_state::MoveVMState;
use crate::state_input::StagedVMState;

use move_core_types::account_address::AccountAddress;
use move_core_types::language_storage::ModuleId;
use move_vm_types::loaded_data::runtime_types::Type;
use move_vm_types::values::Value;
use serde::{Deserialize, Serialize};
use crate::state::FuzzState;

pub type MoveAddress = AccountAddress;
pub type MoveSlotTy = (ModuleId, Vec<usize>);

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MoveOutput {
    #[serde(skip)]
    pub vars: Vec<TypedValue>
}

pub type MoveStagedVMState = StagedVMState<ModuleId, AccountAddress, MoveVMState>;
pub type MoveFuzzState = FuzzState<
    MoveFunctionInput, MoveVMState, ModuleId, AccountAddress, MoveOutput
>;

pub type TypedValue = (Type, Value);
// pub type MoveVMTy<I, S> = dyn ;
