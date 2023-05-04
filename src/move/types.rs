use crate::r#move::input::MoveFunctionInput;
use crate::r#move::vm_state::MoveVMState;
use crate::state_input::StagedVMState;

use move_core_types::account_address::AccountAddress;
use move_core_types::language_storage::ModuleId;
use move_vm_types::loaded_data::runtime_types::Type;
use move_vm_types::values::Value;

pub type MoveAddress = AccountAddress;
pub type MoveSlotTy = (ModuleId, Vec<usize>);
pub type MoveStagedVMState = StagedVMState<ModuleId, AccountAddress, MoveVMState>;
pub type TypedValue = (Type, Value);
pub type MoveOutput = Vec<TypedValue>;
// pub type MoveVMTy<I, S> = dyn ;
