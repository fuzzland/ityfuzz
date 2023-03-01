use crate::generic_vm::vm_executor::GenericVM;
use crate::r#move::input::MoveFunctionInput;
use crate::r#move::vm_state::MoveVMState;
use move_binary_format::CompiledModule;
use move_core_types::account_address::AccountAddress;
use move_core_types::language_storage::ModuleId;
use move_vm_types::values;

pub type MoveAddress = AccountAddress;
pub type MoveSlotTy = (ModuleId, Vec<usize>);
// pub type MoveVMTy<I, S> = dyn ;
