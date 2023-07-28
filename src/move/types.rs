use move_binary_format::CompiledModule;
use crate::r#move::input::{ConciseMoveInput, MoveFunctionInput};
use crate::r#move::vm_state::MoveVMState;
use crate::state_input::StagedVMState;

use move_core_types::account_address::AccountAddress;
use move_core_types::language_storage::ModuleId;
use move_vm_types::loaded_data::runtime_types::Type;
use move_vm_types::values::Value;
use serde::{Deserialize, Serialize};
use crate::oracle::{Oracle, OracleCtx};
use crate::state::{FuzzState, InfantStateState};

pub type MoveAddress = AccountAddress;
pub type MoveSlotTy = u128;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MoveOutput {
    #[serde(skip)]
    pub vars: Vec<TypedValue>
}

pub type MoveStagedVMState = StagedVMState<ModuleId, AccountAddress, MoveVMState, ConciseMoveInput>;
pub type MoveInfantStateState = InfantStateState<ModuleId, AccountAddress, MoveVMState, ConciseMoveInput>;

pub type MoveFuzzState = FuzzState<
    MoveFunctionInput, MoveVMState, ModuleId, AccountAddress, MoveOutput, ConciseMoveInput
>;

pub type MoveOracleCtx<'a> = OracleCtx<'a, MoveVMState, AccountAddress, CompiledModule, MoveFunctionInput, ModuleId, u128, MoveOutput, MoveFunctionInput, MoveFuzzState, ConciseMoveInput>;

pub type TypedValue = (Type, Value);

