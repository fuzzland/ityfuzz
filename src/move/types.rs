use move_binary_format::CompiledModule;
use move_core_types::{account_address::AccountAddress, language_storage::ModuleId};
use move_vm_types::{loaded_data::runtime_types::Type, values::Value};
use serde::{Deserialize, Serialize};

use crate::{
    oracle::OracleCtx,
    r#move::{
        input::{ConciseMoveInput, MoveFunctionInput},
        movevm::MoveVM,
        vm_state::MoveVMState,
    },
    state::{FuzzState, InfantStateState},
    state_input::StagedVMState,
};

pub type MoveAddress = AccountAddress;
pub type MoveSlotTy = u128;
pub type MoveLoc = ModuleId;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MoveOutput {
    #[serde(skip)]
    pub vars: Vec<TypedValue>,
}

impl From<MoveOutput> for Vec<u8> {
    fn from(_output: MoveOutput) -> Self {
        vec![]
    }
}

pub type MoveStagedVMState = StagedVMState<ModuleId, AccountAddress, MoveVMState, ConciseMoveInput>;
pub type MoveInfantStateState = InfantStateState<ModuleId, AccountAddress, MoveVMState, ConciseMoveInput>;

pub type MoveFuzzState =
    FuzzState<MoveFunctionInput, MoveVMState, ModuleId, AccountAddress, MoveOutput, ConciseMoveInput>;

pub type MoveOracleCtx<'a> = OracleCtx<
    'a,
    MoveVMState,
    AccountAddress,
    CompiledModule,
    MoveFunctionInput,
    ModuleId,
    u128,
    MoveOutput,
    MoveFunctionInput,
    MoveFuzzState,
    ConciseMoveInput,
    MoveVM<MoveFunctionInput, MoveFuzzState>,
>;

pub type TypedValue = (Type, Value);
