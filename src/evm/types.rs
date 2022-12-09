use crate::evm::input::EVMInput;
use crate::evm::vm::EVMState;
use crate::mutator::FuzzMutator;
use crate::oracle::OracleCtx;
use crate::scheduler::SortedDroppingScheduler;
use crate::state::{FuzzState, InfantStateState};
use crate::state_input::StagedVMState;
use bytes::Bytes;
use primitive_types::{H160, U256};
use revm::Bytecode;

pub type EVMFuzzState = FuzzState<EVMInput, EVMState, H160>;
pub type EVMOracleCtx<'a> =
    OracleCtx<'a, EVMState, H160, Bytecode, Bytes, H160, U256, EVMInput, EVMFuzzState>;

pub type EVMFuzzMutator<'a> = FuzzMutator<
    'a,
    EVMState,
    H160,
    SortedDroppingScheduler<StagedVMState<EVMState>, InfantStateState<EVMState>>,
>;
