use crate::evm::input::EVMInput;
use crate::evm::mutator::FuzzMutator;
use crate::evm::vm::EVMState;
use crate::generic_vm::vm_executor::GenericVM;
use crate::input::VMInputT;
use crate::oracle::OracleCtx;
use crate::scheduler::SortedDroppingScheduler;
use crate::state::{FuzzState, InfantStateState};
use crate::state_input::StagedVMState;
use bytes::Bytes;
use primitive_types::{H160, U256};
use revm::Bytecode;

pub type EVMFuzzState = FuzzState<EVMInput, EVMState, H160, H160, Vec<u8>>;
pub type EVMOracleCtx<'a> =
    OracleCtx<'a, EVMState, H160, Bytecode, Bytes, H160, U256, Vec<u8>, EVMInput, EVMFuzzState>;

pub type EVMFuzzMutator<'a> = FuzzMutator<
    'a,
    EVMState,
    H160,
    H160,
    SortedDroppingScheduler<
        StagedVMState<H160, H160, EVMState>,
        InfantStateState<H160, H160, EVMState>,
    >,
>;

pub type EVMInfantStateState = InfantStateState<H160, H160, EVMState>;

pub type EVMStagedVMState = StagedVMState<H160, H160, EVMState>;
