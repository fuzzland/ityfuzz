use crate::evm::host::FuzzHost;
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT};
use crate::evm::vm::EVMState;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasItyState};

use bytes::Bytes;
use libafl::corpus::{Corpus, Testcase};
use libafl::inputs::Input;
use libafl::prelude::UsesInput;
use libafl::schedulers::Scheduler;
use libafl::state::{HasCorpus, HasMetadata, State};
use primitive_types::U512;
use serde::{Deserialize, Serialize};

use std::clone::Clone;
use std::fmt::Debug;

use crate::evm::types::{EVMAddress, EVMU256};
use revm_interpreter::Interpreter;
use revm_primitives::Bytecode;
use std::time::Duration;

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Copy)]
pub enum MiddlewareType {
    OnChain,
    Concolic,
    Flashloan,
    Selfdestruct,
    InstructionCoverage,
    BranchCoverage,
    Sha3Bypass,
    Sha3TaintAnalysis,
    CallPrinter,
    Reentrancy
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Copy)]
pub enum ExecutionStage {
    Call,
    Create,
    Log,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallMiddlewareReturn {
    Continue,
    ReturnRevert,
    ReturnSuccess(Bytes),
}

#[derive(Clone, Debug)]
pub enum MiddlewareOp {
    UpdateSlot(MiddlewareType, EVMAddress, EVMU256, EVMU256),
    UpdateCode(MiddlewareType, EVMAddress, Bytecode),
    AddCorpus(MiddlewareType, String, EVMAddress),
    AddCaller(MiddlewareType, EVMAddress),
    AddAddress(MiddlewareType, EVMAddress),
    AddBlacklist(MiddlewareType, EVMAddress),
    Owed(MiddlewareType, U512),
    Earned(MiddlewareType, U512),
    MakeSubsequentCallSuccess(Bytes),
}

pub fn add_corpus<VS, I, S, SC>(host: &mut FuzzHost<VS, I, S, SC>, state: &mut S, input: &EVMInput)
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        + HasCorpus
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCaller<EVMAddress>
        + Clone
        + Debug
        + UsesInput<Input = I>
        + 'static,
    VS: VMStateT + Default,
    SC: Scheduler<State = S> + Clone,
{
    let mut tc = Testcase::new(input.as_any().downcast_ref::<I>().unwrap().clone()) as Testcase<I>;
    tc.set_exec_time(Duration::from_secs(0));
    let idx = state.corpus_mut().add(tc).expect("failed to add");
    host.scheduler
        .on_add(state, idx)
        .expect("failed to call scheduler on_add");
}

pub trait Middleware<VS, I, S, SC>: Debug
where
    S: State + HasCorpus + HasCaller<EVMAddress> + Clone + Debug,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
    SC: Scheduler<State = S> + Clone,
{
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S, SC>,
        state: &mut S,
    );

    unsafe fn on_return(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S, SC>,
        state: &mut S,
        ret: &Bytes,
    ) { }

    unsafe fn before_execute(
        &mut self,
        interp: Option<&mut Interpreter>,
        host: &mut FuzzHost<VS, I, S, SC>,
        state: &mut S,
        is_step: bool,
        data: &mut Bytes,
        evm_state: &mut EVMState,
    ) { }

    unsafe fn on_insert(&mut self,
                        interp: Option<&mut Interpreter>,
                        host: &mut FuzzHost<VS, I, S, SC>,
                        state: &mut S,
                        bytecode: &mut Bytecode,
                        address: EVMAddress,
                    ) {}
    fn get_type(&self) -> MiddlewareType;
}
