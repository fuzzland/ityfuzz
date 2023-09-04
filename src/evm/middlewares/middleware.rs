use crate::evm::host::FuzzHost;
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasItyState};

use bytes::Bytes;
use libafl::corpus::{Corpus, Testcase};
use libafl::inputs::Input;
use libafl::schedulers::Scheduler;
use libafl::state::{HasCorpus, HasMetadata, State};
use primitive_types::U512;
use serde::{Deserialize, Serialize};

use std::clone::Clone;
use std::fmt::Debug;

use std::time::Duration;
use revm_interpreter::Interpreter;
use revm_primitives::Bytecode;
use crate::evm::types::{EVMAddress, EVMU256};

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

pub fn add_corpus<VS, I, S>(host: &FuzzHost<VS, I, S>, state: &mut S, input: &EVMInput)
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCaller<EVMAddress>
        + Clone
        + Debug
        + 'static,
    VS: VMStateT + Default,
{
    let mut tc = Testcase::new(input.as_any().downcast_ref::<I>().unwrap().clone()) as Testcase<I>;
    tc.set_exec_time(Duration::from_secs(0));
    let idx = state.corpus_mut().add(tc).expect("failed to add");
    host.scheduler
        .on_add(state, idx)
        .expect("failed to call scheduler on_add");
}

pub trait Middleware<VS, I, S>: Debug
where
    S: State + HasCaller<EVMAddress> + Clone + Debug,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S>,
        state: &mut S,
    );

    unsafe fn on_return(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S>,
        state: &mut S,
        ret: &Bytes
    ) {}

    unsafe fn on_insert(&mut self,
                        bytecode: &mut Bytecode,
                        address: EVMAddress,
                        host: &mut FuzzHost<VS, I, S>,
                        state: &mut S);
    fn get_type(&self) -> MiddlewareType;
}
