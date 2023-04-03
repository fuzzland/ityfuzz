use crate::evm::abi::get_abi_type_boxed;
use crate::evm::contract_utils::ContractLoader;
use crate::evm::input::{EVMInput, EVMInputT};
use crate::evm::vm::{FuzzHost, IntermediateExecutionResult};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasItyState, HasCurrentInputIdx};
use crate::state_input::StagedVMState;
use bytes::Bytes;
use libafl::corpus::{Corpus, Testcase};
use libafl::inputs::Input;
use libafl::schedulers::Scheduler;
use libafl::state::{HasCorpus, HasMetadata, State};
use primitive_types::{H160, U256, U512};
use revm::{Bytecode, Interpreter};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::clone::Clone;
use std::fmt::Debug;
use std::ops::Deref;
use std::time::Duration;

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Copy)]
pub enum MiddlewareType {
    OnChain,
    Concolic,
    Flashloan,
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
    UpdateSlot(MiddlewareType, H160, U256, U256),
    UpdateCode(MiddlewareType, H160, Bytecode),
    AddCorpus(MiddlewareType, String, H160),
    AddCaller(MiddlewareType, H160),
    AddAddress(MiddlewareType, H160),
    AddBlacklist(MiddlewareType, H160),
    Owed(MiddlewareType, U512),
    Earned(MiddlewareType, U512),
    MakeSubsequentCallSuccess(Bytes),
}

pub fn add_corpus<VS, I, S>(host: &FuzzHost<VS, I, S>, state: &mut S, input: &EVMInput)
where
    I: Input + VMInputT<VS, H160, H160> + EVMInputT + 'static,
    S: State
        + HasCorpus<I>
        + HasItyState<H160, H160, VS>
        + HasMetadata
        + HasCaller<H160>
        + Clone
        + Debug
        + 'static,
    VS: VMStateT + Default,
{
    let mut tc =
        Testcase::new(input.as_any().downcast_ref::<I>().unwrap().clone()) as Testcase<I>;
    tc.set_exec_time(Duration::from_secs(0));
    let idx = state.corpus_mut().add(tc).expect("failed to add");
    host.scheduler
        .on_add(state, idx)
        .expect("failed to call scheduler on_add");
}

pub trait Middleware<VS, I, S>: Debug
where
    S: State + HasCaller<H160> + Clone + Debug,
    I: VMInputT<VS, H160, H160> + EVMInputT,
    VS: VMStateT,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<VS, I, S>, state: &mut S);
    fn get_type(&self) -> MiddlewareType;
}
