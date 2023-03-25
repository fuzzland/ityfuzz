use std::fmt::Formatter;
use std::marker::PhantomData;

use libafl::executors::{Executor, ExitKind};
use libafl::inputs::Input;
use libafl::prelude::{HasCorpus, HasMetadata, HasObservers, ObserversTuple};
use libafl::state::State;
use libafl::Error;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

use crate::generic_vm::vm_executor::GenericVM;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::HasExecutionResult;
use crate::tracer::build_basic_txn;

// TODO: in the future, we may need to add handlers?
// handle timeout/crash of executing contract
pub struct FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT>
where
    I: VMInputT<VS, Loc, Addr>,
    OT: ObserversTuple<I, S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    pub vm: Box<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S>>,
    observers: OT,
    phantom: PhantomData<(I, S, Addr, Out)>,
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT> Debug
    for FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT>
where
    I: VMInputT<VS, Loc, Addr>,
    OT: ObserversTuple<I, S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuzzExecutor")
            // .field("evm_executor", &self.evm_executor)
            .field("observers", &self.observers)
            .finish()
    }
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT>
    FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT>
where
    I: VMInputT<VS, Loc, Addr>,
    OT: ObserversTuple<I, S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    pub fn new(
        vm_executor: Box<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S>>,
        observers: OT,
    ) -> Self {
        Self {
            vm: vm_executor,
            observers,
            phantom: PhantomData,
        }
    }
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, EM, Z> Executor<EM, I, S, Z>
    for FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT>
where
    I: VMInputT<VS, Loc, Addr> + Input + 'static,
    OT: ObserversTuple<I, S>,
    S: State + HasExecutionResult<Loc, Addr, VS, Out> + HasCorpus<I> + HasMetadata + 'static,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        let mut res = self.vm.execute(input, Some(state));

        // add the trace of the new state
        #[cfg(any(feature = "print_infant_corpus", feature = "print_txn_corpus"))]
        {
            res.new_state.trace.from_idx = Some(input.get_state_idx());
            res.new_state.trace.add_txn(build_basic_txn(input));
        }

        // the execution result is added to the fuzzer state
        // later the feedback/objective can run oracle on this result
        state.set_execution_result(res);
        Ok(ExitKind::Ok)
    }
}

// implement HasObservers trait for ItyFuzzer
impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT> HasObservers<I, OT, S>
    for FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT>
where
    I: VMInputT<VS, Loc, Addr>,
    OT: ObserversTuple<I, S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    fn observers(&self) -> &OT {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}
