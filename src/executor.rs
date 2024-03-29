/// Wrapper of smart contract VM, which implements LibAFL [`Executor`]
use std::cell::RefCell;
use std::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
    ops::Deref,
    rc::Rc,
};

use libafl::{
    executors::{Executor, ExitKind},
    inputs::Input,
    prelude::{HasCorpus, HasMetadata, HasObservers, ObserversTuple, UsesInput, UsesObservers},
    state::{State, UsesState},
    Error,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::{ConciseSerde, VMInputT},
    state::HasExecutionResult,
};

/// Wrapper of smart contract VM, which implements LibAFL [`Executor`]
/// TODO: in the future, we may need to add handlers?
/// handle timeout/crash of executing contract
#[allow(clippy::type_complexity)]
pub struct FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    S: UsesInput<Input = I>,
    OT: ObserversTuple<S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// The VM executor
    pub vm: Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI>>>,
    /// Observers (e.g., coverage)
    observers: OT,
    phantom: PhantomData<(I, S, Addr, Out)>,
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI> UsesState
    for FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    S: State + UsesInput<Input = I>,
    OT: ObserversTuple<S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    type State = S;
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI> UsesObservers
    for FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    S: State + UsesInput<Input = I>,
    OT: ObserversTuple<S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    type Observers = OT;
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI> Debug
    for FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    S: State + UsesInput<Input = I>,
    OT: ObserversTuple<S> + Debug,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuzzExecutor")
            // .field("evm_executor", &self.evm_executor)
            .field("observers", &self.observers)
            .finish()
    }
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
    FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    S: UsesInput<Input = I>,
    OT: ObserversTuple<S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Create a new [`FuzzExecutor`]
    #[allow(clippy::type_complexity)]
    pub fn new(
        vm_executor: Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI>>>,
        observers: OT,
    ) -> Self {
        Self {
            vm: vm_executor,
            observers,
            phantom: PhantomData,
        }
    }
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, EM, Z, CI> Executor<EM, Z>
    for FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI> + Input + 'static,
    OT: ObserversTuple<S>,
    S: State + HasExecutionResult<Loc, Addr, VS, Out, CI> + HasCorpus + HasMetadata + UsesInput<Input = I> + 'static,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default + Into<Vec<u8>> + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    /// Run the VM to execute the input
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        let res = self.vm.deref().borrow_mut().execute(input, state);
        // the execution result is added to the fuzzer state
        // later the feedback/objective can run oracle on this result
        state.set_execution_result(res);
        Ok(ExitKind::Ok)
    }
}

// implement HasObservers trait for ItyFuzzer
impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI> HasObservers
    for FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    S: State + UsesInput<Input = I>,
    OT: ObserversTuple<S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Get the observers
    fn observers(&self) -> &OT {
        &self.observers
    }

    /// Get the observers (mutable)
    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}
