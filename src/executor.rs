/// Wrapper of smart contract VM, which implements LibAFL [`Executor`]
use std::cell::RefCell;
use std::fmt::Formatter;
use std::marker::PhantomData;

use crate::evm::input::EVMInput;
use libafl::executors::{Executor, ExitKind};
use libafl::inputs::Input;
use libafl::prelude::{HasCorpus, HasMetadata, HasObservers, ObserversTuple, UsesInput, UsesObservers};
use libafl::state::{State, UsesState};
use libafl::Error;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::ops::Deref;
use std::rc::Rc;

use crate::generic_vm::vm_executor::GenericVM;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::{ConciseSerde, VMInputT};
use crate::state::HasExecutionResult;

/// Wrapper of smart contract VM, which implements LibAFL [`Executor`]
/// TODO: in the future, we may need to add handlers?
/// handle timeout/crash of executing contract
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
    S: UsesInput<Input = I>,
    OT: ObserversTuple<S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde
{
    type State = S;
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI> UsesObservers
    for FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    S: UsesInput<Input = I>,
    OT: ObserversTuple<S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde
{
    type Observers = OT;
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI> Debug
    for FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    S: UsesInput<Input = I>,
    OT: ObserversTuple<S>,
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
    Out: Default,
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
    S: UsesInput<Input = I>,
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
