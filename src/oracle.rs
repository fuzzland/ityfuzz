/// Implementation of the oracle (i.e., invariant checker)

use crate::generic_vm::vm_executor::GenericVM;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::HasExecutionResult;

use libafl::prelude::{HasCorpus, HasMetadata, SerdeAnyMap};
use libafl::state::State;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::cell::RefCell;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Deref;
use std::rc::Rc;

/// The context passed to the oracle
pub struct OracleCtx<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S: 'static>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// The state of the fuzzer
    pub fuzz_state: &'a mut S,
    /// The VMState before the execution
    pub pre_state: &'a VS,
    /// The VMState after the execution
    pub post_state: VS,
    /// The metadata of the oracle
    pub metadata: SerdeAnyMap,
    /// The executor
    pub executor: &'a mut Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S>>>,
    /// The input executed by the VM
    pub input: &'a I,
    pub phantom: PhantomData<Addr>,
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
    OracleCtx<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
where
    I: VMInputT<VS, Loc, Addr> + 'static,
    S: State + HasCorpus<I> + HasMetadata + HasExecutionResult<Loc, Addr, VS, Out>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Create a new oracle context
    pub fn new(
        fuzz_state: &'a mut S,
        pre_state: &'a VS,
        executor: &'a mut Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S>>>,
        input: &'a I,
    ) -> Self {
        Self {
            post_state: fuzz_state.get_execution_result().new_state.state.clone(),
            fuzz_state,
            pre_state,
            metadata: SerdeAnyMap::new(),
            executor,
            input,
            phantom: Default::default(),
        }
    }

    /// Conduct a batch of static calls on the state before the execution
    pub(crate) fn call_pre_batch(&mut self, data: &Vec<(Addr, By)>) -> Vec<Out> {
        self.executor.deref().borrow_mut().fast_static_call(
            data,
            self.pre_state,
            self.fuzz_state,
        )
    }

    /// Conduct a batch of static calls on the state after the execution
    pub(crate) fn call_post_batch(&mut self, data: &Vec<(Addr, By)>) -> Vec<Out> {
        self.executor.deref().borrow_mut().fast_static_call(
            data,
            &self.post_state,
            self.fuzz_state,
        )
    }
}


/// Producer trait provides functions needed to produce data for the oracle
pub trait Producer<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Produce data for the oracle, called everytime before any oracle is called
    fn produce(&mut self, ctx: &mut OracleCtx<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>);
    /// Cleanup. Called everytime after the oracle is called
    fn notify_end(&mut self, ctx: &mut OracleCtx<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>);
}

/// Oracle trait provides functions needed to implement an oracle
pub trait Oracle<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Transition function, called everytime after non-reverted execution
    fn transition(
        &self,
        ctx: &mut OracleCtx<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>,
        stage: u64,
    ) -> u64;

    /// Oracle function, called everytime after non-reverted execution
    /// Returns true if the oracle is violated
    fn oracle(
        &self,
        ctx: &mut OracleCtx<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>,
        stage: u64,
    ) -> bool;
}
