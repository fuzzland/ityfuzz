use std::cell::RefCell;
use crate::generic_vm::vm_executor::{ExecutionResult, GenericVM};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{FuzzState, HasExecutionResult, HasItyState};
use crate::state_input::StagedVMState;
use hex;
use libafl::prelude::{tuple_list, HasCorpus, HasMetadata, SerdeAnyMap};
use libafl::state::State;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Deref;
use std::rc::Rc;

pub struct OracleCtx<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S: 'static>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    pub fuzz_state: &'a mut S,
    pub pre_state: &'a VS,
    pub metadata: SerdeAnyMap,
    pub executor: &'a mut Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S>>>,
    pub input: &'a I,
    pub phantom: PhantomData<(Addr)>,
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
    OracleCtx<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
where
    I: VMInputT<VS, Loc, Addr> + 'static,
    S: State + HasCorpus<I> + HasMetadata + HasExecutionResult<Loc, Addr, VS, Out>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default
{
    pub fn new(
        fuzz_state: &'a mut S,
        pre_state: &'a VS,
        executor: &'a mut Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S>>>,
        input: &'a I,
    ) -> Self {
        Self {
            fuzz_state,
            pre_state,
            metadata: SerdeAnyMap::new(),
            executor,
            input,
            phantom: Default::default(),
        }
    }

    pub(crate) fn call_pre(&mut self, input: &mut I) -> ExecutionResult<Loc, Addr, VS, Out> {
        input.set_staged_state(StagedVMState::new_with_state(self.pre_state.clone()), 0);
        self.executor.deref().borrow_mut().execute(
            input,
            &mut self.fuzz_state
        )
    }

    pub(crate) fn call_post(&mut self, input: &mut I) -> ExecutionResult<Loc, Addr, VS, Out> {
        input.set_staged_state(StagedVMState::new_with_state(self.fuzz_state.get_execution_result().new_state.state.clone()), 0);
        self.executor.deref().borrow_mut().execute(
            input,
            &mut self.fuzz_state
        )
    }
}

pub trait Oracle<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    fn transition(
        &self,
        ctx: &mut OracleCtx<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>,
        stage: u64,
    ) -> u64;
    fn oracle(
        &self,
        ctx: &mut OracleCtx<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>,
        stage: u64,
    ) -> bool;
}
