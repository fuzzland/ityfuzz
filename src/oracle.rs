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
    pub phantom: PhantomData<Addr>,
    pub post_state: VS,
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

    pub(crate) fn call_pre_batch(&mut self, data: &Vec<(Addr, By)>) -> Vec<Out> {
        self.executor.deref().borrow_mut().fast_static_call(
            data,
            self.pre_state,
            self.fuzz_state,
        )
    }

    pub(crate) fn call_post_batch(&mut self, data: &Vec<(Addr, By)>) -> Vec<Out> {
        self.executor.deref().borrow_mut().fast_static_call(
            data,
            &self.post_state,
            self.fuzz_state,
        )
    }
}

pub trait Producer<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    fn produce(&mut self, ctx: &mut OracleCtx<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>);
    fn notify_end(&mut self, ctx: &mut OracleCtx<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>);
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
