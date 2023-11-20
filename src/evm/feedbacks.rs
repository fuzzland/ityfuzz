use std::{
    cell::RefCell,
    fmt::{Debug, Formatter},
    ops::Deref,
    rc::Rc,
};

use libafl::{
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    observers::ObserversTuple,
    prelude::Testcase,
    schedulers::Scheduler,
    Error,
};
use libafl_bolts::Named;

use super::{input::EVMInput, types::EVMFuzzState};
use crate::{
    evm::{input::ConciseEVMInput, middlewares::sha3_bypass::Sha3TaintAnalysis, vm::EVMExecutor},
    generic_vm::vm_state::VMStateT,
    input::VMInputT,
};

/// A wrapper around a feedback that also performs sha3 taint analysis
/// when the feedback is interesting.
#[allow(clippy::type_complexity)]
pub struct Sha3WrappedFeedback<VS, F, SC>
where
    VS: VMStateT,
    F: Feedback<EVMFuzzState>,
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    pub inner_feedback: Box<F>,
    pub sha3_taints: Rc<RefCell<Sha3TaintAnalysis>>,
    pub evm_executor: Rc<RefCell<EVMExecutor<VS, ConciseEVMInput, SC>>>,
    pub enabled: bool,
}

impl<VS, F, SC> Feedback<EVMFuzzState> for Sha3WrappedFeedback<VS, F, SC>
where
    VS: VMStateT + 'static,
    F: Feedback<EVMFuzzState>,
    SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
{
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut EVMFuzzState,
        manager: &mut EM,
        input: &EVMInput,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = EVMFuzzState>,
        OT: ObserversTuple<EVMFuzzState>,
    {
        // checks if the inner feedback is interesting
        if self.enabled {
            match self
                .inner_feedback
                .is_interesting(state, manager, input, observers, exit_kind)
            {
                Ok(true) => {
                    if !input.is_step() {
                        // reexecute with sha3 taint analysis
                        self.sha3_taints.deref().borrow_mut().cleanup();

                        (self.evm_executor.deref().borrow_mut()).reexecute_with_middleware(
                            input,
                            state,
                            self.sha3_taints.clone(),
                        );
                    }
                    Ok(true)
                }
                Ok(false) => Ok(false),
                Err(e) => Err(e),
            }
        } else {
            self.inner_feedback
                .is_interesting(state, manager, input, observers, exit_kind)
        }
    }

    #[inline]
    #[allow(unused_variables)]
    fn append_metadata<OT>(
        &mut self,
        state: &mut EVMFuzzState,
        observers: &OT,
        testcase: &mut Testcase<EVMInput>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<EVMFuzzState>,
    {
        self.inner_feedback.as_mut().append_metadata(state, observers, testcase)
    }
}

impl<VS, F, SC> Sha3WrappedFeedback<VS, F, SC>
where
    VS: VMStateT,
    F: Feedback<EVMFuzzState>,
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    #[allow(clippy::type_complexity)]
    pub(crate) fn new(
        inner_feedback: F,
        sha3_taints: Rc<RefCell<Sha3TaintAnalysis>>,
        evm_executor: Rc<RefCell<EVMExecutor<VS, ConciseEVMInput, SC>>>,
        enabled: bool,
    ) -> Self {
        Self {
            inner_feedback: Box::new(inner_feedback),
            sha3_taints,
            evm_executor,
            enabled,
        }
    }
}

impl<VS, F, SC> Named for Sha3WrappedFeedback<VS, F, SC>
where
    VS: VMStateT,
    F: Feedback<EVMFuzzState>,
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    fn name(&self) -> &str {
        todo!()
    }
}

impl<VS, F, SC> Debug for Sha3WrappedFeedback<VS, F, SC>
where
    VS: VMStateT,
    F: Feedback<EVMFuzzState>,
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    fn fmt(&self, _f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        todo!()
    }
}
