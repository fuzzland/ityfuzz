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
    prelude::{HasCorpus, HasMetadata, HasRand, State, Testcase, UsesInput},
    schedulers::Scheduler,
    state::HasClientPerfMonitor,
    Error,
};
use libafl_bolts::Named;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInputT},
        middlewares::sha3_bypass::Sha3TaintAnalysis,
        types::EVMAddress,
        vm::EVMExecutor,
    },
    generic_vm::vm_state::VMStateT,
    input::VMInputT,
    state::{HasCaller, HasCurrentInputIdx, HasItyState},
};

/// A wrapper around a feedback that also performs sha3 taint analysis
/// when the feedback is interesting.
#[allow(clippy::type_complexity)]
pub struct Sha3WrappedFeedback<I, S, VS, F, SC>
where
    S: State + HasCorpus + HasCaller<EVMAddress> + Debug + Clone + HasClientPerfMonitor + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
    F: Feedback<S>,
    SC: Scheduler<State = S> + Clone,
{
    pub inner_feedback: Box<F>,
    pub sha3_taints: Rc<RefCell<Sha3TaintAnalysis>>,
    pub evm_executor: Rc<RefCell<EVMExecutor<I, S, VS, ConciseEVMInput, SC>>>,
    pub enabled: bool,
}

impl<I, S, VS, F, SC> Feedback<S> for Sha3WrappedFeedback<I, S, VS, F, SC>
where
    S: State
        + HasRand
        + HasCorpus
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCaller<EVMAddress>
        + HasCurrentInputIdx
        + HasClientPerfMonitor
        + Default
        + Clone
        + Debug
        + UsesInput<Input = I>
        + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    VS: VMStateT + 'static,
    F: Feedback<S>,
    SC: Scheduler<State = S> + Clone + 'static,
{
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
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
        state: &mut S,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
    {
        self.inner_feedback.as_mut().append_metadata(state, observers, testcase)
    }
}

impl<I, S, VS, F, SC> Sha3WrappedFeedback<I, S, VS, F, SC>
where
    S: State + HasCorpus + HasCaller<EVMAddress> + Debug + Clone + HasClientPerfMonitor + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
    F: Feedback<S>,
    SC: Scheduler<State = S> + Clone,
{
    #[allow(clippy::type_complexity)]
    pub(crate) fn new(
        inner_feedback: F,
        sha3_taints: Rc<RefCell<Sha3TaintAnalysis>>,
        evm_executor: Rc<RefCell<EVMExecutor<I, S, VS, ConciseEVMInput, SC>>>,
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

impl<I, S, VS, F, SC> Named for Sha3WrappedFeedback<I, S, VS, F, SC>
where
    S: State + HasCorpus + HasCaller<EVMAddress> + Debug + Clone + HasClientPerfMonitor + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
    F: Feedback<S>,
    SC: Scheduler<State = S> + Clone,
{
    fn name(&self) -> &str {
        todo!()
    }
}

impl<I, S, VS, F, SC> Debug for Sha3WrappedFeedback<I, S, VS, F, SC>
where
    S: State + HasCorpus + HasCaller<EVMAddress> + Debug + Clone + HasClientPerfMonitor + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
    F: Feedback<S>,
    SC: Scheduler<State = S> + Clone,
{
    fn fmt(&self, _f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        todo!()
    }
}
