use std::cell::RefCell;
use std::fmt::{Debug, Formatter};
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use libafl::Error;
use libafl::events::EventFirer;
use libafl::executors::ExitKind;
use libafl::feedbacks::Feedback;
use libafl::inputs::Input;
use libafl::observers::ObserversTuple;
use libafl::prelude::{HasCorpus, HasMetadata, HasRand, Named, State};
use libafl::state::HasClientPerfMonitor;
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT};
use crate::evm::middlewares::sha3_bypass::Sha3TaintAnalysis;
use crate::evm::types::EVMAddress;
use crate::evm::vm::EVMExecutor;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasItyState};

/// A wrapper around a feedback that also performs sha3 taint analysis
/// when the feedback is interesting.
pub struct Sha3WrappedFeedback<I, S, VS, F>
    where S: State + HasCaller<EVMAddress> + Debug + Clone + HasClientPerfMonitor + 'static,
          I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
          VS: VMStateT,
          F: Feedback<I, S>
{
    pub inner_feedback: Box<F>,
    pub sha3_taints: Rc<RefCell<Sha3TaintAnalysis>>,
    pub evm_executor: Rc<RefCell<EVMExecutor<I, S, VS, ConciseEVMInput>>>,
    pub enabled: bool,
}



impl<I, S, VS, F> Feedback<I, S> for Sha3WrappedFeedback<I, S, VS, F>
where S: State + HasRand
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCaller<EVMAddress>
        + HasCurrentInputIdx
        + HasClientPerfMonitor
        + Default
        + Clone
        + Debug
        + 'static,
      I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
      VS: VMStateT + 'static,
      F: Feedback<I, S>
{
    fn is_interesting<EM, OT>(&mut self,
                              state: &mut S,
                              manager: &mut EM,
                              input: &I,
                              observers: &OT,
                              exit_kind: &ExitKind)
        -> Result<bool, Error> where EM: EventFirer<I>, OT: ObserversTuple<I, S> {
        // checks if the inner feedback is interesting
        if self.enabled {
            match self.inner_feedback.is_interesting(state, manager, input, observers, exit_kind) {
                Ok(true) => {
                    {
                        // reexecute with sha3 taint analysis
                        (*self.evm_executor.borrow_mut()).reexecute_with_middleware(
                            input,
                            state,
                            self.sha3_taints.clone(),
                        );
                    }
                    Ok(true)
                },
                Ok(false) => Ok(false),
                Err(e) => Err(e)
            }
        } else {
            self.inner_feedback.is_interesting(state, manager, input, observers, exit_kind)
        }
    }
}


impl<I, S, VS, F> Sha3WrappedFeedback<I, S, VS, F>
    where S: State + HasCaller<EVMAddress> + Debug + Clone + HasClientPerfMonitor + 'static,
          I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
          VS: VMStateT,
          F: Feedback<I, S>{
    pub(crate) fn new(inner_feedback: F,
                      sha3_taints: Rc<RefCell<Sha3TaintAnalysis>>,
                      evm_executor: Rc<RefCell<EVMExecutor<I, S, VS, ConciseEVMInput>>>,
                      enabled: bool
    ) -> Self {
        Self {
            inner_feedback: Box::new(inner_feedback),
            sha3_taints,
            evm_executor,
            enabled
        }
    }
}

impl<I, S, VS, F> Named for Sha3WrappedFeedback<I, S, VS, F>
    where S: State + HasCaller<EVMAddress> + Debug + Clone + HasClientPerfMonitor + 'static,
          I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
          VS: VMStateT,
          F: Feedback<I, S>{
    fn name(&self) -> &str {
        todo!()
    }
}

impl<I, S, VS, F> Debug for Sha3WrappedFeedback<I, S, VS, F>
    where S: State + HasCaller<EVMAddress> + Debug + Clone + HasClientPerfMonitor + 'static,
          I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
          VS: VMStateT,
          F: Feedback<I, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        todo!()
    }
}