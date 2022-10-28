use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::executors::ExitKind;
use libafl::inputs::Input;
use libafl::observers::ObserversTuple;
use libafl::prelude::{Feedback, Named};
use libafl::state::{HasClientPerfMonitor, State};
use libafl::Error;
use std::fmt::{Debug, Formatter};

use crate::evm::ExecutionResult;
use crate::input::{VMInputT, VMInput};
use crate::state::HasExecutionResult;

pub struct InfantFeedback<I>
where I: VMInputT,
{
    oracle: fn(&I, &ExecutionResult) -> bool
}

impl<I> Debug for InfantFeedback<I>
where I: VMInputT,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InfantFeedback")
            // .field("oracle", &self.oracle)
            .finish()
    }
}

impl<I> Named for InfantFeedback<I>
where I: VMInputT {
    fn name(&self) -> &str {
        "InfantFeedback"
    }
}

impl<I> InfantFeedback<I>
where I: VMInputT
{
    pub fn new(oracle: fn(&I, &ExecutionResult) -> bool) -> Self {
        Self { oracle }
    }
}

impl<I, S> Feedback<I, S> for InfantFeedback<I>
where
    S: State + HasClientPerfMonitor + HasExecutionResult,
    I: VMInputT,
{
    // since InfantFeedback is just a wrapper around one stateless oracle
    // we don't need to do initialization
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        todo!()
    }

    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        Ok((self.oracle)(input, state.get_execution_result()))
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        _testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }
}



// Resulting state should not change
fn oracle_same_state<I>(input: &I, result: &ExecutionResult) -> Result<bool, Error> where I: VMInputT {
    Ok(input.get_state().eq(&result.new_state))
}

// Resulting state should be different
fn oracle_diff_state<I>(input: &I, result: &ExecutionResult) -> Result<bool, Error> where I: VMInputT {
    Ok(!input.get_state().eq(&result.new_state))
}

