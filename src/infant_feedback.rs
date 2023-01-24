use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::executors::ExitKind;
use libafl::inputs::Input;
use libafl::observers::ObserversTuple;
use libafl::prelude::{Feedback, Named, Executor};
use libafl::state::{HasClientPerfMonitor, State};
use libafl::Error;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;

use crate::evm::{ExecutionResult, EVMExecutor};
use crate::executor::FuzzExecutor;
use crate::input::{VMInputT, VMInput};
use crate::state::HasExecutionResult;
use crate::oracle::{Oracle, OracleCtx};

pub struct InfantFeedback<I, S, O, E, EM, Z>
where I: VMInputT,
E: Executor<EM, I, S, Z>,
O: Oracle<I, S>,
{
    oracle: O,
    executor: E,
    phantom: PhantomData<(I, S, EM, Z)>,
}

impl<I, S, O, E, EM, Z> Debug for InfantFeedback<I, S, O, E, EM, Z>
where I: VMInputT,
E: Executor<EM, I, S, Z>,
O: Oracle<I, S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InfantFeedback")
            // .field("oracle", &self.oracle)
            .finish()
    }
}

impl<I, S, O, E, EM, Z> Named for InfantFeedback<I, S, O, E, EM, Z>
where I: VMInputT,
E: Executor<EM, I, S, Z>,
O: Oracle<I, S>,

{
    fn name(&self) -> &str {
        "InfantFeedback"
    }
}

impl<I, S, O, E, EM, Z> InfantFeedback<I, S, O, E, EM, Z>
where I: VMInputT,
E: Executor<EM, I, S, Z>,
O: Oracle<I, S>,

{
    pub fn new(oracle: O, executor: E) -> Self {
        Self { oracle, executor, phantom: PhantomData }
    }
}

impl<I, S, O, E, EM, Z> Feedback<I, S> for InfantFeedback<I, S, O, E, EM, Z>
where
    S: State + HasClientPerfMonitor + HasExecutionResult,
    I: VMInputT,
    E: Executor<EM, I, S, Z>,
    O: Oracle<I, S>,
{
    // since InfantFeedback is just a wrapper around one stateless oracle
    // we don't need to do initialization
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        todo!()
    }

    fn is_interesting<EMI, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EMI,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EMI: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        let mut oracle_ctx = OracleCtx::new(input.get_state_mut(), &mut state.get_execution_result().new_state, &mut self.executor, input);
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

