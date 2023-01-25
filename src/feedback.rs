use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::executors::ExitKind;
use libafl::inputs::Input;
use libafl::observers::ObserversTuple;
use libafl::prelude::{Executor, Feedback, Named};
use libafl::state::{HasClientPerfMonitor, State};
use libafl::Error;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;

use crate::evm::{EVMExecutor, ExecutionResult};
use crate::executor::FuzzExecutor;
use crate::input::{VMInput, VMInputT};
use crate::oracle::{Oracle, OracleCtx};
use crate::state::HasExecutionResult;

pub struct InfantFeedback<I, S, O>
where
    I: VMInputT,
    O: Oracle<I, S>,
{
    oracle: O,
    executor: EVMExecutor<I, S>,
    phantom: PhantomData<(I, S)>,
}

impl<I, S, O> Debug for InfantFeedback<I, S, O>
where
    I: VMInputT,
    O: Oracle<I, S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InfantFeedback")
            // .field("oracle", &self.oracle)
            .finish()
    }
}

impl<I, S, O> Named for InfantFeedback<I, S, O>
where
    I: VMInputT,
    O: Oracle<I, S>,
{
    fn name(&self) -> &str {
        "InfantFeedback"
    }
}

impl<I, S, O> InfantFeedback<I, S, O>
where
    I: VMInputT,
    O: Oracle<I, S>,
{
    pub fn new(oracle: O, executor: EVMExecutor<I, S>) -> Self {
        Self {
            oracle,
            executor,
            phantom: PhantomData,
        }
    }
}

impl<I, S, O> Feedback<I, S> for InfantFeedback<I, S, O>
where
    S: State + HasClientPerfMonitor + HasExecutionResult,
    I: VMInputT,
    O: Oracle<I, S>,
{
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        todo!()
    }

    // TODO: fix stage and pre_condition
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
        let mut oracle_ctx = OracleCtx::new(
            input.get_state(),
            &state.get_execution_result().new_state,
            &mut self.executor,
            input,
        );
        Ok(self.oracle.pre_condition(&mut oracle_ctx, 0) != 0)
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

pub struct OracleFeedback<I, S, O>
where
    I: VMInputT,
    O: Oracle<I, S>,
{
    oracle: O,
    executor: EVMExecutor<I, S>,
    phantom: PhantomData<(I, S)>,
}

impl<I, S, O> Debug for OracleFeedback<I, S, O>
where
    I: VMInputT,
    O: Oracle<I, S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleFeedback")
            // .field("oracle", &self.oracle)
            .finish()
    }
}

impl<I, S, O> Named for OracleFeedback<I, S, O>
where
    I: VMInputT,
    O: Oracle<I, S>,
{
    fn name(&self) -> &str {
        "OracleFeedback"
    }
}

impl<I, S, O> OracleFeedback<I, S, O>
where
    I: VMInputT,
    O: Oracle<I, S>,
{
    pub fn new(oracle: O, executor: EVMExecutor<I, S>) -> Self {
        Self {
            oracle,
            executor,
            phantom: PhantomData,
        }
    }
}

impl<I, S, O> Feedback<I, S> for OracleFeedback<I, S, O>
where
    S: State + HasClientPerfMonitor + HasExecutionResult,
    I: VMInputT,
    O: Oracle<I, S>,
{
    // since OracleFeedback is just a wrapper around one stateless oracle
    // we don't need to do initialization
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
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
        let mut oracle_ctx = OracleCtx::new(
            input.get_state(),
            &state.get_execution_result().new_state,
            &mut self.executor,
            input,
        );
        Ok(self.oracle.oracle(&mut oracle_ctx, 0))
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



// // Resulting state should not change
// fn oracle_same_state<I>(input: &I, result: &ExecutionResult) -> Result<bool, Error> where I: VMInputT {
//     Ok(input.get_state().eq(&result.new_state))
// }

// // Resulting state should be different
// fn oracle_diff_state<I>(input: &I, result: &ExecutionResult) -> Result<bool, Error> where I: VMInputT {
//     Ok(!input.get_state().eq(&result.new_state))
// }
