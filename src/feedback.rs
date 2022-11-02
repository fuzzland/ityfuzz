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
use crate::state::{FuzzState, HasExecutionResult};

const MAX_SIZE: usize = 2000;

// TODO: add hash table for stages
pub struct InfantFeedback<'a, I, S, O>
where
    I: VMInputT,
    O: Oracle<I, S>,
{
    oracle: &'a O,
    executor: EVMExecutor<I, S>,
    map: [bool; MAX_SIZE],
    phantom: PhantomData<(I, S)>,
}

impl<'a, I, S, O> Debug for InfantFeedback<'a, I, S, O>
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

impl<'a, I, S, O> Named for InfantFeedback<'a, I, S, O>
where
    I: VMInputT,
    O: Oracle<I, S>,
{
    fn name(&self) -> &str {
        "InfantFeedback"
    }
}

impl<'a, I, S, O> InfantFeedback<'a, I, S, O>
where
    I: VMInputT,
    O: Oracle<I, S>,
{
    pub fn new(oracle: &'a O, executor: EVMExecutor<I, S>) -> Self {
        Self {
            oracle,
            executor,
            map: [false; MAX_SIZE],
            phantom: PhantomData,
        }
    }
}

impl<'a, I, S, O> Feedback<I, S> for InfantFeedback<'a, I, S, O>
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
        // finish executing pre state and post state
        let post_execution = self
            .executor
            .finish_execution(state.get_execution_result(), input);

        // reverted states should be discarded as they are infeasible
        if post_execution.reverted {
            return Ok(false);
        }

        let mut oracle_ctx = OracleCtx::new(
            // todo(@shou): we should get a previous state, not incomplete state!
            input.get_state(),
            &post_execution.new_state.state,
            &mut self.executor,
            input,
        );
        let original_stage = input.get_staged_state().stage;
        let new_stage = self.oracle.transition(&mut oracle_ctx, original_stage);
        if new_stage != original_stage {
            state
                .get_execution_result_mut()
                .new_state
                .update_stage(new_stage);
        }

        // todo(@shou): need to test this about collision and investigate why it is giving a huge speed up
        let slot: usize = (new_stage << 8 ^ original_stage) as usize % MAX_SIZE;
        if !self.map[slot] {
            self.map[slot] = true;
            return Ok(true);
        }
        return Ok(false);
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

pub struct OracleFeedback<'a, I, S, O>
where
    I: VMInputT,
    O: Oracle<I, S>,
{
    oracle: &'a O,
    executor: EVMExecutor<I, S>,
    phantom: PhantomData<(I, S)>,
}

impl<'a, I, S, O> Debug for OracleFeedback<'a, I, S, O>
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

impl<'a, I, S, O> Named for OracleFeedback<'a, I, S, O>
where
    I: VMInputT,
    O: Oracle<I, S>,
{
    fn name(&self) -> &str {
        "OracleFeedback"
    }
}

impl<'a, I, S, O> OracleFeedback<'a, I, S, O>
where
    I: VMInputT,
    O: Oracle<I, S>,
{
    pub fn new(oracle: &'a O, executor: EVMExecutor<I, S>) -> Self {
        Self {
            oracle,
            executor,
            phantom: PhantomData,
        }
    }
}

impl<'a, I, S, O> Feedback<I, S> for OracleFeedback<'a, I, S, O>
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
        let mut oracle_ctx: OracleCtx<I, S> = OracleCtx::new(
            input.get_state(),
            &state.get_execution_result().new_state.state,
            &mut self.executor,
            input,
        );
        let old_stage = input.get_staged_state().stage;
        Ok(self.oracle.oracle(&mut oracle_ctx, old_stage))
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
