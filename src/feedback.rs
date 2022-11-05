use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::executors::ExitKind;
use libafl::inputs::Input;
use libafl::observers::ObserversTuple;
use libafl::prelude::{Executor, Feedback, Named};
use libafl::state::{HasClientPerfMonitor, State};
use libafl::Error;
use std::fmt::{Debug, Formatter};
use std::iter::Map;
use std::marker::PhantomData;

use crate::evm::{EVMExecutor, ExecutionResult, MAP_SIZE};
use crate::executor::FuzzExecutor;
use crate::input::{VMInput, VMInputT};
use crate::oracle::{Oracle, OracleCtx};
use crate::state::{FuzzState, HasExecutionResult};

pub struct InfantFeedback<'a, I, S, O>
where
    I: VMInputT,
    O: Oracle<I, S>,
{
    oracle: &'a O,
    executor: EVMExecutor<I, S>,
    map: [bool; MAP_SIZE],
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
            map: [false; MAP_SIZE],
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
        let slot: usize = (new_stage << 8 ^ original_stage) as usize % MAP_SIZE;
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

/// DataflowFeedback is a feedback that uses dataflow analysis to determine
/// whether a state is interesting or not.
/// Logic: Maintains read and write map, if a write map idx is true in the read map,
/// and that item is greater than what we have, then the state is interesting.
#[cfg(feature = "dataflow")]
pub struct DataflowFeedback<'a> {
    global_write_map: [u8; MAP_SIZE],
    read_map: &'a mut [bool],
    write_map: &'a mut [u8],
}

#[cfg(feature = "dataflow")]
impl<'a> Debug for DataflowFeedback<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataflowFeedback")
            // .field("oracle", &self.oracle)
            .finish()
    }
}

#[cfg(feature = "dataflow")]
impl<'a> Named for DataflowFeedback<'a> {
    fn name(&self) -> &str {
        "DataflowFeedback"
    }
}

#[cfg(feature = "dataflow")]
impl<'a> DataflowFeedback<'a> {
    pub fn new(read_map: &'a mut [bool], write_map: &'a mut [u8]) -> Self {
        Self {
            global_write_map: [0; MAP_SIZE],
            read_map,
            write_map,
        }
    }
}

#[cfg(feature = "dataflow")]
impl<'a, I, S> Feedback<I, S> for DataflowFeedback<'a>
where
    S: State + HasClientPerfMonitor + HasExecutionResult,
    I: VMInputT,
{
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
        for i in 0..MAP_SIZE {
            if self.read_map[i] && (self.global_write_map[i] < self.write_map[i]) {
                self.global_write_map[i] = self.write_map[i];
                return Ok(true);
            }
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
