use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::executors::ExitKind;
use libafl::inputs::Input;
use libafl::observers::ObserversTuple;
use libafl::prelude::{Feedback, HasMetadata, Named};
use libafl::schedulers::Scheduler;
use libafl::state::{HasClientPerfMonitor, HasCorpus, State};
use libafl::Error;
use primitive_types::U256;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};

use std::marker::PhantomData;

use crate::evm::{state_change, EVMExecutor, JMP_MAP, MAP_SIZE, READ_MAP, WRITE_MAP};

use crate::input::VMInputT;
use crate::oracle::{Oracle, OracleCtx};
use crate::scheduler::HasVote;
use crate::state::{HasExecutionResult, HasInfantStateState, HasItyState, InfantStateState};
use crate::state_input::StagedVMState;

pub struct InfantFeedback<'a, I, S: 'static>
where
    I: VMInputT,
{
    oracle: &'a Vec<Box<dyn Oracle<I, S>>>,
    executor: EVMExecutor<I, S>,
    map: [bool; MAP_SIZE],
    phantom: PhantomData<(I, S)>,
}

impl<'a, I, S> Debug for InfantFeedback<'a, I, S>
where
    I: VMInputT,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InfantFeedback")
            // .field("oracle", &self.oracle)
            .finish()
    }
}

impl<'a, I, S> Named for InfantFeedback<'a, I, S>
where
    I: VMInputT,
{
    fn name(&self) -> &str {
        "InfantFeedback"
    }
}

impl<'a, I, S> InfantFeedback<'a, I, S>
where
    I: VMInputT,
{
    pub fn new(oracle: &'a Vec<Box<dyn Oracle<I, S>>>, executor: EVMExecutor<I, S>) -> Self {
        Self {
            oracle,
            executor,
            map: [false; MAP_SIZE],
            phantom: PhantomData,
        }
    }
}

impl<'a, I, S> Feedback<I, S> for InfantFeedback<'a, I, S>
where
    S: State + HasClientPerfMonitor + HasExecutionResult + HasCorpus<I> + HasMetadata + HasItyState,
    I: Input + VMInputT + 'static,
{
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        todo!()
    }

    fn is_interesting<EMI, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EMI,
        input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EMI: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        let mut oracle_ctx = OracleCtx::new(
            // todo(@shou): we should get a previous state, not incomplete state!
            state,
            input.get_state(),
            &state.get_execution_result().new_state.state,
            &mut self.executor,
            input,
        );

        let mut new_stages = vec![];
        let mut is_interesting = false;

        for idx in 0..self.oracle.len() {
            let original_stage = if idx >= input.get_staged_state().stage.len() {
                0
            } else {
                input.get_staged_state().stage[idx]
            };
            let new_stage = self.oracle[idx].transition(&mut oracle_ctx, original_stage);
            new_stages.push(new_stage);
            // todo(@shou): need to test this about collision and investigate why it is giving a huge speed up
            let slot: usize = (new_stage << 8 ^ original_stage) as usize % MAP_SIZE;
            if !self.map[slot] {
                self.map[slot] = true;
                is_interesting = true;
            }
        }
        state
            .get_execution_result_mut()
            .new_state
            .update_stage(new_stages);

        return Ok(is_interesting);
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

pub struct OracleFeedback<'a, I, S: 'static>
where
    I: VMInputT,
{
    oracle: &'a Vec<Box<dyn Oracle<I, S>>>,
    executor: EVMExecutor<I, S>,
}

impl<'a, I, S> Debug for OracleFeedback<'a, I, S>
where
    I: VMInputT,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleFeedback")
            // .field("oracle", &self.oracle)
            .finish()
    }
}

impl<'a, I, S> Named for OracleFeedback<'a, I, S>
where
    I: VMInputT,
{
    fn name(&self) -> &str {
        "OracleFeedback"
    }
}

impl<'a, I, S> OracleFeedback<'a, I, S>
where
    I: VMInputT,
{
    pub fn new(oracle: &'a Vec<Box<dyn Oracle<I, S>>>, executor: EVMExecutor<I, S>) -> Self {
        Self { oracle, executor }
    }
}

impl<'a, I, S> Feedback<I, S> for OracleFeedback<'a, I, S>
where
    S: State
        + HasClientPerfMonitor
        + HasExecutionResult
        + HasCorpus<I>
        + HasMetadata
        + HasItyState
        + 'static,
    I: VMInputT + 'static,
{
    // since OracleFeedback is just a wrapper around one stateless oracle
    // we don't need to do initialization
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }

    fn is_interesting<EMI, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EMI,
        input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EMI: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        let mut oracle_ctx: OracleCtx<I, S> = OracleCtx::new(
            state,
            input.get_state(),
            &state.get_execution_result().new_state.state,
            &mut self.executor,
            input,
        );
        // todo(@shou): should it be new stage?
        for idx in 0..self.oracle.len() {
            let original_stage = if idx >= input.get_staged_state().stage.len() {
                0
            } else {
                input.get_staged_state().stage[idx]
            };
            if self.oracle[idx].oracle(&mut oracle_ctx, original_stage) {
                return Ok(true);
            }
        }
        Ok(false)
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
    global_write_map: [[bool; 4]; MAP_SIZE],
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
            global_write_map: [[false; 4]; MAP_SIZE],
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
        _state: &mut S,
        _manager: &mut EMI,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EMI: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        let mut interesting = false;
        let mut seq: usize = 0;
        for i in 0..MAP_SIZE {
            if self.read_map[i] && self.write_map[i] != 0 {
                seq += i;
                let category = if self.write_map[i] < (2 << 2) {
                    0
                } else if self.write_map[i] < (2 << 4) {
                    1
                } else if self.write_map[i] < (2 << 6) {
                    2
                } else {
                    3
                };
                if !self.global_write_map[seq % MAP_SIZE][category] {
                    // println!("Interesting seq: {}!!!!!!!!!!!!!!!!!", seq);
                    interesting = true;
                    self.global_write_map[seq % MAP_SIZE][category] = true;
                }
            }
        }
        for i in 0..MAP_SIZE {
            self.write_map[i] = 0;
        }
        return Ok(interesting);
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

#[cfg(feature = "cmp")]
pub struct CmpFeedback<'a, SC> {
    min_map: [U256; MAP_SIZE],
    current_map: &'a mut [U256],
    known_jmp_map: [u8; MAP_SIZE],
    known_states: HashSet<u64>,
    scheduler: &'a SC,
}

#[cfg(feature = "cmp")]
impl<'a, SC> CmpFeedback<'a, SC>
where
    SC: Scheduler<StagedVMState, InfantStateState> + HasVote<StagedVMState, InfantStateState>,
{
    pub(crate) fn new(current_map: &'a mut [U256], scheduler: &'a SC) -> Self {
        Self {
            min_map: [U256::MAX; MAP_SIZE],
            current_map,
            known_jmp_map: [0; MAP_SIZE],
            known_states: Default::default(),
            scheduler,
        }
    }
}

#[cfg(feature = "cmp")]
impl<'a, SC> Named for CmpFeedback<'a, SC> {
    fn name(&self) -> &str {
        "CmpFeedback"
    }
}

#[cfg(feature = "cmp")]
impl<'a, SC> Debug for CmpFeedback<'a, SC> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CmpFeedback").finish()
    }
}

#[cfg(feature = "cmp")]
impl<'a, I0, S0, SC> Feedback<I0, S0> for CmpFeedback<'a, SC>
where
    S0: State + HasClientPerfMonitor + HasInfantStateState + HasExecutionResult,
    I0: Input + VMInputT,
    SC: Scheduler<StagedVMState, InfantStateState> + HasVote<StagedVMState, InfantStateState>,
{
    fn init_state(&mut self, _state: &mut S0) -> Result<(), Error> {
        Ok(())
    }

    fn is_interesting<EMI, OT>(
        &mut self,
        state: &mut S0,
        _manager: &mut EMI,
        input: &I0,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EMI: EventFirer<I0>,
        OT: ObserversTuple<I0, S0>,
    {
        let mut cmp_interesting = false;
        let mut cov_interesting = false;
        for i in 0..MAP_SIZE {
            if self.current_map[i] < self.min_map[i] {
                self.min_map[i] = self.current_map[i];
                cmp_interesting = true;
            }
            // unsafe {
            //     if self.known_jmp_map[i] < JMP_MAP[i] {
            //         self.known_jmp_map[i] = JMP_MAP[i];
            //         cov_interesting = true;
            //     }
            // }
        }
        if cmp_interesting {
            self.scheduler
                .vote(state.get_infant_state_state(), input.get_state_idx());
        }

        if cov_interesting {
            self.scheduler
                .vote(state.get_infant_state_state(), input.get_state_idx());
        }

        unsafe {
            if state_change {
                let hash = state.get_execution_result().new_state.state.get_hash();
                if self.known_states.contains(&hash) {
                    return Ok(false);
                }
                let mut df_interesting = false;
                for i in 0..MAP_SIZE {
                    if READ_MAP[i] && WRITE_MAP[i] != 0 {
                        df_interesting = true;
                        break;
                    }
                }
                for i in 0..MAP_SIZE {
                    WRITE_MAP[i] = 0;
                }
                if df_interesting {
                    self.known_states.insert(hash);
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn append_metadata(
        &mut self,
        _state: &mut S0,
        _testcase: &mut Testcase<I0>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut S0, _input: &I0) -> Result<(), Error> {
        Ok(())
    }
}
