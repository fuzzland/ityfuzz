use std::cell::RefCell;
use crate::generic_vm::vm_executor::{GenericVM, MAP_SIZE};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::oracle::{Oracle, OracleCtx};
use crate::scheduler::HasVote;
use crate::state::{HasExecutionResult, HasInfantStateState, InfantStateState};
use crate::state_input::StagedVMState;
use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::executors::ExitKind;
use libafl::inputs::Input;
use libafl::observers::ObserversTuple;
use libafl::prelude::{Feedback, HasMetadata, Named};
use libafl::schedulers::Scheduler;
use libafl::state::{HasClientPerfMonitor, HasCorpus, State};
use libafl::Error;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::ops::Deref;
use std::rc::Rc;

pub struct InfantFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S: 'static>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    oracle: &'a Vec<Box<dyn Oracle<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>>>,
    executor: &'a mut Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S>>>,
    map: [bool; MAP_SIZE],
    phantom: PhantomData<(I, S, Out)>,
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S> Debug
    for InfantFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InfantFeedback")
            // .field("oracle", &self.oracle)
            .finish()
    }
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S> Named
    for InfantFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    fn name(&self) -> &str {
        "InfantFeedback"
    }
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
    InfantFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    pub fn new(
        oracle: &'a Vec<Box<dyn Oracle<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>>>,
        executor: &'a mut Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S>>>,
    ) -> Self {
        Self {
            oracle,
            executor,
            map: [false; MAP_SIZE],
            phantom: PhantomData,
        }
    }
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S> Feedback<I, S>
    for InfantFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
where
    S: State
        + HasClientPerfMonitor
        + HasExecutionResult<Loc, Addr, VS, Out>
        + HasCorpus<I>
        + HasMetadata,
    I: Input + VMInputT<VS, Loc, Addr> + 'static,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
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
            self.executor,
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

pub struct OracleFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S: 'static>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    oracle: &'a Vec<Rc<RefCell<dyn Oracle<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>>>>,
    executor: Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S>>>,
    phantom: PhantomData<(Out)>,
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S> Debug
    for OracleFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleFeedback")
            // .field("oracle", &self.oracle)
            .finish()
    }
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S> Named
    for OracleFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    fn name(&self) -> &str {
        "OracleFeedback"
    }
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
    OracleFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    pub fn new(
        oracle: &'a mut Vec<Rc<RefCell<dyn Oracle<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>>>>,
        executor: Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S>>>,
    ) -> Self {
        Self {
            oracle,
            executor,
            phantom: Default::default(),
        }
    }
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S> Feedback<I, S>
    for OracleFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S>
where
    S: State
        + HasClientPerfMonitor
        + HasExecutionResult<Loc, Addr, VS, Out>
        + HasCorpus<I>
        + HasMetadata
        + 'static,
    I: VMInputT<VS, Loc, Addr> + 'static,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
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
        let mut oracle_ctx: OracleCtx<VS, Addr, Code, By, Loc, SlotTy, Out, I, S> = OracleCtx::new(
            state,
            input.get_state(),
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
            if self.oracle[idx].deref().borrow().oracle(&mut oracle_ctx, original_stage) {
                // ensure the execution is finished
                if state
                    .get_execution_result()
                    .new_state
                    .state
                    .has_post_execution()
                {
                    return Ok(false);
                }
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
pub struct DataflowFeedback<'a, VS, Loc, Addr, Out> {
    global_write_map: [[bool; 4]; MAP_SIZE],
    read_map: &'a mut [bool],
    write_map: &'a mut [u8],
    phantom: PhantomData<(VS, Loc, Addr, Out)>,
}

#[cfg(feature = "dataflow")]
impl<'a, VS, Loc, Addr, Out> Debug for DataflowFeedback<'a, VS, Loc, Addr, Out> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataflowFeedback")
            // .field("oracle", &self.oracle)
            .finish()
    }
}

#[cfg(feature = "dataflow")]
impl<'a, VS, Loc, Addr, Out> Named for DataflowFeedback<'a, VS, Loc, Addr, Out> {
    fn name(&self) -> &str {
        "DataflowFeedback"
    }
}

#[cfg(feature = "dataflow")]
impl<'a, VS, Loc, Addr, Out> DataflowFeedback<'a, VS, Loc, Addr, Out> {
    pub fn new(read_map: &'a mut [bool], write_map: &'a mut [u8]) -> Self {
        Self {
            global_write_map: [[false; 4]; MAP_SIZE],
            read_map,
            write_map,
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "dataflow")]
impl<'a, VS, Loc, Addr, I, S, Out> Feedback<I, S> for DataflowFeedback<'a, VS, Loc, Addr, Out>
where
    S: State + HasClientPerfMonitor + HasExecutionResult<Loc, Addr, VS, Out>,
    I: VMInputT<VS, Loc, Addr>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
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
pub struct CmpFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC> {
    min_map: [SlotTy; MAP_SIZE],
    current_map: &'a mut [SlotTy],
    known_jmp_map: [u8; MAP_SIZE],
    known_states: HashSet<u64>,
    known_pcs: HashSet<usize>,
    scheduler: &'a SC,
    vm: Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S>>>,
    phantom: PhantomData<(Addr, Out)>,
}

#[cfg(feature = "cmp")]
impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC>
    CmpFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC>
where
    SC: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>
        + HasVote<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    VS: Default + VMStateT,
    SlotTy: PartialOrd + Copy + From<u128>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    pub(crate) fn new(
        current_map: &'a mut [SlotTy],
        scheduler: &'a SC,
        vm: Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S>>>,
    ) -> Self {
        Self {
            min_map: [SlotTy::from(u128::MAX); MAP_SIZE],
            current_map,
            known_jmp_map: [0; MAP_SIZE],
            known_states: Default::default(),
            known_pcs: Default::default(),
            scheduler,
            vm,
            phantom: Default::default(),
        }
    }
}

#[cfg(feature = "cmp")]
impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC> Named
    for CmpFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC>
{
    fn name(&self) -> &str {
        "CmpFeedback"
    }
}

#[cfg(feature = "cmp")]
impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC> Debug
    for CmpFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CmpFeedback").finish()
    }
}

#[cfg(feature = "cmp")]
impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, I0, S0, SC> Feedback<I0, S0>
    for CmpFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC>
where
    S0: State
        + HasClientPerfMonitor
        + HasInfantStateState<Loc, Addr, VS>
        + HasExecutionResult<Loc, Addr, VS, Out>,
    I0: Input + VMInputT<VS, Loc, Addr>,
    SC: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>
        + HasVote<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    VS: Default + VMStateT + 'static,
    SlotTy: PartialOrd + Copy,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
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
            let cur_read_map = self.vm.deref().borrow_mut().get_read();
            let cur_write_map = self.vm.deref().borrow_mut().get_write();
            // hack to account for saving reentrancy without dataflow
            let pc_interesting = state
                .get_execution_result()
                .new_state
                .state
                .get_post_execution_pc()
                != 0;

            if self.vm.deref().borrow_mut().state_changed() || pc_interesting {
                let hash = state.get_execution_result().new_state.state.get_hash();
                if self.known_states.contains(&hash) {
                    return Ok(false);
                }

                let mut df_interesting = false;
                for i in 0..MAP_SIZE {
                    if cur_read_map[i] && cur_write_map[i] != 0 {
                        df_interesting = true;
                        break;
                    }
                }
                for i in 0..MAP_SIZE {
                    cur_write_map[i] = 0;
                }
                if df_interesting || pc_interesting {
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
