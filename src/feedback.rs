use std::{
    cell::RefCell,
    collections::HashSet,
    fmt::{Debug, Formatter},
    marker::PhantomData,
    ops::Deref,
    rc::Rc,
};

use libafl::{
    events::EventFirer,
    executors::ExitKind,
    inputs::Input,
    observers::ObserversTuple,
    prelude::{Feedback, HasMetadata, UsesInput},
    schedulers::Scheduler,
    state::{HasCorpus, State},
    Error,
};
use libafl_bolts::{impl_serdeany, Named};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::debug;

/// Implements the feedback mechanism needed by ItyFuzz.
/// Implements Oracle, Comparison, Dataflow feedbacks.
use crate::generic_vm::vm_executor::{GenericVM, MAP_SIZE};
use crate::{
    fuzzer::ORACLE_OUTPUT,
    generic_vm::vm_state::VMStateT,
    input::{ConciseSerde, VMInputT},
    oracle::{BugMetadata, Oracle, OracleCtx, Producer},
    r#const::{INFANT_STATE_INITIAL_VOTES, KNOWN_STATE_MAX_SIZE, KNOWN_STATE_SKIP_SIZE},
    scheduler::HasVote,
    state::{HasExecutionResult, HasInfantStateState, InfantStateState},
};

/// OracleFeedback is a wrapper around a set of oracles and producers.
/// It executes the producers and then oracles after each successful execution.
/// If any of the oracle returns true, then it returns true and report a
/// vulnerability found.
#[allow(clippy::type_complexity)]
pub struct OracleFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S: 'static, CI, E>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
    E: GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI>,
{
    /// A set of producers that produce data needed by oracles
    producers: &'a mut Vec<Rc<RefCell<dyn Producer<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E>>>>,
    /// A set of oracles that check for vulnerabilities
    oracle: &'a Vec<Rc<RefCell<dyn Oracle<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E>>>>,
    /// VM executor
    executor: Rc<RefCell<E>>,
    phantom: PhantomData<Out>,
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E> Debug
    for OracleFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
    E: GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleFeedback")
            // .field("oracle", &self.oracle)
            .finish()
    }
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E> Named
    for OracleFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
    E: GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI>,
{
    fn name(&self) -> &str {
        "OracleFeedback"
    }
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E>
    OracleFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E>
where
    S: State + HasExecutionResult<Loc, Addr, VS, Out, CI> + HasCorpus + HasMetadata + UsesInput<Input = I> + 'static,
    I: VMInputT<VS, Loc, Addr, CI> + 'static,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default + Into<Vec<u8>> + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
    E: GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI>,
{
    /// Create a new [`OracleFeedback`]
    #[allow(clippy::type_complexity)]
    pub fn new(
        oracle: &'a mut Vec<Rc<RefCell<dyn Oracle<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E>>>>,
        producers: &'a mut Vec<Rc<RefCell<dyn Producer<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E>>>>,
        executor: Rc<RefCell<E>>,
    ) -> Self {
        Self {
            producers,
            oracle,
            executor,
            phantom: Default::default(),
        }
    }

    /// Determines whether the current execution reproduces the bug
    /// specified in the bug_idx.
    pub fn reproduces(&mut self, state: &mut S, input: &S::Input, bug_idx: &[u64]) -> bool {
        let initial_oracle_output = unsafe { ORACLE_OUTPUT.clone() };
        if state.get_execution_result().reverted {
            return false;
        }
        // set up oracle context
        let mut oracle_ctx: OracleCtx<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E> =
            OracleCtx::new(state, input.get_state(), self.executor.clone(), input);

        // cleanup producers by calling `notify_end` hooks
        macro_rules! before_exit {
            () => {
                unsafe {
                    ORACLE_OUTPUT = initial_oracle_output;
                }
                self.producers.iter().for_each(|producer| {
                    producer.deref().borrow_mut().notify_end(&mut oracle_ctx);
                });
            };
        }

        // execute producers
        self.producers.iter().for_each(|producer| {
            producer.deref().borrow_mut().produce(&mut oracle_ctx);
        });

        let mut bug_to_hit = bug_idx.to_owned();
        let has_post_exec = oracle_ctx
            .fuzz_state
            .get_execution_result()
            .new_state
            .state
            .has_post_execution();

        // execute oracles and update stages if needed
        for idx in 0..self.oracle.len() {
            let original_stage = if idx >= input.get_staged_state().stage.len() {
                0
            } else {
                input.get_staged_state().stage[idx]
            };

            for bug_idx in self.oracle[idx]
                .deref()
                .borrow()
                .oracle(&mut oracle_ctx, original_stage)
            {
                bug_to_hit.retain(|x| *x != bug_idx);
            }
        }

        // ensure the execution is finished
        if has_post_exec {
            before_exit!();
            return false;
        }

        before_exit!();
        bug_to_hit.is_empty()
    }
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E> Feedback<S>
    for OracleFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E>
where
    S: State + HasExecutionResult<Loc, Addr, VS, Out, CI> + HasCorpus + HasMetadata + UsesInput<Input = I> + 'static,
    I: VMInputT<VS, Loc, Addr, CI> + 'static,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default + Into<Vec<u8>> + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
    E: GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI>,
{
    /// since OracleFeedback is just a wrapper around one stateless oracle
    /// we don't need to do initialization
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }

    /// Called after every execution.
    /// It executes the producers and then oracles after each successful
    /// execution. Returns true if any of the oracle returns true.
    fn is_interesting<EMI, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EMI,
        input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EMI: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        if state.get_execution_result().reverted {
            return Ok(false);
        }
        {
            if !state.has_metadata::<BugMetadata>() {
                state.metadata_map_mut().insert(BugMetadata::default());
            }

            state
                .metadata_map_mut()
                .get_mut::<BugMetadata>()
                .unwrap()
                .current_bugs
                .clear();
        }

        // set up oracle context
        let mut oracle_ctx: OracleCtx<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E> =
            OracleCtx::new(state, input.get_state(), self.executor.clone(), input);

        // cleanup producers by calling `notify_end` hooks
        macro_rules! before_exit {
            () => {
                self.producers.iter().for_each(|producer| {
                    producer.deref().borrow_mut().notify_end(&mut oracle_ctx);
                });
            };
        }

        // execute producers
        self.producers.iter().for_each(|producer| {
            producer.deref().borrow_mut().produce(&mut oracle_ctx);
        });

        let mut is_any_bug_hit = false;
        let has_post_exec = oracle_ctx
            .fuzz_state
            .get_execution_result()
            .new_state
            .state
            .has_post_execution();

        // execute oracles and update stages if needed
        for idx in 0..self.oracle.len() {
            let original_stage = if idx >= input.get_staged_state().stage.len() {
                0
            } else {
                input.get_staged_state().stage[idx]
            };

            for bug_idx in self.oracle[idx]
                .deref()
                .borrow()
                .oracle(&mut oracle_ctx, original_stage)
            {
                let metadata = oracle_ctx
                    .fuzz_state
                    .metadata_map_mut()
                    .get_mut::<BugMetadata>()
                    .unwrap();
                if metadata.known_bugs.contains(&bug_idx) || has_post_exec {
                    continue;
                }
                metadata.known_bugs.insert(bug_idx);
                metadata.current_bugs.push(bug_idx);
                is_any_bug_hit = true;
            }
        }

        // ensure the execution is finished
        if has_post_exec {
            before_exit!();
            return Ok(false);
        }

        before_exit!();
        Ok(is_any_bug_hit)
    }
}

/// DataflowFeedback is a feedback that uses dataflow analysis to determine
/// whether a state is interesting or not.
/// Logic: Maintains read and write map, if a write map idx is true in the read
/// map, and that item is greater than what we have, then the state is
/// interesting.
#[cfg(feature = "dataflow")]
pub struct DataflowFeedback<'a, VS, Loc, Addr, Out, CI> {
    /// global write map that OR all the write maps from each execution
    /// `[bool;4]` means 4 categories of write map, representing which bucket
    /// the written value fails into 0 - 2^2, 2^2 - 2^4, 2^4 - 2^6, 2^6 -
    /// inf are 4 buckets
    global_write_map: [[bool; 4]; MAP_SIZE],
    /// global read map recording whether a slot is read or not
    read_map: &'a mut [bool],
    /// write map of the current execution
    write_map: &'a mut [u8],
    phantom: PhantomData<(VS, Loc, Addr, Out, CI)>,
}

#[cfg(feature = "dataflow")]
impl<'a, VS, Loc, Addr, Out, CI> Debug for DataflowFeedback<'a, VS, Loc, Addr, Out, CI> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataflowFeedback")
            // .field("oracle", &self.oracle)
            .finish()
    }
}

#[cfg(feature = "dataflow")]
impl<'a, VS, Loc, Addr, Out, CI> Named for DataflowFeedback<'a, VS, Loc, Addr, Out, CI> {
    fn name(&self) -> &str {
        "DataflowFeedback"
    }
}

#[cfg(feature = "dataflow")]
impl<'a, VS, Loc, Addr, Out, CI> DataflowFeedback<'a, VS, Loc, Addr, Out, CI> {
    /// create a new dataflow feedback
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
impl<'a, VS, Loc, Addr, S, Out, CI, I> Feedback<S> for DataflowFeedback<'a, VS, Loc, Addr, Out, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    S: State + HasExecutionResult<Loc, Addr, VS, Out, CI> + UsesInput<Input = I>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default + Into<Vec<u8>> + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }

    /// Returns true if the dataflow analysis determines that the execution is
    /// interesting.
    fn is_interesting<EMI, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EMI,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EMI: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let mut interesting = false;
        for i in 0..MAP_SIZE {
            // if the global read map slot is true, and that slot in write map is also true
            if self.read_map[i] && self.write_map[i] != 0 {
                // bucketing
                let category = if self.write_map[i] < (2 << 2) {
                    0
                } else if self.write_map[i] < (2 << 4) {
                    1
                } else if self.write_map[i] < (2 << 6) {
                    2
                } else {
                    3
                };
                // update the global write map, if the current write map is not set, then it is
                // interesting
                if !self.global_write_map[i % MAP_SIZE][category] {
                    // debug!("Interesting seq: {}!!!!!!!!!!!!!!!!!", seq);
                    interesting = true;
                    self.global_write_map[i % MAP_SIZE][category] = true;
                }
            }
        }

        // clean up the write map for the next execution
        for i in 0..MAP_SIZE {
            self.write_map[i] = 0;
        }
        Ok(interesting)
    }
}

/// CmpFeedback is a feedback that uses cmp analysis to determine
/// whether a state is interesting or not.
///
/// Logic: For each comparison encountered in execution, we calculate the
/// absolute difference (distance) between the two operands.
/// Smaller distance means the operands are closer to each other,
/// and thus more likely the comparison will be true, opening up more paths. Our
/// goal is to minimize the distance between the two operands of any
/// comparisons.
///
/// We use this distance to update the min_map, which records the minimum
/// distance for each comparison. If the current distance is smaller than the
/// min_map, then we update the min_map and mark the it as interesting.
///
/// We also use a set of hashes of already encountered VMStates so that we don't
/// re-analyze them.
///
/// When we consider an execution interesting, we use a votable scheduler to
/// vote on whether the VMState is interesting or not. With more votes, the
/// VMState is more likely to be selected for fuzzing.
#[allow(clippy::type_complexity)]
#[cfg(feature = "cmp")]
pub struct CmpFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC, CI> {
    /// global min map recording the minimum distance for each comparison
    min_map: [SlotTy; MAP_SIZE],
    /// min map recording the minimum distance for each comparison in the
    /// current execution
    current_map: &'a mut [SlotTy],
    /// a set of hashes of already encountered VMStates so that we don't
    /// re-analyze them
    known_states: HashSet<u64>,
    /// votable scheduler that can vote on whether a VMState is interesting or
    /// not
    scheduler: SC,
    /// the VM providing information about the current execution
    vm: Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI>>>,
    phantom: PhantomData<(Addr, Out)>,
}

#[cfg(feature = "cmp")]
impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC, CI>
    CmpFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC, CI>
where
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>> + HasVote<InfantStateState<Loc, Addr, VS, CI>>,
    VS: Default + VMStateT,
    SlotTy: PartialOrd + Copy + TryFrom<u128>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    <SlotTy as TryFrom<u128>>::Error: std::fmt::Debug,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Create a new CmpFeedback.
    #[allow(clippy::type_complexity)]
    pub(crate) fn new(
        current_map: &'a mut [SlotTy],
        scheduler: SC,
        vm: Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI>>>,
    ) -> Self {
        Self {
            min_map: [SlotTy::try_from(u128::MAX).expect(""); MAP_SIZE],
            current_map,
            known_states: Default::default(),
            scheduler,
            vm,
            phantom: Default::default(),
        }
    }
}

#[cfg(feature = "cmp")]
impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC, CI> Named
    for CmpFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC, CI>
{
    fn name(&self) -> &str {
        "CmpFeedback"
    }
}

#[cfg(feature = "cmp")]
impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC, CI> Debug
    for CmpFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC, CI>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CmpFeedback").finish()
    }
}

#[cfg(feature = "cmp")]
impl<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, I0, S0, SC, CI> Feedback<S0>
    for CmpFeedback<'a, VS, Addr, Code, By, Loc, SlotTy, Out, I, S, SC, CI>
where
    I0: Input + VMInputT<VS, Loc, Addr, CI>,
    S0: State
        + HasInfantStateState<Loc, Addr, VS, CI>
        + HasExecutionResult<Loc, Addr, VS, Out, CI>
        + HasMetadata
        + UsesInput<Input = I0>,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>> + HasVote<InfantStateState<Loc, Addr, VS, CI>>,
    VS: Default + VMStateT + 'static,
    SlotTy: PartialOrd + Copy,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default + Into<Vec<u8>> + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn init_state(&mut self, _state: &mut S0) -> Result<(), Error> {
        Ok(())
    }

    /// It uses scheduler voting to determine whether a VM State is interesting
    /// or not. If it returns true, the VM State is added to corpus but not
    /// necessarily it is interesting.
    fn is_interesting<EMI, OT>(
        &mut self,
        state: &mut S0,
        _manager: &mut EMI,
        input: &S0::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EMI: EventFirer<State = S0>,
        OT: ObserversTuple<S0>,
    {
        let mut cmp_interesting = false;
        let cov_interesting = false;

        // Clear the result of any cached cmp analysis
        if let Some(metadata) = state.metadata_map_mut().get_mut::<CmpMetadata>() {
            metadata.set_cmp_interesting(false);
        } else {
            let mut metadata = CmpMetadata::new();
            metadata.set_cmp_interesting(false);
            state.metadata_map_mut().insert(metadata);
        }

        // check if the current distance is smaller than the min_map
        for i in 0..MAP_SIZE {
            if self.current_map[i] < self.min_map[i] {
                self.min_map[i] = self.current_map[i];
                cmp_interesting = true;
            }
        }

        // cache the result of this testcase's cmp analysis
        if let Some(metadata) = state.metadata_map_mut().get_mut::<CmpMetadata>() {
            metadata.set_cmp_interesting(cmp_interesting);
        } else {
            let mut metadata = CmpMetadata::new();
            metadata.set_cmp_interesting(cmp_interesting);
            state.metadata_map_mut().insert(metadata);
        }

        // if the current distance is smaller than the min_map, vote for the state
        if cmp_interesting {
            debug!("Voted for {} because of CMP", input.get_state_idx());
            self.scheduler.vote(
                state.get_infant_state_state(),
                input.get_state_idx(),
                INFANT_STATE_INITIAL_VOTES,
            );
        }

        // if coverage has increased, vote for the state
        if cov_interesting {
            debug!("Voted for {} because of COV", input.get_state_idx());

            self.scheduler.vote(
                state.get_infant_state_state(),
                input.get_state_idx(),
                INFANT_STATE_INITIAL_VOTES,
            );
        }

        if self.vm.deref().borrow_mut().state_changed() ||
            state.get_execution_result().new_state.state.has_post_execution()
        {
            let hash = state.get_execution_result().new_state.state.get_hash();
            if self.known_states.contains(&hash) {
                return Ok(false);
            }
            self.known_states.insert(hash);
            if self.known_states.len() > KNOWN_STATE_MAX_SIZE {
                self.known_states = self.known_states.iter().skip(KNOWN_STATE_SKIP_SIZE).cloned().collect();
            }
            return Ok(true);
        }
        Ok(false)
    }
}

/// Metadata for Coverage Comparisons
///
/// This is metadata attached to the global fuzz state
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CmpMetadata {
    /// Used to cache the result of the last run's comparison mapping
    pub cmp_interesting: bool,
}

impl CmpMetadata {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn set_cmp_interesting(&mut self, cmp_interesting: bool) {
        self.cmp_interesting = cmp_interesting;
    }
}

impl_serdeany!(CmpMetadata);
