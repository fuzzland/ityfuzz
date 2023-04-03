use crate::{
    input::VMInputT,
    state::{HasCurrentInputIdx, HasInfantStateState, HasItyState, InfantStateState},
    state_input::StagedVMState,
};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::Write;
use std::ops::Deref;
use std::path::Path;
use std::process::exit;
use std::{marker::PhantomData, time::Duration};

use crate::evm::oracle::FL_DATA;
use crate::evm::vm::JMP_MAP;
use crate::generic_vm::vm_executor::MAP_SIZE;
use crate::generic_vm::vm_state::VMStateT;
#[cfg(feature = "record_instruction_coverage")]
use crate::r#const::DEBUG_PRINT_PERCENT;
use crate::state::HasExecutionResult;
use crate::tracer::{build_basic_txn, TxnTrace};
use libafl::{
    fuzzer::Fuzzer,
    mark_feature_time,
    prelude::{
        current_time, Corpus, Event, EventConfig, EventManager, Executor, Feedback, HasObservers,
        ObserversTuple, Testcase,
    },
    schedulers::Scheduler,
    stages::StagesTuple,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasMetadata, HasSolutions},
    Error, Evaluator, ExecuteInputResult,
};
use rand::random;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::hash::{Hash, Hasher};

const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub struct ItyFuzzer<'a, VS, Loc, Addr, Out, CS, IS, F, IF, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    F: Feedback<I, S>,
    IF: Feedback<I, S>,
    I: VMInputT<VS, Loc, Addr>,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    scheduler: CS,
    feedback: F,
    infant_feedback: IF,
    infant_scheduler: &'a IS,
    objective: OF,
    // map from hash of a testcase can do (e.g., coverage map) to the (testcase idx, fav factor)
    minimizer_map: HashMap<u64, (usize, f64)>,
    phantom: PhantomData<(I, S, OT, VS, Loc, Addr, Out)>,
}

impl<'a, VS, Loc, Addr, Out, CS, IS, F, IF, I, OF, S, OT>
    ItyFuzzer<'a, VS, Loc, Addr, Out, CS, IS, F, IF, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    F: Feedback<I, S>,
    IF: Feedback<I, S>,
    I: VMInputT<VS, Loc, Addr>,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    pub fn new(
        scheduler: CS,
        infant_scheduler: &'a IS,
        feedback: F,
        infant_feedback: IF,
        objective: OF,
    ) -> Self {
        Self {
            scheduler,
            feedback,
            infant_feedback,
            infant_scheduler,
            objective,
            minimizer_map: Default::default(),
            phantom: PhantomData,
        }
    }

    pub fn on_add_corpus(
        &mut self,
        input: &I,
        coverage: &[u8; MAP_SIZE],
        testcase_idx: usize,
    ) -> () {
        let mut hasher = DefaultHasher::new();
        coverage.hash(&mut hasher);
        let hash = hasher.finish();
        self.minimizer_map
            .insert(hash, (testcase_idx, input.fav_factor()));
    }

    pub fn on_replace_corpus(
        &mut self,
        (hash, new_fav_factor, _): (u64, f64, usize),
        new_testcase_idx: usize,
    ) -> () {
        let res = self.minimizer_map.get_mut(&hash).unwrap();
        res.0 = new_testcase_idx;
        res.1 = new_fav_factor;
    }

    pub fn should_replace(
        &self,
        input: &I,
        coverage: &[u8; MAP_SIZE],
    ) -> Option<(u64, f64, usize)> {
        let mut hasher = DefaultHasher::new();
        coverage.hash(&mut hasher);
        let hash = hasher.finish();
        if let Some((testcase_idx, fav_factor)) = self.minimizer_map.get(&hash) {
            let new_fav_factor = input.fav_factor();
            if new_fav_factor > *fav_factor {
                return Some((hash, new_fav_factor, testcase_idx.clone()));
            }
        }
        None
    }
}

// implement fuzzer trait for ItyFuzzer
// Seems that we can get rid of this impl and just use StdFuzzer?
impl<'a, VS, Loc, Addr, Out, CS, IS, E, EM, F, IF, I, OF, S, ST, OT> Fuzzer<E, EM, I, S, ST>
    for ItyFuzzer<'a, VS, Loc, Addr, Out, CS, IS, F, IF, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    EM: EventManager<E, I, S, Self>,
    F: Feedback<I, S>,
    IF: Feedback<I, S>,
    I: VMInputT<VS, Loc, Addr>,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor + HasExecutions + HasMetadata + HasCurrentInputIdx,
    ST: StagesTuple<E, EM, S, Self> + ?Sized,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    fn fuzz_one(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<usize, libafl::Error> {
        let idx = self.scheduler.next(state)?;
        state.set_current_input_idx(idx);

        // TODO: if the idx input is a concolic input returned by the solver
        // we should not perform all stages.

        stages
            .perform_all(self, executor, state, manager, idx)
            .expect("perform_all failed");
        manager.process(self, state, executor)?;
        Ok(idx)
    }

    fn fuzz_loop(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<usize, Error> {
        let mut last = current_time();
        // now report stats to manager every 0.1 sec
        let monitor_timeout = STATS_TIMEOUT_DEFAULT;
        loop {
            self.fuzz_one(stages, executor, state, manager)?;
            last = manager.maybe_report_progress(state, last, monitor_timeout)?;
        }
    }
}

#[cfg(feature = "print_txn_corpus")]
pub static mut DUMP_FILE_COUNT: u8 = 0;

// implement evaluator trait for ItyFuzzer
impl<'a, VS, Loc, Addr, Out, E, EM, I, S, CS, IS, F, IF, OF, OT> Evaluator<E, EM, I, S>
    for ItyFuzzer<'a, VS, Loc, Addr, Out, CS, IS, F, IF, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    F: Feedback<I, S>,
    IF: Feedback<I, S>,
    E: Executor<EM, I, S, Self> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S> + serde::Serialize + serde::de::DeserializeOwned,
    EM: EventManager<E, I, S, Self>,
    I: VMInputT<VS, Loc, Addr>,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor
        + HasCorpus<I>
        + HasSolutions<I>
        + HasInfantStateState<Loc, Addr, VS>
        + HasItyState<Loc, Addr, VS>
        + HasExecutionResult<Loc, Addr, VS, Out>
        + HasExecutions,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    fn evaluate_input_events(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error> {
        start_timer!(state);
        executor.observers_mut().pre_exec_all(state, &input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);

        start_timer!(state);
        let exitkind = executor.run_target(self, state, manager, &input)?;
        mark_feature_time!(state, PerfFeature::TargetExecution);

        *state.executions_mut() += 1;
        // println!("{}", *state.executions());

        start_timer!(state);
        executor
            .observers_mut()
            .post_exec_all(state, &input, &exitkind)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        let observers = executor.observers();
        let reverted = state.get_execution_result().reverted;

        // get new stage first
        let is_infant_interesting = self
            .infant_feedback
            .is_interesting(state, manager, &input, observers, &exitkind)?;

        let is_solution = self
            .objective
            .is_interesting(state, manager, &input, observers, &exitkind)?;

        // add the trace of the new state
        #[cfg(any(feature = "print_infant_corpus", feature = "print_txn_corpus"))]
        {
            let txn = build_basic_txn(&input, &state.get_execution_result());
            state.get_execution_result_mut().new_state.trace.from_idx = Some(input.get_state_idx());
            state
                .get_execution_result_mut()
                .new_state
                .trace
                .add_txn(txn);
        }

        if is_infant_interesting && !reverted {
            state.add_infant_state(
                &state.get_execution_result().new_state.clone(),
                self.infant_scheduler,
            );
        }

        let mut res = ExecuteInputResult::None;
        if is_solution && !reverted {
            res = ExecuteInputResult::Solution;
        } else {
            let is_corpus = self
                .feedback
                .is_interesting(state, manager, &input, observers, &exitkind)?;
            if is_corpus {
                res = ExecuteInputResult::Corpus;
                #[cfg(feature = "print_txn_corpus")]
                {
                    unsafe {
                        DUMP_FILE_COUNT += 1;
                    }
                    let txn_text = state
                        .get_execution_result()
                        .new_state
                        .trace
                        .clone()
                        .to_string(state);

                    let data = format!(
                        "Reverted? {} \n Txn: {}",
                        state.get_execution_result().reverted,
                        txn_text
                    );
                    println!("============= New Corpus Item =============");
                    println!("{}", data);
                    println!("==========================================");

                    // write to file
                    let path = Path::new("corpus");
                    if !path.exists() {
                        std::fs::create_dir(path).unwrap();
                    }
                    let mut file =
                        File::create(format!("corpus/{}", unsafe { DUMP_FILE_COUNT })).unwrap();
                    file.write_all(data.as_bytes()).unwrap();
                }
            }
        }

        match res {
            ExecuteInputResult::None => {
                self.objective.discard_metadata(state, &input)?;
                match self.should_replace(&input, unsafe { &JMP_MAP }) {
                    Some((hash, new_fav_factor, old_testcase_idx)) => {
                        state.corpus_mut().remove(old_testcase_idx)?;

                        let mut testcase = Testcase::new(input.clone());
                        self.feedback.append_metadata(state, &mut testcase)?;
                        let new_testcase_idx = state.corpus_mut().add(testcase)?;
                        self.scheduler.on_add(state, new_testcase_idx)?;
                        self.on_replace_corpus(
                            (hash, new_fav_factor, old_testcase_idx),
                            new_testcase_idx,
                        );

                        Ok((res, Some(new_testcase_idx)))
                    }
                    None => {
                        self.feedback.discard_metadata(state, &input)?;
                        Ok((res, None))
                    }
                }
            }
            ExecuteInputResult::Corpus => {
                // Not a solution
                self.objective.discard_metadata(state, &input)?;

                // Add the input to the main corpus
                let mut testcase = Testcase::new(input.clone());
                self.feedback.append_metadata(state, &mut testcase)?;
                let idx = state.corpus_mut().add(testcase)?;
                self.scheduler.on_add(state, idx)?;
                self.on_add_corpus(&input, unsafe { &JMP_MAP }, idx);

                if send_events {
                    // TODO set None for fast targets
                    let observers_buf = if manager.configuration() == EventConfig::AlwaysUnique {
                        None
                    } else {
                        Some(manager.serialize_observers(observers)?)
                    };
                    manager.fire(
                        state,
                        Event::NewTestcase {
                            input,
                            observers_buf,
                            exit_kind: exitkind,
                            corpus_size: state.corpus().count(),
                            client_config: manager.configuration(),
                            time: current_time(),
                            executions: *state.executions(),
                        },
                    )?;
                }
                Ok((res, Some(idx)))
            }
            ExecuteInputResult::Solution => {
                unsafe {
                    println!("Flashloan: {}", FL_DATA);
                }
                println!(
                    "Found a solution! trace: {}",
                    state
                        .get_execution_result()
                        .new_state
                        .trace
                        .clone()
                        .to_string(state)
                );
                exit(0);
                // Not interesting
                self.feedback.discard_metadata(state, &input)?;

                // The input is a solution, add it to the respective corpus
                let mut testcase = Testcase::new(input.clone());
                self.objective.append_metadata(state, &mut testcase)?;
                state.solutions_mut().add(testcase)?;

                if send_events {
                    manager.fire(
                        state,
                        Event::Objective {
                            objective_size: state.solutions().count(),
                        },
                    )?;
                }

                Ok((res, None))
            }
        }
    }

    fn add_input(
        &mut self,
        _state: &mut S,
        _executor: &mut E,
        _manager: &mut EM,
        _input: I,
    ) -> Result<usize, libafl::Error> {
        todo!()
    }
}
