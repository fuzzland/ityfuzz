/// Implements fuzzing logic for ItyFuzz

use crate::{
    input::VMInputT,
    state::{HasCurrentInputIdx, HasInfantStateState, HasItyState, InfantStateState},
    state_input::StagedVMState,
};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::Write;

use std::path::Path;
use std::process::exit;
use std::{marker::PhantomData, time::Duration};

use crate::generic_vm::vm_executor::MAP_SIZE;
use crate::generic_vm::vm_state::VMStateT;
use crate::state::HasExecutionResult;
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

use crate::evm::host::JMP_MAP;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use itertools::Itertools;
use libafl::prelude::HasRand;
use primitive_types::H256;
use serde_json::Value;
use crate::evm::input::ConciseEVMInput;
use crate::evm::vm::EVMState;
use crate::input::ConciseSerde;
use crate::oracle::BugMetadata;
use crate::scheduler::{HasReportCorpus, HasVote};
use crate::telemetry::report_vulnerability;

const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_millis(100);
pub static mut RUN_FOREVER: bool = false;
pub static mut ORACLE_OUTPUT: Vec<serde_json::Value> = vec![];


/// A fuzzer that implements ItyFuzz logic using LibAFL's [`Fuzzer`] trait
///
/// CS: The scheduler for the input corpus
/// IS: The scheduler for the infant state corpus
/// F: The feedback for the input corpus (e.g., coverage map)
/// IF: The feedback for the infant state corpus (e.g., comparison, etc.)
/// I: The VM input type
/// OF: The objective for the input corpus (e.g., oracles)
/// S: The fuzzer state type
/// VS: The VM state type
/// Addr: The address type (e.g., H160)
/// Loc: The call target location type (e.g., H160)
#[derive(Debug)]
pub struct ItyFuzzer<'a, VS, Loc, Addr, Out, CS, IS, F, IF, IFR, I, OF, S, OT, CI>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr, VS, CI>, InfantStateState<Loc, Addr, VS, CI>> + HasReportCorpus<InfantStateState<Loc, Addr, VS, CI>>,
    F: Feedback<I, S>,
    IF: Feedback<I, S>,
    IFR: Feedback<I, S>,
    I: VMInputT<VS, Loc, Addr, CI>,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor + HasCorpus<I> + HasRand + HasMetadata,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// The scheduler for the input corpus
    scheduler: CS,
    /// The feedback for the input corpus (e.g., coverage map)
    feedback: F,
    /// The feedback for the input state and execution result in infant state corpus (e.g., comparison, etc.)
    infant_feedback: IF,
    /// The feedback for the resultant state to be inserted into infant state corpus (e.g., dataflow, etc.)
    infant_result_feedback: IFR,
    /// The scheduler for the infant state corpus
    infant_scheduler: &'a IS,
    /// The objective for the input corpus (e.g., oracles)
    objective: OF,
    /// Map from hash of a testcase can do (e.g., coverage map) to the (testcase idx, fav factor)
    /// Used to minimize the corpus
    minimizer_map: HashMap<u64, (usize, f64)>,
    phantom: PhantomData<(I, S, OT, VS, Loc, Addr, Out, CI)>,
    /// work dir path
    work_dir: String,
}

impl<'a, VS, Loc, Addr, Out, CS, IS, F, IF, IFR, I, OF, S, OT, CI>
    ItyFuzzer<'a, VS, Loc, Addr, Out, CS, IS, F, IF, IFR, I, OF, S, OT, CI>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr, VS, CI>, InfantStateState<Loc, Addr, VS, CI>> + HasReportCorpus<InfantStateState<Loc, Addr, VS, CI>>,
    F: Feedback<I, S>,
    IF: Feedback<I, S>,
    IFR: Feedback<I, S>,
    I: VMInputT<VS, Loc, Addr, CI>,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor + HasCorpus<I> + HasRand + HasMetadata,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Creates a new ItyFuzzer
    pub fn new(
        scheduler: CS,
        infant_scheduler: &'a IS,
        feedback: F,
        infant_feedback: IF,
        infant_result_feedback: IFR,
        objective: OF,
        work_dir: String,
    ) -> Self {
        Self {
            scheduler,
            feedback,
            infant_feedback,
            infant_result_feedback,
            infant_scheduler,
            objective,
            work_dir,
            minimizer_map: Default::default(),
            phantom: PhantomData,
        }
    }

    /// Called every time a new testcase is added to the corpus
    /// Setup the minimizer map
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

    /// Called every time a testcase is replaced for the corpus
    /// Update the minimizer map
    pub fn on_replace_corpus(
        &mut self,
        (hash, new_fav_factor, _): (u64, f64, usize),
        new_testcase_idx: usize,
    ) -> () {
        let res = self.minimizer_map.get_mut(&hash).unwrap();
        res.0 = new_testcase_idx;
        res.1 = new_fav_factor;
    }

    /// Determine if a testcase should be replaced based on the minimizer map
    /// If the new testcase has a higher fav factor, replace the old one
    /// Returns None if the testcase should not be replaced
    /// Returns Some((hash, new_fav_factor, testcase_idx)) if the testcase should be replaced
    pub fn should_replace(
        &self,
        input: &I,
        coverage: &[u8; MAP_SIZE],
    ) -> Option<(u64, f64, usize)> {
        let mut hasher = DefaultHasher::new();
        coverage.hash(&mut hasher);
        let hash = hasher.finish();
        // if the coverage is same
        if let Some((testcase_idx, fav_factor)) = self.minimizer_map.get(&hash) {
            let new_fav_factor = input.fav_factor();
            // if the new testcase has a higher fav factor, replace the old one
            if new_fav_factor > *fav_factor {
                return Some((hash, new_fav_factor, testcase_idx.clone()));
            }
        }
        None
    }
}

/// Implement fuzzer trait for ItyFuzzer
impl<'a, VS, Loc, Addr, Out, CS, IS, E, EM, F, IF, IFR, I, OF, S, ST, OT, CI> Fuzzer<E, EM, I, S, ST>
    for ItyFuzzer<'a, VS, Loc, Addr, Out, CS, IS, F, IF, IFR, I, OF, S, OT, CI>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr, VS, CI>, InfantStateState<Loc, Addr, VS, CI>> + HasReportCorpus<InfantStateState<Loc, Addr, VS, CI>>,
    EM: EventManager<E, I, S, Self>,
    F: Feedback<I, S>,
    IF: Feedback<I, S>,
    IFR: Feedback<I, S>,
    I: VMInputT<VS, Loc, Addr, CI>,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor + HasExecutions + HasMetadata + HasCurrentInputIdx + HasRand + HasCorpus<I>,
    ST: StagesTuple<E, EM, S, Self> + ?Sized,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde
{
    /// Fuzz one input
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

    /// Fuzz loop
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
pub static mut DUMP_FILE_COUNT: usize = 0;

pub static mut REPLAY: bool = false;


#[macro_export]
macro_rules! dump_file {
    ($state: expr, $corpus_path: expr, $print: expr) => {
        {
            if !unsafe {REPLAY} {
                unsafe {
                    DUMP_FILE_COUNT += 1;
                }

                let tx_trace = $state.get_execution_result().new_state.trace.clone();
                let txn_text = tx_trace.to_string($state);
                let txn_text_replayable = tx_trace.to_file_str($state);

                let data = format!(
                    "Reverted? {} \n Txn: {}",
                    $state.get_execution_result().reverted,
                    txn_text
                );
                if $print {
                    println!("============= New Corpus Item =============");
                    println!("{}", data);
                    println!("==========================================");
                }

                // write to file
                let path = Path::new($corpus_path.as_str());
                if !path.exists() {
                    std::fs::create_dir_all(path).unwrap();
                }
                let mut file =
                    File::create(format!("{}/{}", $corpus_path, unsafe { DUMP_FILE_COUNT })).unwrap();
                file.write_all(data.as_bytes()).unwrap();

                let mut replayable_file =
                    File::create(format!("{}/{}_replayable", $corpus_path, unsafe { DUMP_FILE_COUNT })).unwrap();
                replayable_file.write_all(txn_text_replayable.as_bytes()).unwrap();
            }
        }
    };
}

#[macro_export]
macro_rules! dump_txn {
    ($corpus_path: expr, $input: expr) => {
        {
            if !unsafe {REPLAY} {
                unsafe {
                    DUMP_FILE_COUNT += 1;
                }
                // write to file
                let path = Path::new($corpus_path.as_str());
                if !path.exists() {
                    std::fs::create_dir_all(path).unwrap();
                }

                let concise_input = ConciseEVMInput::from_input($input, &EVMExecutionResult::empty_result());

                let txn_text = concise_input.serialize_string();
                let txn_text_replayable = String::from_utf8(concise_input.serialize_concise()).unwrap();

                let mut file =
                    File::create(format!("{}/{}_seed", $corpus_path, unsafe { DUMP_FILE_COUNT })).unwrap();
                file.write_all(txn_text.as_bytes()).unwrap();

                let mut replayable_file =
                    File::create(format!("{}/{}_seed_replayable", $corpus_path, unsafe { DUMP_FILE_COUNT })).unwrap();
                replayable_file.write_all(txn_text_replayable.as_bytes()).unwrap();
            }
        }
    };
}

// implement evaluator trait for ItyFuzzer
impl<'a, VS, Loc, Addr, Out, E, EM, I, S, CS, IS, F, IF, IFR, OF, OT, CI> Evaluator<E, EM, I, S>
    for ItyFuzzer<'a, VS, Loc, Addr, Out, CS, IS, F, IF, IFR, I, OF, S, OT, CI>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr, VS, CI>, InfantStateState<Loc, Addr, VS, CI>> + HasReportCorpus<InfantStateState<Loc, Addr, VS, CI>>,
    F: Feedback<I, S>,
    IF: Feedback<I, S>,
    IFR: Feedback<I, S>,
    E: Executor<EM, I, S, Self> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S> + serde::Serialize + serde::de::DeserializeOwned,
    EM: EventManager<E, I, S, Self>,
    I: VMInputT<VS, Loc, Addr, CI>,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor
        + HasCorpus<I>
        + HasSolutions<I>
        + HasInfantStateState<Loc, Addr, VS, CI>
        + HasItyState<Loc, Addr, VS, CI>
        + HasExecutionResult<Loc, Addr, VS, Out, CI>
        + HasExecutions
        + HasMetadata
        + HasRand,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde
{
    /// Evaluate input (execution + feedback + objectives)
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

        // execute the input
        start_timer!(state);
        let exitkind = executor.run_target(self, state, manager, &input)?;
        mark_feature_time!(state, PerfFeature::TargetExecution);
        *state.executions_mut() += 1;

        start_timer!(state);
        executor
            .observers_mut()
            .post_exec_all(state, &input, &exitkind)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        let observers = executor.observers();

        let concise_input = input.get_concise(state.get_execution_result());

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
            state.get_execution_result_mut().new_state.trace.from_idx = Some(input.get_state_idx());
            state
                .get_execution_result_mut()
                .new_state
                .trace
                .add_input(concise_input);
        }

        // add the new VM state to infant state corpus if it is interesting
        let mut state_idx = input.get_state_idx();
        if is_infant_interesting && !reverted {
            state_idx = state.add_infant_state(
                &state.get_execution_result().new_state.clone(),
                self.infant_scheduler,
                input.get_state_idx()
            );

            if self
                .infant_result_feedback
                .is_interesting(state, manager, &input, observers, &exitkind)? {
                self.infant_scheduler.sponsor_state(
                    state.get_infant_state_state(), state_idx, 3
                )
            }
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

                // Debugging prints
                #[cfg(feature = "print_txn_corpus")]
                {
                    let corpus_dir = format!("{}/corpus", self.work_dir.as_str()).to_string();
                    dump_file!(state, corpus_dir, true);
                }
            }
        }

        let mut corpus_idx = 0;
        if res == ExecuteInputResult::Corpus || res == ExecuteInputResult::Solution {
            // Add the input to the main corpus
            let mut testcase = Testcase::new(input.clone());
            self.feedback.append_metadata(state, &mut testcase)?;
            corpus_idx = state.corpus_mut().add(testcase)?;
            self.infant_scheduler.report_corpus(
                state.get_infant_state_state(),
                state_idx
            );
            self.scheduler.on_add(state, corpus_idx)?;
            self.on_add_corpus(&input, unsafe { &JMP_MAP }, corpus_idx);
        }

        let final_res = match res {
            // not interesting input, just check whether we should replace it due to better fav factor
            ExecuteInputResult::None => {
                self.objective.discard_metadata(state, &input)?;
                match self.should_replace(&input, unsafe { &JMP_MAP }) {
                    Some((hash, new_fav_factor, old_testcase_idx)) => {
                        state.corpus_mut().remove(old_testcase_idx)?;

                        let mut testcase = Testcase::new(input.clone());
                        let new_testcase_idx = state.corpus_mut().add(testcase)?;
                        self.infant_scheduler.report_corpus(
                            state.get_infant_state_state(),
                            state_idx
                        );
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
            // if the input is interesting, we need to add it to the input corpus
            ExecuteInputResult::Corpus => {
                // Not a solution
                self.objective.discard_metadata(state, &input)?;

                // Fire the event for CLI
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
                Ok((res, Some(corpus_idx)))
            }
            // find the solution
            ExecuteInputResult::Solution => {
                report_vulnerability(
                    unsafe {serde_json::to_string(&ORACLE_OUTPUT).expect("")},
                );

                println!("\n\n\n😊😊 Found violations! \n\n");
                let cur_report = format!(
                    "================ Oracle ================\n{}\n================ Trace ================\n{}\n",
                    unsafe { ORACLE_OUTPUT.iter().map(|v| { v["bug_info"].as_str().expect("") }).join("\n") },
                    state
                        .get_execution_result()
                        .new_state
                        .trace
                        .clone()
                        .to_string(state)
                );
                println!("{}", cur_report);

                let vuln_file = format!("{}/vuln_info.jsonl", self.work_dir.as_str());
                let mut f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(vuln_file)
                    .expect("Unable to open file");
                f.write_all(unsafe {
                    ORACLE_OUTPUT.iter().map(|v| serde_json::to_string(v).expect("failed to json"))
                        .join("\n").as_bytes()
                }).expect("Unable to write data");
                f.write_all(b"\n").expect("Unable to write data");

                state.metadata_mut().get_mut::<BugMetadata>().unwrap().register_corpus_idx(
                    corpus_idx
                );

                #[cfg(feature = "print_txn_corpus")]
                {
                    let vulns_dir = format!("{}/vulnerabilities", self.work_dir.as_str());
                    dump_file!(state, vulns_dir, false);
                }

                if !unsafe { RUN_FOREVER } {
                    exit(0);
                }

                return Ok((res, None));
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
        };
        unsafe {
            ORACLE_OUTPUT.clear();
        }
        final_res
    }

    /// never called!
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
