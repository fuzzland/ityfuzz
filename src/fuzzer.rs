use crate::{
    input::VMInputT,
    state::{HasInfantStateState, HasItyState, InfantStateState},
    state_input::StagedVMState,
};
use std::ops::Deref;
use std::process::exit;
use std::{marker::PhantomData, time::Duration};
use std::fmt::Debug;

use crate::generic_vm::vm_state::VMStateT;
#[cfg(feature = "record_instruction_coverage")]
use crate::r#const::DEBUG_PRINT_PERCENT;
use crate::state::HasExecutionResult;
use crate::tracer::TxnTrace;
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

const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub struct ItyFuzzer<'a, VS, Loc, Addr, CS, IS, F, IF, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    F: Feedback<I, S>,
    IF: Feedback<I, S>,
    I: VMInputT<VS, Loc, Addr>,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug+ Clone,
    Loc: Serialize + DeserializeOwned + Debug+ Clone,
{
    scheduler: CS,
    feedback: F,
    infant_feedback: IF,
    infant_scheduler: &'a IS,
    objective: OF,
    phantom: PhantomData<(I, S, OT, VS, Loc, Addr)>,
}

impl<'a, VS, Loc, Addr, CS, IS, F, IF, I, OF, S, OT> ItyFuzzer<'a, VS, Loc, Addr, CS, IS, F, IF, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    F: Feedback<I, S>,
    IF: Feedback<I, S>,
    I: VMInputT<VS, Loc, Addr>,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug+ Clone,
    Loc:Serialize + DeserializeOwned +  Debug+ Clone,
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
            phantom: PhantomData,
        }
    }
}

// implement fuzzer trait for ItyFuzzer
// Seems that we can get rid of this impl and just use StdFuzzer?
impl<'a, VS, Loc, Addr, CS, IS, E, EM, F, IF, I, OF, S, ST, OT> Fuzzer<E, EM, I, S, ST>
    for ItyFuzzer<'a, VS, Loc, Addr, CS, IS, F, IF, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    EM: EventManager<E, I, S, Self>,
    F: Feedback<I, S>,
    IF: Feedback<I, S>,
    I: VMInputT<VS, Loc, Addr>,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor + HasExecutions + HasMetadata,
    ST: StagesTuple<E, EM, S, Self> + ?Sized,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug+ Clone,
    Loc: Serialize + DeserializeOwned + Debug+ Clone,
{
    fn fuzz_one(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<usize, libafl::Error> {
        let idx = self.scheduler.next(state)?;
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

// implement evaluator trait for ItyFuzzer
impl<'a, VS, Loc, Addr, E, EM, I, S, CS, IS, F, IF, OF, OT> Evaluator<E, EM, I, S>
    for ItyFuzzer<'a, VS, Loc, Addr, CS, IS, F, IF, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr,VS>, InfantStateState<Loc, Addr,VS>>,
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
        + HasExecutionResult<Loc, Addr, VS>
        + HasExecutions,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
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
        if is_infant_interesting && !reverted {
            let new_state = state.get_execution_result();
            state.add_infant_state(&new_state.new_state.clone(), self.infant_scheduler);
        }

        let is_solution = self
            .objective
            .is_interesting(state, manager, &input, observers, &exitkind)?;

        let mut res = ExecuteInputResult::None;
        if is_solution && !reverted {
            res = ExecuteInputResult::Solution;
        } else {
            let is_corpus = self
                .feedback
                .is_interesting(state, manager, &input, observers, &exitkind)?;
            if is_corpus {
                res = ExecuteInputResult::Corpus;
            }
        }

        #[cfg(feature = "print_txn_corpus")]
        {
            use crate::r#const::DEBUG_PRINT_PERCENT;
            if random::<usize>() % DEBUG_PRINT_PERCENT == 0 {
                println!("============= Corpus =============");
                for i in 0..state.corpus().count() {
                    match state.corpus().get(i) {
                        Ok(v) => {
                            println!("{}", v.borrow().input().as_ref().unwrap().to_string());
                        }
                        _ => {}
                    }
                }
                println!("==================================");
            }
        }

        match res {
            ExecuteInputResult::None => {
                self.feedback.discard_metadata(state, &input)?;
                self.objective.discard_metadata(state, &input)?;
                Ok((res, None))
            }
            ExecuteInputResult::Corpus => {
                // Not a solution
                self.objective.discard_metadata(state, &input)?;

                // Add the input to the main corpus
                let mut testcase = Testcase::new(input.clone());
                self.feedback.append_metadata(state, &mut testcase)?;
                let idx = state.corpus_mut().add(testcase)?;
                self.scheduler.on_add(state, idx)?;

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
                println!(
                    "trace: {}",
                    TxnTrace::to_string(&input.get_staged_state().trace, state)
                );
                println!("Found a solution! {}", input.to_string());
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
