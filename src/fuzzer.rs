use crate::{
    input::VMInputT,
    state::{HasInfantStateState, HasItyState},
    state_input::ItyVMState,
};
use std::marker::PhantomData;

use crate::state::HasExecutionResult;
use libafl::{
    fuzzer::Fuzzer,
    mark_feature_time,
    prelude::{
        current_time, Corpus, Event, EventConfig, EventManager, Executor, Feedback, HasObservers,
        Input, ObserversTuple, Testcase,
    },
    schedulers::Scheduler,
    stages::StagesTuple,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasMetadata, HasSolutions},
    Error, Evaluator, ExecuteInputResult,
};

#[derive(Debug)]
pub struct ItyFuzzer<CS, F, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    F: Feedback<I, S>,
    I: VMInputT,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor,
{
    scheduler: CS,
    feedback: F,
    objective: OF,
    phantom: PhantomData<(I, S, OT)>,
}

impl<CS, F, I, OF, S, OT> ItyFuzzer<CS, F, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    F: Feedback<I, S>,
    I: VMInputT,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor,
{
    pub fn new(scheduler: CS, feedback: F, objective: OF) -> Self {
        Self {
            scheduler,
            feedback,
            objective,
            phantom: PhantomData,
        }
    }
}

// implement fuzzer trait for ItyFuzzer
// Seems that we can get rid of this impl and just use StdFuzzer?
impl<CS, E, EM, F, I, OF, S, ST, OT> Fuzzer<E, EM, I, S, ST> for ItyFuzzer<CS, F, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    EM: EventManager<E, I, S, Self>,
    F: Feedback<I, S>,
    I: VMInputT,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor + HasExecutions + HasMetadata,
    ST: StagesTuple<E, EM, S, Self> + ?Sized,
{
    fn fuzz_one(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<usize, libafl::Error> {
        let idx = self.scheduler.next(state)?;
        stages.perform_all(self, executor, state, manager, idx)?;
        manager.process(self, state, executor)?;
        Ok(idx)
    }
}

// implement evaluator trait for ItyFuzzer
impl<E, EM, I, S, CS, F, OF, OT> Evaluator<E, EM, I, S> for ItyFuzzer<CS, F, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    F: Feedback<I, S>,
    E: Executor<EM, I, S, Self> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S> + serde::Serialize + serde::de::DeserializeOwned,
    EM: EventManager<E, I, S, Self>,
    I: VMInputT,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor
        + HasCorpus<I>
        + HasSolutions<I>
        + HasInfantStateState
        + HasItyState
        + HasExecutionResult,
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

        start_timer!(state);
        executor
            .observers_mut()
            .post_exec_all(state, &input, &exitkind)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        let observers = executor.observers();
        let is_solution = self
            .objective
            .is_interesting(state, manager, &input, observers, &exitkind)?;

        let mut res = ExecuteInputResult::None;
        if is_solution {
            res = ExecuteInputResult::Solution;
        } else {
            let is_corpus = self
                .feedback
                .is_interesting(state, manager, &input, observers, &exitkind)?;
            if is_corpus {
                res = ExecuteInputResult::Corpus;
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
                            executions: 0,
                        },
                    )?;
                }
                Ok((res, Some(idx)))
            }
            ExecuteInputResult::Solution => {
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
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
    ) -> Result<usize, libafl::Error> {
        todo!()
    }
}
