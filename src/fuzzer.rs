use crate::input::VMInputT;
use std::marker::PhantomData;

use libafl::{
    fuzzer::Fuzzer,
    prelude::{EventManager, Executor, Feedback, HasObservers, Input, ObserversTuple},
    schedulers::Scheduler,
    stages::StagesTuple,
    state::{HasClientPerfMonitor, HasExecutions, HasMetadata},
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
    S: HasClientPerfMonitor,
{
    fn evaluate_input_events(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error> {
        todo!()
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
