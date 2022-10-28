use crate::state::{HasExecutionResult, HasInfantStateState, HasItyState, InfantStateState};
use crate::state_input::ItyVMState;
use libafl::schedulers::Scheduler;
use libafl::stages::Stage;
use libafl::Error;

pub struct InfantStateStage<'a, SC> {
    scheduler: &'a SC,
}

impl<'a, SC> InfantStateStage<'a, SC> {
    pub fn new(scheduler: &'a SC) -> Self {
        Self { scheduler }
    }
}

impl<'a, E, EM, S, Z, SC> Stage<E, EM, S, Z> for InfantStateStage<'a, SC>
where
    S: HasItyState + HasExecutionResult,
    SC: Scheduler<ItyVMState, InfantStateState>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        // add the current VMState to the infant state corpus
        // TODO(shou): add feedback for infant state here
        let new_state = state.get_execution_result();
        state.add_infant_state(&ItyVMState(new_state.new_state.clone()), self.scheduler);
        Ok(())
    }
}
