use crate::input::VMInputT;
use crate::state::InfantStateState;
use libafl::inputs::Input;
use libafl::mutators::MutationResult;
use libafl::prelude::{HasMaxSize, HasRand, Mutator, Rand, State};
use libafl::schedulers::Scheduler;
use libafl::Error;
use crate::mutation_utils::VMStateHintedMutator;

use crate::state::HasItyState;
use crate::state_input::StagedVMState;

pub struct FuzzMutator<'a, S> {
    pub infant_scheduler: &'a S,
}

impl<'a, SC> FuzzMutator<'a, SC>
where
    SC: Scheduler<StagedVMState, InfantStateState>,
{
    pub fn new(infant_scheduler: &'a SC) -> Self {
        Self { infant_scheduler }
    }
}

impl<'a, I, S, SC> Mutator<I, S> for FuzzMutator<'a, SC>
where
    I: VMInputT + Input,
    S: State + HasRand + HasMaxSize + HasItyState,
    SC: Scheduler<StagedVMState, InfantStateState>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if !input.get_staged_state().initialized {
            let concrete = state.get_infant_state(self.infant_scheduler).unwrap();
            input.set_staged_state(concrete.1, concrete.0);
        }
        let should_havoc = state.rand_mut().below(100) < 40;
        let havoc_times = if should_havoc {
            state.rand_mut().below(10) + 1
        } else {
            1
        };
        let mut mutator = || -> MutationResult {
            match state.rand_mut().below(30) {
                0 => {
                    // mutate the caller
                    let caller = state.get_rand_caller();
                    if caller == input.get_caller() {
                        return MutationResult::Skipped;
                    }
                    input.set_caller(caller);
                    MutationResult::Mutated
                }
                1 => {
                    // cross over infant state
                    // we need power schedule here for infant states
                    let old_idx = input.get_state_idx();
                    let (idx, new_state) = state.get_infant_state(self.infant_scheduler).unwrap();
                    if idx == old_idx {
                        return MutationResult::Skipped;
                    }
                    input.set_staged_state(new_state, idx);
                    MutationResult::Mutated
                }
                2 => match input.get_txn_value() {
                    Some(_) => {
                        input.set_txn_value(state.rand_mut().next() as usize);
                        MutationResult::Mutated
                    }
                    None => MutationResult::Skipped,
                },
                _ => input.mutate(state),
            }
        };

        let mut res = MutationResult::Skipped;
        while res != MutationResult::Mutated {
            for _ in 0..havoc_times {
                if mutator() == MutationResult::Mutated {
                    res = MutationResult::Mutated;
                }
            }
        }
        Ok(res)
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _stage_idx: i32,
        _corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        // todo!()
        Ok(())
    }
}
