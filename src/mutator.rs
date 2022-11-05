use crate::input::VMInputT;
use crate::state::{FuzzState, InfantStateState};
use libafl::inputs::{HasBytesVec, Input};
use libafl::mutators::{MutationResult, MutatorsTuple};
use libafl::prelude::{
    tuple_list, BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
    ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator, BytesExpandMutator,
    BytesInsertMutator, BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator,
    BytesSwapMutator, DwordAddMutator, DwordInterestingMutator, HasConstLen, HasMaxSize, HasRand,
    Mutator, Prepend, QwordAddMutator, Rand, State, WordAddMutator, WordInterestingMutator,
};
use libafl::schedulers::Scheduler;
use libafl::Error;
use primitive_types::H160;

use crate::abi::{AArray, ADynamic, BoxedABI, A256};
use crate::state::HasItyState;
use crate::state_input::StagedVMState;
use rand::random;
use serde::{Deserialize, Serialize};

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
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if !input.get_staged_state().initialized {
            let concrete = state.get_infant_state(self.infant_scheduler).unwrap();
            input.set_staged_state(concrete.1, concrete.0);
        }
        match state.rand_mut().below(10) {
            0 => {
                // mutate the caller
                let caller = state.get_rand_caller();
                if caller == input.get_caller() {
                    return Ok(MutationResult::Skipped);
                }
                input.set_caller(caller);
            }
            1 => {
                // cross over infant state
                // we need power schedule here for infant states
                let mutant = state.get_infant_state(self.infant_scheduler).unwrap();
                input.set_staged_state(mutant.1, mutant.0);
            }
            _ => {
                input.mutate(state);
            }
        }
        return Ok(MutationResult::Mutated);
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
