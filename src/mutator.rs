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
use crate::state::FuzzStateT;
use crate::state_input::ItyVMState;
use rand::random;
use serde::{Deserialize, Serialize};

pub struct FuzzMutator<S> {
    pub infant_scheduler: S,
}

impl<SC> FuzzMutator<SC>
where
    SC: Scheduler<ItyVMState, InfantStateState>,
{
    pub fn new(infant_scheduler: SC) -> Self {
        Self { infant_scheduler }
    }
}

impl<I, S, SC> Mutator<I, S> for FuzzMutator<SC>
where
    I: VMInputT + Input,
    S: State + HasRand + HasMaxSize + FuzzStateT,
    SC: Scheduler<ItyVMState, InfantStateState>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        match state.rand_mut().below(10) {
            0 => {
                // mutate the caller
            }
            1 => {
                // cross over infant state
                // we need power schedule here for infant states
                let ItyVMState(mutant) = state.get_infant_state(&self.infant_scheduler).unwrap().1;
                input.set_state(&mutant);
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
        todo!()
    }
}
