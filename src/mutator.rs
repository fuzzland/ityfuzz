use crate::input::VMInputT;
use crate::state::FuzzState;
use libafl::inputs::{HasBytesVec, Input};
use libafl::mutators::{MutationResult, MutatorsTuple};
use libafl::prelude::{
    tuple_list, BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
    ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator, BytesExpandMutator,
    BytesInsertMutator, BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator,
    BytesSwapMutator, DwordAddMutator, DwordInterestingMutator, HasConstLen, HasMaxSize, HasRand,
    Mutator, Prepend, QwordAddMutator, Rand, State, WordAddMutator, WordInterestingMutator,
};
use libafl::Error;
use primitive_types::H160;

use crate::abi::{AArray, ADynamic, BoxedABI, A256};
use crate::state::FuzzStateT;
use rand::random;
use serde::{Deserialize, Serialize};

pub struct FuzzMutator {}

impl FuzzMutator {
    pub fn new() -> Self {
        Self {}
    }
}

impl<I, S> Mutator<I, S> for FuzzMutator
where
    I: VMInputT + Input,
    S: State + HasRand + FuzzStateT,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        match state.rand_mut().below(2) {
            0 => {
                // mutate the caller
            }
            1 => {
                // cross over infant state
                // we need power schedule here for infant states
            }
            _ => {
                panic!("unreachable");
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
