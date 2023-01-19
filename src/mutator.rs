use crate::input::VMInputT;
use crate::state::FuzzState;
use libafl::inputs::{HasBytesVec, Input};
use libafl::mutators::{MutationResult, MutatorsTuple};
use libafl::prelude::{
    tuple_list, BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
    ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator, BytesExpandMutator,
    BytesInsertMutator, BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator,
    BytesSwapMutator, DwordAddMutator, DwordInterestingMutator, HasConstLen, HasMaxSize, HasRand,
    Mutator, Prepend, QwordAddMutator, State, WordAddMutator, WordInterestingMutator,
};
use libafl::Error;

use crate::abi::{AArray, ADynamic, BoxedABI, A256};
use rand::random;

pub struct FuzzMutator {}

impl FuzzMutator {
    pub fn new() -> Self {
        Self {}
    }
}

//
// impl BoxedABI {
//     fn mutate<S>(&mut self, state: &mut S) -> MutationResult
//         where S: State + HasRand + HasMaxSize {
//         match self.get_type() {
//             ABILossyType::T256 => {
//                 let mut inner = self.get_mut().downcast_mut::<A256>().unwrap();
//                 inner.mutate(state)
//             }
//             _ => {
//                 MutationResult::Mutated
//             }
//         }
//     }
// }

impl<I, S> Mutator<I, S> for FuzzMutator
where
    I: VMInputT + Input,
    S: State,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        todo!()
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
