use crate::input::VMInputT;
use crate::state::FuzzState;
use libafl::inputs::{HasBytesVec, Input};
use libafl::mutators::{MutationResult, MutatorsTuple};
use libafl::prelude::{
    tuple_list, BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
    ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator, BytesExpandMutator,
    BytesInsertMutator, BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator,
    BytesSwapMutator, DwordAddMutator, DwordInterestingMutator, HasConstLen, HasRand, Mutator,
    Prepend, QwordAddMutator, State, WordAddMutator, WordInterestingMutator,
};
use libafl::Error;

use crate::abi::{AArray, ADynamic, A256};
use rand::random;

pub struct FuzzMutator {}

impl FuzzMutator {
    pub fn new() -> Self {
        Self {}
    }
}

fn byte_mutator<I, S>(mut state: S, input: &mut I) -> MutationResult
where
    S: State + HasRand,
    I: HasBytesVec + Input,
{
    let mut mutations = tuple_list!(
        BitFlipMutator::new(),
        ByteFlipMutator::new(),
        ByteIncMutator::new(),
        ByteDecMutator::new(),
        ByteNegMutator::new(),
        ByteRandMutator::new(),
        ByteAddMutator::new(),
        WordAddMutator::new(),
        DwordAddMutator::new(),
        QwordAddMutator::new(),
        ByteInterestingMutator::new(),
        WordInterestingMutator::new(),
        DwordInterestingMutator::new(),
        // BytesExpandMutator::new(),
        // BytesInsertMutator::new(),
        // BytesRandInsertMutator::new(),
        BytesSetMutator::new(),
        BytesRandSetMutator::new(),
        // BytesCopyMutator::new(),
        BytesSwapMutator::new(),
    );
    mutations
        .get_and_mutate(random::<usize>() % mutations.len(), &mut state, input, 0)
        .unwrap()
}

// impl A256 {
//     fn mutate<S>(&mut self, state: &mut S) -> MutationResult
//         where S: State + HasRand {
//         byte_mutator(state, &mut self)
//     }
// }
//
//
// impl ADynamic {
//     fn mutate<S>(&mut self, state: &mut S) -> MutationResult
//         where S: State + HasRand {
//         byte_mutator(state, &mut self)
//     }
// }

//
// impl AArray {
//     fn mutate<S>(&mut self, state: &mut S) -> MutationResult {
//         let data_len = self.data.len();
//         if data_len == 0 {
//             return MutationResult::Skipped;
//         }
//         if self.dynamic_size {
//             if (random() % 2) == 0 {
//                 let index = random() % data_len;
//                 let mut result = self.data[index].mutate(state);
//                 return result;
//             }
//
//             // increase size
//             let base_type = self.data[0];
//             for _ in 0..random() % MAX_INSERT_SIZE {
//                 self.data.push(base_type.clone());
//             }
//
//         } else {
//             let mut index = random().next_u32() as usize % data_len;
//             return self.data[index].mutate(state);
//         }
//
//         MutationResult::Mutated
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
