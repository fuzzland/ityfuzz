use libafl::Error;
use libafl::inputs::Input;
use libafl::mutators::{MutationResult, Mutator};
use libafl::state::State;
use crate::input::VMInputT;
use crate::state::FuzzState;

pub struct FuzzMutator {}

impl<I, S> Mutator<I, S> for FuzzMutator
where I: VMInputT + Input, S: State
{
    fn mutate(&mut self, state: &mut S, input: &mut I, stage_idx: i32) -> Result<MutationResult, Error> {
        todo!()
    }

    fn post_exec(&mut self, _state: &mut S, _stage_idx: i32, _corpus_idx: Option<usize>) -> Result<(), Error> {
        todo!()
    }
}