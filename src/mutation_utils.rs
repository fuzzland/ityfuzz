use crate::input::VMInputT;
use crate::VMState;
use libafl::inputs::{HasBytesVec, Input};
use libafl::mutators::MutationResult;
use libafl::prelude::{
    tuple_list, BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
    ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator, BytesExpandMutator,
    BytesInsertMutator, BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator,
    BytesSwapMutator, DwordAddMutator, DwordInterestingMutator, Mutator, Named, QwordAddMutator,
    Rand, StdScheduledMutator, WordAddMutator, WordInterestingMutator,
};
use libafl::state::{HasMaxSize, HasRand, State};
use libafl::Error;
use primitive_types::U256;
use std::collections::HashMap;

pub struct VMStateHintedMutator<'a> {
    pub vm_slots: &'a HashMap<U256, U256>,
}

impl Named for VMStateHintedMutator<'_> {
    fn name(&self) -> &str {
        "VMStateHintedMutator"
    }
}

impl<'a> VMStateHintedMutator<'a> {
    pub fn new(vm_slots: &'a HashMap<U256, U256>) -> Self {
        Self { vm_slots }
    }
}

impl<'a, I, S> Mutator<I, S> for VMStateHintedMutator<'a>
where
    S: State + HasRand,
    I: Input + HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let bm = input.bytes_mut();
        let bm_len = bm.len();
        if bm_len < 8 {
            return Ok(MutationResult::Skipped);
        }
        let mut data = vec![0u8; 32];
        // sample a key from the vm_state.state
        let idx = state.rand_mut().below(self.vm_slots.len() as u64) as usize;
        let key = self.vm_slots.keys().nth(idx).unwrap();
        if state.rand_mut().below(100) < 80 {
            let value = self.vm_slots.get(key).unwrap();
            value.to_big_endian(&mut data);
        } else {
            key.to_big_endian(&mut data);
        }
        bm.copy_from_slice(&data[(32 - bm_len)..]);
        Ok(MutationResult::Mutated)
    }
}

pub fn byte_mutator<I, S>(
    state: &mut S,
    input: &mut I,
    vm_slots: Option<HashMap<U256, U256>>,
) -> MutationResult
where
    S: State + HasRand,
    I: HasBytesVec + Input,
{
    let mutations = tuple_list!(
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
        BytesSetMutator::new(),
        BytesRandSetMutator::new(),
        BytesSwapMutator::new(),
    );

    if let Some(vm_slots) = vm_slots {
        let mut mutator =
            StdScheduledMutator::new((VMStateHintedMutator::new(&vm_slots), mutations));
        mutator.mutate(state, input, 0).unwrap()
    } else {
        let mut mutator = StdScheduledMutator::new(mutations);
        mutator.mutate(state, input, 0).unwrap()
    }
}

pub fn byte_mutator_with_expansion<I, S>(
    state: &mut S,
    input: &mut I,
    vm_slots: Option<HashMap<U256, U256>>,
) -> MutationResult
where
    S: State + HasRand + HasMaxSize,
    I: HasBytesVec + Input,
{
    let mutations = tuple_list!(
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
        BytesExpandMutator::new(),
        BytesInsertMutator::new(),
        BytesRandInsertMutator::new(),
        BytesSetMutator::new(),
        BytesRandSetMutator::new(),
        BytesCopyMutator::new(),
        BytesSwapMutator::new(),
    );

    if let Some(vm_slots) = vm_slots {
        let mut mutator =
            StdScheduledMutator::new((VMStateHintedMutator::new(&vm_slots), mutations));
        mutator.mutate(state, input, 0).unwrap()
    } else {
        let mut mutator = StdScheduledMutator::new(mutations);
        mutator.mutate(state, input, 0).unwrap()
    }
}
