/// Mutation utilities for the EVM
use crate::input::VMInputT;
use libafl::inputs::{HasBytesVec, Input};
use libafl::mutators::MutationResult;
use libafl::prelude::{
    tuple_list, BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
    ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator, BytesExpandMutator,
    BytesInsertMutator, BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator,
    BytesSwapMutator, DwordAddMutator, DwordInterestingMutator, HasMetadata, Mutator, Named,
    QwordAddMutator, Rand, StdScheduledMutator, WordAddMutator, WordInterestingMutator,
};
use libafl::state::{HasMaxSize, HasRand, State};
use libafl::{impl_serdeany, Error};
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use crate::evm::types::EVMU256;

/// Constants in the contracts
///
/// This is metadata attached to the global fuzz state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstantPoolMetadata {
    /// Vector of constants in the contracts
    pub constants: Vec<Vec<u8>>,
}

impl ConstantPoolMetadata {
    /// Create a new [`ConstantPoolMetadata`]
    pub fn new() -> Self {
        Self {
            constants: Vec::new(),
        }
    }

    /// Add a constant to the pool
    pub fn add_constant(&mut self, constant: Vec<u8>) {
        self.constants.push(constant);
    }
}

impl_serdeany!(ConstantPoolMetadata);

/// [`ConstantHintedMutator`] is a mutator that mutates the input to a constant in the contract
///
/// We discover that sometimes directly setting the bytes to the constants allow us to increase
/// test coverage.
pub struct ConstantHintedMutator;

impl Named for ConstantHintedMutator {
    fn name(&self) -> &str {
        "ConstantHintedMutator"
    }
}

impl ConstantHintedMutator {
    pub fn new() -> Self {
        Self {}
    }
}

impl<I, S> Mutator<I, S> for ConstantHintedMutator
where
    S: State + HasRand + HasMetadata,
    I: Input + HasBytesVec,
{
    /// Mutate the input to a constant in the contract
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let idx = state.rand_mut().next() as usize;

        let constant = match state.metadata().get::<ConstantPoolMetadata>() {
            Some(meta) if !meta.constants.is_empty() => unsafe { 
                meta.constants.get_unchecked(idx % meta.constants.len()) 
            },
            _ => return Ok(MutationResult::Skipped),
        };

        let input_bytes = input.bytes_mut();
        let input_len = input_bytes.len();
        let constant_len = constant.len();

        if input_len < constant_len {
            input_bytes.copy_from_slice(&constant[0..input_len]);
        } else {
            input_bytes
                .copy_from_slice(&[vec![0; input_len - constant_len], constant.clone()].concat());
        }
        Ok(MutationResult::Mutated)
    }
}

/// [`VMStateHintedMutator`] is a mutator that mutates the input to a value in the VM state
///
/// Similar to [`ConstantHintedMutator`], we discover that sometimes directly setting the bytes to
/// the values in the VM state allow us to increase test coverage.
pub struct VMStateHintedMutator<'a> {
    pub vm_slots: &'a HashMap<EVMU256, EVMU256>,
}

impl Named for VMStateHintedMutator<'_> {
    fn name(&self) -> &str {
        "VMStateHintedMutator"
    }
}

impl<'a> VMStateHintedMutator<'a> {
    pub fn new(vm_slots: &'a HashMap<EVMU256, EVMU256>) -> Self {
        Self { vm_slots }
    }
}

/// Mutate the input to a value in the VM state
pub fn mutate_with_vm_slot<S: State + HasRand>(
    vm_slots: &HashMap<EVMU256, EVMU256>,
    state: &mut S,
) -> EVMU256 {
    // sample a key from the vm_state.state
    let idx = state.rand_mut().below(vm_slots.len() as u64) as usize;
    let key = vm_slots.keys().nth(idx).unwrap();
    if state.rand_mut().below(100) < 90 {
        let value = vm_slots.get(key).unwrap();
        value.clone()
    } else {
        key.clone()
    }
}

impl<'a, I, S> Mutator<I, S> for VMStateHintedMutator<'a>
where
    S: State + HasRand,
    I: Input + HasBytesVec,
{
    /// Mutate the input to a value in the VM state
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let input_len = input.bytes().len();
        if input_len < 8 {
            return Ok(MutationResult::Skipped);
        }
        let new_val = mutate_with_vm_slot(self.vm_slots, state);

        let mut data: [u8; 32] = new_val.to_be_bytes();

        input.bytes_mut().copy_from_slice(&data[(32 - input_len)..]);
        Ok(MutationResult::Mutated)
    }
}


/// Mutator that mutates the `CONSTANT SIZE` input bytes (e.g., uint256) in various ways provided by
/// [`libafl::mutators`]. It also uses the [`ConstantHintedMutator`] and [`VMStateHintedMutator`]
pub fn byte_mutator<I, S>(
    state: &mut S,
    input: &mut I,
    vm_slots: Option<HashMap<EVMU256, EVMU256>>,
) -> MutationResult
where
    S: State + HasRand + HasMetadata,
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
        ConstantHintedMutator::new(),
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

/// Mutator that mutates the `VARIABLE SIZE` input bytes (e.g., string) in various ways provided by
/// [`libafl::mutators`]. It also uses the [`ConstantHintedMutator`] and [`VMStateHintedMutator`]
pub fn byte_mutator_with_expansion<I, S>(
    state: &mut S,
    input: &mut I,
    vm_slots: Option<HashMap<EVMU256, EVMU256>>,
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
