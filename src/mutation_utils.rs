use std::collections::HashMap;

/// Mutation utilities for the EVM
use libafl::inputs::{HasBytesVec, Input};
use libafl::{
    mutators::MutationResult,
    prelude::{
        BitFlipMutator,
        ByteAddMutator,
        ByteDecMutator,
        ByteFlipMutator,
        ByteIncMutator,
        ByteInterestingMutator,
        ByteNegMutator,
        ByteRandMutator,
        BytesCopyMutator,
        BytesExpandMutator,
        BytesInsertMutator,
        BytesRandInsertMutator,
        BytesRandSetMutator,
        BytesSetMutator,
        BytesSwapMutator,
        DwordAddMutator,
        DwordInterestingMutator,
        HasMetadata,
        Mutator,
        QwordAddMutator,
        StdScheduledMutator,
        WordAddMutator,
        WordInterestingMutator,
    },
    state::{HasMaxSize, HasRand, State},
    Error,
};
use libafl_bolts::{impl_serdeany, prelude::Rand, tuples::tuple_list, Named};
use serde::{Deserialize, Serialize};

use crate::evm::types::EVMU256;

/// Constants in the contracts
///
/// This is metadata attached to the global fuzz state
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ConstantPoolMetadata {
    /// Vector of constants in the contracts
    pub constants: Vec<Vec<u8>>,
}

impl ConstantPoolMetadata {
    /// Create a new [`ConstantPoolMetadata`]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a constant to the pool
    pub fn add_constant(&mut self, constant: Vec<u8>) {
        self.constants.push(constant);
    }
}

impl_serdeany!(ConstantPoolMetadata);

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MutatorMetadata {
    pub full_overwrite_performed: bool,
}

impl MutatorMetadata {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn set_full_overwrite_performed(&mut self, full_overwrite_performed: bool) {
        self.full_overwrite_performed = full_overwrite_performed;
    }
}

impl_serdeany!(MutatorMetadata);

/// [`ConstantHintedMutator`] is a mutator that mutates the input to a constant
/// in the contract
///
/// We discover that sometimes directly setting the bytes to the constants allow
/// us to increase test coverage.
#[derive(Default)]
pub struct ConstantHintedMutator;

impl Named for ConstantHintedMutator {
    fn name(&self) -> &str {
        "ConstantHintedMutator"
    }
}

impl ConstantHintedMutator {
    pub fn new() -> Self {
        Self
    }
}

impl<I, S> Mutator<I, S> for ConstantHintedMutator
where
    S: State + HasRand + HasMetadata,
    I: Input + HasBytesVec,
{
    /// Mutate the input to a constant in the contract
    /// This always entirely overwrites the input (unless it skips mutation)
    fn mutate(&mut self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<MutationResult, Error> {
        // if full_overwrite_performed is true, we skip mutation
        if let Some(metadata) = state.metadata_map().get::<MutatorMetadata>() {
            if metadata.full_overwrite_performed {
                return Ok(MutationResult::Skipped);
            }
        }

        let idx = state.rand_mut().next() as usize;

        let constant = match state.metadata_map().get::<ConstantPoolMetadata>() {
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
            input_bytes.copy_from_slice(&[vec![0; input_len - constant_len], constant.clone()].concat());
        }

        // prevent fully overwriting the input on this mutation cycle again
        if let Some(metadata) = state.metadata_map_mut().get_mut::<MutatorMetadata>() {
            metadata.set_full_overwrite_performed(true);
        } else {
            let mut metadata = MutatorMetadata::new();
            metadata.set_full_overwrite_performed(true);
            state.metadata_map_mut().insert(metadata);
        }

        Ok(MutationResult::Mutated)
    }
}

/// [`VMStateHintedMutator`] is a mutator that mutates the input to a value in
/// the VM state
///
/// Similar to [`ConstantHintedMutator`], we discover that sometimes directly
/// setting the bytes to the values in the VM state allow us to increase test
/// coverage.
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
pub fn mutate_with_vm_slot<S: State + HasRand>(vm_slots: &HashMap<EVMU256, EVMU256>, state: &mut S) -> EVMU256 {
    // sample a key from the vm_state.state
    let idx = state.rand_mut().below(vm_slots.len() as u64) as usize;
    let key = vm_slots.keys().nth(idx).unwrap();
    if state.rand_mut().below(100) < 90 {
        let value = vm_slots.get(key).unwrap();
        *value
    } else {
        *key
    }
}

impl<'a, I, S> Mutator<I, S> for VMStateHintedMutator<'a>
where
    S: State + HasRand + HasMetadata,
    I: Input + HasBytesVec,
{
    /// Mutate the input to a value in the VM state
    /// This always entirely overwrites the input (unless it skips mutation)
    fn mutate(&mut self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<MutationResult, Error> {
        // if full_overwrite_performed is true, we skip mutation
        if let Some(metadata) = state.metadata_map().get::<MutatorMetadata>() {
            if metadata.full_overwrite_performed {
                return Ok(MutationResult::Skipped);
            }
        }

        let input_len = input.bytes().len();
        if input_len < 8 {
            return Ok(MutationResult::Skipped);
        }
        let new_val = mutate_with_vm_slot(self.vm_slots, state);

        let data: [u8; 32] = new_val.to_be_bytes();

        input.bytes_mut().copy_from_slice(&data[(32 - input_len)..]);

        // prevent fully overwriting the input on this mutation cycle again
        if let Some(metadata) = state.metadata_map_mut().get_mut::<MutatorMetadata>() {
            metadata.set_full_overwrite_performed(true);
        } else {
            let mut metadata = MutatorMetadata::new();
            metadata.set_full_overwrite_performed(true);
            state.metadata_map_mut().insert(metadata);
        }
        Ok(MutationResult::Mutated)
    }
}

/// Mutator that mutates the `CONSTANT SIZE` input bytes (e.g., uint256) in
/// various ways provided by [`libafl::mutators`]. It also uses the
/// [`ConstantHintedMutator`] and [`VMStateHintedMutator`]
pub fn byte_mutator<I, S>(state: &mut S, input: &mut I, vm_slots: Option<HashMap<EVMU256, EVMU256>>) -> MutationResult
where
    S: State + HasRand + HasMetadata,
    I: HasBytesVec + Input,
{
    let mutations = tuple_list!(
        BitFlipMutator::new(),
        ByteInterestingMutator::new(),
        WordInterestingMutator::new(),
        DwordInterestingMutator::new(),
        ConstantHintedMutator::new(),
    );

    if !state.has_metadata::<MutatorMetadata>() {
        state.metadata_map_mut().insert(MutatorMetadata::default());
    }

    let mut res = MutationResult::Skipped;
    if let Some(vm_slots) = vm_slots {
        let mut mutator = StdScheduledMutator::new((VMStateHintedMutator::new(&vm_slots), mutations));
        res = mutator.mutate(state, input, 0).unwrap()
    } else {
        let mut mutator = StdScheduledMutator::new(mutations);
        res = mutator.mutate(state, input, 0).unwrap()
    }

    state
        .metadata_map_mut()
        .get_mut::<MutatorMetadata>()
        .unwrap()
        .set_full_overwrite_performed(false);

    res
}

/// Mutator that mutates the `VARIABLE SIZE` input bytes (e.g., string) in
/// various ways provided by [`libafl::mutators`]. It also uses the
/// [`ConstantHintedMutator`] and [`VMStateHintedMutator`]
pub fn byte_mutator_with_expansion<I, S>(
    state: &mut S,
    input: &mut I,
    vm_slots: Option<HashMap<EVMU256, EVMU256>>,
) -> MutationResult
where
    S: State + HasRand + HasMaxSize + HasMetadata,
    I: HasBytesVec + Input,
{
    let mutations = tuple_list!(
        BitFlipMutator::new(),
        ByteInterestingMutator::new(),
        WordInterestingMutator::new(),
        DwordInterestingMutator::new(),
        BytesExpandMutator::new(),
        BytesInsertMutator::new(),
        ConstantHintedMutator::new(),
    );

    if !state.has_metadata::<MutatorMetadata>() {
        state.metadata_map_mut().insert(MutatorMetadata::default());
    }

    let mut res = MutationResult::Skipped;
    if let Some(vm_slots) = vm_slots {
        let mut mutator = StdScheduledMutator::new((VMStateHintedMutator::new(&vm_slots), mutations));
        res = mutator.mutate(state, input, 0).unwrap();
    } else {
        let mut mutator = StdScheduledMutator::new(mutations);
        res = mutator.mutate(state, input, 0).unwrap();
    }
    state
        .metadata_map_mut()
        .get_mut::<MutatorMetadata>()
        .unwrap()
        .set_full_overwrite_performed(false);
    res
}
