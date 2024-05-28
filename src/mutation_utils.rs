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

use crate::{evm::types::EVMU256, r#const::MAX_STACK_POW};

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

/// Metadata for Mutations
///
/// This is metadata attached to the global fuzz state
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MutatorMetadata {
    /// Used to prevent more than one full overwrite during mutation
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

/// [`GaussianNoiseMutator`] is a mutator that adds Gaussian noise to the input
/// value.
///
/// This mutator scales the input by a factor derived from a Gaussian
/// distribution, with varying ranges based on randomly chosen percentages. The
/// goal is to mutate the input within a general range of itself, independent of
/// its potential size.
///
/// The Gaussian mutator will modify the input to be anywhere in the space of
/// `input +- {10%, 25%, 50%, 100%, 200%, ..., 1000%}`. For example, a uint256
/// of 10,000 can be mutated to become somewhere between 7,500-12,500 if the 25%
/// multiplier is chosen. These percentages were chosen to be able to both focus
/// close to the input value but also be able to explore the space around it
/// aggressively.
///
/// This probably isn't useful for signed integers, since the bytes
/// representation is treated as a uint and negative values will always be
/// scaled according to the max size.
///
/// It clamps the mutated value between 0 and the maximum value for the size of
/// the input.
#[derive(Default)]
pub struct GaussianNoiseMutator;

impl Named for GaussianNoiseMutator {
    fn name(&self) -> &str {
        "GaussianNoiseMutator"
    }
}

impl GaussianNoiseMutator {
    pub fn new() -> Self {
        Self
    }
}

impl<I, S> Mutator<I, S> for GaussianNoiseMutator
where
    S: State + HasRand + HasMetadata,
    I: Input + HasBytesVec,
{
    /// Mutate the input by adding Gaussian noise to the entire input value.
    ///
    /// The mutation process involves:
    /// 1. Selecting a multiplier from a predefined set of percentages that act
    ///    as the standard deviation to the distribution.
    /// 2. Generating a scaling factor based on the chosen multiplier and a
    ///    Gaussian distribution.
    /// 3. Scaling the input bytes by the calculated factor, with special
    ///    handling for overflow and underflow.
    ///
    /// # Parameters
    /// - `state`: The current state, which provides randomness.
    /// - `input`: The input to be mutated.
    /// - `_stage_idx`: The stage index (unused in this implementation).
    ///
    /// # Returns
    /// - `Ok(MutationResult::Mutated)` if the input was successfully mutated.
    /// - `Ok(MutationResult::Skipped)` if the mutation was skipped.
    /// - `Err(Error)` if an error occurred during mutation.
    fn mutate(&mut self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<MutationResult, Error> {
        // A gaussian distribution takes a mean and a standard deviation to define a
        // curve. A value chosen within +-3 standard deviations is ~99.7% likely
        // We are going to define a curve where the values at the +-3std mark are chosen
        // according to the input scaled by a multiplier.
        let three_sigma_multipliers = [0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0]; // These 3rd_sigma values are +10%, 25%, 50%, etc of the original value
        let sigma_index = state.rand_mut().below(three_sigma_multipliers.len() as u64) as usize;
        let chosen_3rd_sigma = three_sigma_multipliers[sigma_index];
        let mut scale_factor = {
            let num_samples = 8; // 8 is chosen to be performant and still provide a reasonable distribution
            let mut sum = 0.0;

            // Generate uniformly distributed random variables and sum them up
            for _ in 0..num_samples {
                sum += state.rand_mut().next() as f64 / u64::MAX as f64;
            }

            // Normalize the sum to approximate a standard normal distribution
            let standard_normal = (sum - (num_samples as f64 / 2.0));
            chosen_3rd_sigma / 3.0 * standard_normal // Adjust 3rd sigma to std,
                                                     // then mul by normal. this
                                                     // is expected to be in
                                                     // range of -num_samples*
                                                     // 3sigma/2 to
                                                     // +num_samples*3sigma/2,
                                                     // centered at 0.
        };
        scale_factor += 1.0; // we are scaling our input by scale_factor, so re-centering to 1.0 means we
                             // multiply by 1.0 in most common case

        if scale_factor < 0.0 {
            // anything lower than 0.0 makes all bytes 0. do so and return Mutated
            // This is a common result, since the range is centered around 1.0 and is often
            // able to reach abs values of ~3-4.
            let input_bytes = input.bytes_mut();
            input_bytes.iter_mut().for_each(|byte| *byte = 0);
            return Ok(MutationResult::Mutated);
        }

        if (scale_factor - 1.0).abs() < f64::EPSILON {
            // The scale factor is within f64 err range of 1.0
            // Skip mutation
            return Ok(MutationResult::Skipped);
        } else {
            // iterate in normal order byte by byte, if underflow, set all to 0.
            let input_bytes = input.bytes_mut();
            let mut carry_down = 0.0;
            let mut carry_up = 0.0;

            // The loop is complicated because the input can be arbitrarily sized.
            // This handles scaling a Vec<u8> that represents a number of arbitrary size.
            'arbitrary_sized_scaling_loop: for i in 0..input_bytes.len() {
                // convert u8 to f64, add any carry scaled by 256, and scale by scale_factor
                let scaled_value = (input_bytes[i] as f64 + carry_down * 256.0) * scale_factor;

                // find divided value and carry
                input_bytes[i] = (scaled_value % 256.0).floor() as u8;
                // special condition: if i is 0, and scaled_value is >=256, we overflowed our
                // input. set all bytes to 255 and break all loops. this gets max_clamped
                if i == 0 && scaled_value >= 256.0 {
                    input_bytes.iter_mut().for_each(|byte| *byte = 255);
                    break 'arbitrary_sized_scaling_loop;
                }
                // for example: if a byte gets mutated from 200 to 260.8, we need to carry up
                // the overflow to the prior byte and carry down the decimal to the next byte
                carry_up = (scaled_value / 256.0).floor();
                carry_down = (scaled_value % 1.0) / scale_factor;

                // Propagate carry up if necessary
                let mut j = i;
                while carry_up > 0.0 && j > 0 {
                    j -= 1;
                    let new_value = input_bytes[j] as f64 + carry_up;
                    // special condition: if j is 0, and new_value is >=256, set all bytes to 255
                    // and break all loops. this value overflowed and gets max_clamped
                    if j == 0 && new_value >= 256.0 {
                        input_bytes.iter_mut().for_each(|byte| *byte = 255);
                        break 'arbitrary_sized_scaling_loop;
                    }

                    input_bytes[j] = (new_value % 256.0).floor() as u8;
                    carry_up = (new_value / 256.0).floor();
                }
            }
        }

        Ok(MutationResult::Mutated)
    }
}

/// [`IncDecValue`] is a mutator that mutates the input by overflowing_add 1 or
/// overflowing_sub 1
///
/// When paired with [`ConstantHintedMutator`], it allows us to increase test
/// coverage by passing `<input> <CONSTANT> gt` and `<input> <CONSTANT> lt` in
/// the contract
#[derive(Default)]
pub struct IncDecValue;

impl Named for IncDecValue {
    fn name(&self) -> &str {
        "IncDecValue"
    }
}

impl IncDecValue {
    pub fn new() -> Self {
        Self
    }
}

impl<I, S> Mutator<I, S> for IncDecValue
where
    S: State + HasRand + HasMetadata,
    I: Input + HasBytesVec,
{
    /// Mutate the input by adding 1 to the last byte, with carry propagation
    fn mutate(&mut self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<MutationResult, Error> {
        let input_bytes = input.bytes_mut();
        match state.rand_mut().below(2) {
            0 => {
                // increment input by 1
                let mut carry = true;
                for byte in input_bytes.iter_mut().rev() {
                    if carry {
                        let (new_byte, new_carry) = byte.overflowing_add(1);
                        *byte = new_byte;
                        carry = new_carry;
                    } else {
                        break;
                    }
                }
                Ok(MutationResult::Mutated)
            }
            1 => {
                // decrement input by 1
                let mut borrow = true;
                for byte in input_bytes.iter_mut().rev() {
                    if borrow {
                        let (new_byte, new_borrow) = byte.overflowing_sub(1);
                        *byte = new_byte;
                        borrow = new_borrow;
                    } else {
                        break;
                    }
                }
                Ok(MutationResult::Mutated)
            }
            _ => {
                // Should be unreachable. If here, rand.below didn't work as expected.
                // unreachable!()
                Ok(MutationResult::Skipped)
            }
        }
    }
}

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
        GaussianNoiseMutator::new(),
        IncDecValue::new(),
    );

    if !state.has_metadata::<MutatorMetadata>() {
        state.metadata_map_mut().insert(MutatorMetadata::default());
    }

    let mut res = MutationResult::Skipped;
    if let Some(vm_slots) = vm_slots {
        let mut mutator = StdScheduledMutator::with_max_stack_pow(
            (VMStateHintedMutator::new(&vm_slots), mutations),
            MAX_STACK_POW as u64,
        );
        res = mutator.mutate(state, input, 0).unwrap()
    } else {
        let mut mutator = StdScheduledMutator::with_max_stack_pow(mutations, MAX_STACK_POW as u64);
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
        BytesRandInsertMutator::new(),
        ConstantHintedMutator::new(),
        GaussianNoiseMutator::new(),
        IncDecValue::new(),
    );

    if !state.has_metadata::<MutatorMetadata>() {
        state.metadata_map_mut().insert(MutatorMetadata::default());
    }

    let mut res = MutationResult::Skipped;
    if let Some(vm_slots) = vm_slots {
        let mut mutator = StdScheduledMutator::with_max_stack_pow(
            (VMStateHintedMutator::new(&vm_slots), mutations),
            MAX_STACK_POW as u64,
        );
        res = mutator.mutate(state, input, 0).unwrap();
    } else {
        let mut mutator = StdScheduledMutator::with_max_stack_pow(mutations, MAX_STACK_POW as u64);
        res = mutator.mutate(state, input, 0).unwrap();
    }

    state
        .metadata_map_mut()
        .get_mut::<MutatorMetadata>()
        .unwrap()
        .set_full_overwrite_performed(false);
    res
}
