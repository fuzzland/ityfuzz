/// Common generic types for EVM fuzzing
use crate::evm::input::EVMInput;
use crate::evm::mutator::FuzzMutator;
use crate::evm::vm::EVMState;

use crate::oracle::OracleCtx;
use crate::scheduler::SortedDroppingScheduler;
use crate::state::{FuzzState, InfantStateState};
use crate::state_input::StagedVMState;
use bytes::Bytes;
use libafl::prelude::{HasRand, RomuDuoJrRand};
use primitive_types::{H160, H256, U256, U512};
use revm::Bytecode;
use libafl::prelude::Rand;
pub type EVMAddress = H160;
pub type EVMU256 = U256;

pub type EVMFuzzState = FuzzState<EVMInput, EVMState, EVMAddress, EVMAddress, Vec<u8>>;
pub type EVMOracleCtx<'a> =
    OracleCtx<'a, EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState>;

pub type EVMFuzzMutator<'a> = FuzzMutator<
    'a,
    EVMState,
    EVMAddress,
    EVMAddress,
    SortedDroppingScheduler<
        StagedVMState<EVMAddress, EVMAddress, EVMState>,
        InfantStateState<EVMAddress, EVMAddress, EVMState>,
    >,
>;

pub type EVMInfantStateState = InfantStateState<EVMAddress, EVMAddress, EVMState>;

pub type EVMStagedVMState = StagedVMState<EVMAddress, EVMAddress, EVMState>;


/// convert array of 20x u8 to H160
pub fn convert_H160(v: [u8; 20]) -> H160 {
    return v.into();
}

/// convert U256 to H160 by taking the last 20 bytes
pub fn convert_u256_to_h160(v: U256) -> H160 {
    let mut temp = H256::zero();
    unsafe { v.to_big_endian(temp.as_bytes_mut()) };
    temp.into()
}

/// multiply a float by 10^decimals and convert to U512
pub fn float_scale_to_u512(v: f64, decimals: u32) -> U512 {
    // todo(@shou) make this sound
    let mut temp = v;
    for _ in 0..decimals {
        temp *= 10.0;
    }
    return U512::from(temp as u64);
}

/// Generate a random H160 address.
pub fn generate_random_address<S>(s: &mut S) -> H160 where S: HasRand{
    let mut rand_seed: RomuDuoJrRand = RomuDuoJrRand::with_seed(s.rand_mut().next());
    let mut address = H160::random_using(&mut rand_seed);
    address
}

/// Generate a fixed H160 address from a hex string.
pub fn fixed_address(s: &str) -> H160 {
    let mut address = H160::zero();
    address.0.copy_from_slice(&hex::decode(s).unwrap());
    address
}
