/// Utilities for generating random values for different types.

use primitive_types::H160;
use libafl::prelude::{ HasRand, Rand, RomuDuoJrRand};

/// Generate a random H160 address.
pub fn generate_random_address<S>(s: &mut S) -> H160 where S: HasRand{
    let mut rand_seed:RomuDuoJrRand = RomuDuoJrRand::with_seed(s.rand_mut().next());
    let mut address = H160::random_using(&mut rand_seed);
    address
}

/// Generate a fixed H160 address from a hex string.
pub fn fixed_address(s: &str) -> H160 {
    let mut address = H160::zero();
    address.0.copy_from_slice(&hex::decode(s).unwrap());
    address
}
