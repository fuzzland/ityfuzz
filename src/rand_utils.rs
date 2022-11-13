use primitive_types::H160;
use rand::thread_rng;
use rand::Rng;

pub fn generate_random_address() -> H160 {
    let mut rng = thread_rng();
    let mut address = H160::zero();
    rng.fill(&mut address.0);
    address
}

pub fn fixed_address(s: &str) -> H160 {
    let mut address = H160::zero();
    address.0.copy_from_slice(&hex::decode(s).unwrap());
    address
}
