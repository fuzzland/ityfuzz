use primitive_types::{H160, H256, U256, U512};

pub fn convert_H160(v: [u8; 20]) -> H160 {
    return v.into();
}
pub fn convert_u256_to_h160(v: U256) -> H160 {
    let mut temp = H256::zero();
    unsafe { v.to_big_endian(temp.as_bytes_mut()) };
    temp.into()
}

pub fn float_scale_to_u512(v: f64, decimals: u32) -> U512 {
    // todo(@shou) make this sound
    let mut temp = v;
    for _ in 0..decimals {
        temp *= 10.0;
    }
    return U512::from(temp as u64);
}
