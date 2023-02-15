use primitive_types::{H160, H256, U256};

pub fn convert_H160(v: [u8; 20]) -> H160 {
    return v.into();
}
pub fn convert_u256_to_h160(v: U256) -> H160 {
    let mut temp = H256::zero();
    unsafe {
        v.to_big_endian(temp.as_bytes_mut())
    };
    temp.into()
}
