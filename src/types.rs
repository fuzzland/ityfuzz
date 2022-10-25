use primitive_types::H160;

pub fn convert_H160(v: [u8; 20]) -> H160 {
    return v.into();
}
