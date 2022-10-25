use bytes::Bytes;

pub trait ABI {
    fn to_bytes(&self) -> &Bytes;
}

// 0~256-bit data types
pub struct A256 {
    data: [u8; 32],
    data_len: usize,
}

pub struct AFixedArray {
    data: Vec<dyn ABI>,
    data_len: usize,
    dynamic: bool,
}


pub struct AArray {
    data: Vec<dyn ABI>,
    data_len: usize,
}

impl ABI for A256 {
    fn to_bytes(&self) -> &Bytes {
        return &Bytes::from(&self.data[..self.data_len]);
    }
}

impl ABI for AFixedArray {
    fn to_bytes(&self) -> &Bytes {
        let mut ret = Bytes::new();
        for i in 0..self.data_len {
            ret.extend_from_slice(self.data[i].to_bytes());
        }
        return &ret;
    }
}

impl ABI for AArray {
    fn to_bytes(&self) -> &Bytes {
        todo!()
    }
}

