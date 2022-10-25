use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Deserializer, Serialize};

// how can we deserialize this trait?
pub trait ABI: CloneABI {
    fn to_bytes(&self) -> &Bytes;
}

trait CloneABI {
    fn clone_box(&self) -> Box<dyn ABI>;
}

impl<T> CloneABI for T
where
    T: ABI + Clone + 'static,
{
    fn clone_box(&self) -> Box<dyn ABI> {
        Box::new(self.clone())
    }
}

// Use BoxedABI so that downstream code knows the size of the trait object
// However, Box makes deserilization difficult
pub type BoxedABI = Box<dyn ABI>;

// TODO: this does not work, need to figure out how to serialize/deserialize trait objects
impl Serialize for BoxedABI {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = BytesMut::with_capacity(self.to_bytes().len());
        bytes.put(&**self.to_bytes());
        serializer.serialize_bytes(&bytes)
    }
}

// TODO: implement Deserialize for BoxedABI

impl Clone for BoxedABI {
    fn clone(&self) -> BoxedABI {
        self.clone_box()
    }
}

// 0~256-bit data types
#[derive(Clone)]
pub struct A256 {
    data: [u8; 32],
    data_len: usize,
}

#[derive(Clone)]
pub struct AFixedArray {
    data: Vec<BoxedABI>,
    data_len: usize,
    dynamic: bool,
}

#[derive(Clone)]
pub struct AArray {
    data: Vec<BoxedABI>,
    data_len: usize,
}

impl ABI for A256 {
    fn to_bytes(&self) -> &Bytes {
        return &Bytes::from(&self.data[..self.data_len]);
    }
}

impl ABI for AFixedArray {
    fn to_bytes(&self) -> &Bytes {
        let mut ret = BytesMut::new();
        for i in 0..self.data_len {
            ret.extend_from_slice((*self.data[i]).to_bytes());
        }
        return &ret.copy_to_bytes(ret.len());
    }
}

impl ABI for AArray {
    fn to_bytes(&self) -> &Bytes {
        todo!()
    }
}
