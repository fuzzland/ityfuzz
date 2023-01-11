use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

// how can we deserialize this trait?
pub trait ABI: CloneABI + serde_traitobject::Serialize + serde_traitobject::Deserialize{
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
#[derive(Serialize, Deserialize, Clone)]
pub struct BoxedABI {
    #[serde(with = "serde_traitobject")]
    b: Box<dyn ABI>
}

impl BoxedABI {
    pub fn new(b: Box<dyn ABI>) -> Self {
        Self { b }
    }

    pub fn get(&self) -> &Box<dyn ABI> {
        &self.b
    }
}

impl Clone for Box<dyn ABI> {
    fn clone(&self) ->  Box<dyn ABI> {
        self.clone_box()
    }
}

// 0~256-bit data types
#[derive(Clone, Serialize, Deserialize)]
pub struct A256 {
    data: [u8; 32],
    data_len: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AFixedArray {
    data: Vec<BoxedABI>,
    data_len: usize,
    dynamic: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AArray {
    data: Vec<BoxedABI>,
    data_len: usize,
}

// FIXME: fix scope
impl ABI for A256 {
    fn to_bytes(&self) -> &Bytes {
        return &Bytes::from(&self.data[..self.data_len]);
    }
}

// FIXME: fix scope
impl ABI for AFixedArray {
    fn to_bytes(&self) -> &Bytes {
        let mut ret = BytesMut::new();
        for i in 0..self.data_len {
            ret.extend_from_slice(self.data[i].b.to_bytes());
        }
        return &ret.copy_to_bytes(ret.len());
    }
}

impl ABI for AArray {
    fn to_bytes(&self) -> &Bytes {
        todo!()
    }
}

// test serialization and deserialization
#[test]
fn test_abi() {
    let a = A256 {
        data: [0; 32],
        data_len: 32,
    };
    let c = serde_json::to_string(&a).unwrap();
    println!("{}", c);
}
