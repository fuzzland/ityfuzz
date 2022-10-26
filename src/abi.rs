use bytes::{Buf, BufMut, Bytes, BytesMut};
use libafl::prelude::Prepend;
use serde::{Deserialize, Serialize};

// how can we deserialize this trait?
pub trait ABI: CloneABI + serde_traitobject::Serialize + serde_traitobject::Deserialize{
    fn set_bytes(&mut self);
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
    bytes: Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ADynamic {
    data: Vec<u8>,
    multiplier: usize,
    bytes: Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AFixedArray {
    data: Vec<BoxedABI>,
    data_len: usize,
    dynamic: bool,
    bytes: Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AArray {
    data: Vec<BoxedABI>,
    data_len: usize,
    bytes: Bytes,
}

// FIXME: fix scope
fn pad_bytes(bytes: &mut Bytes, len: usize) {
    let padding = len - bytes.len();
    if padding > 0 {
        bytes.prepend(vec![0; padding].as_slice());
    }
}

impl ABI for A256 {
    fn set_bytes(&mut self) {
        unsafe {
            let mut counter = 0;
            let ptr = self.bytes.as_mut_ptr();
            loop {
                *ptr = if self.data_len < (32 - counter) { 0 } else {
                    self.data[counter - (32 - self.data_len)]
                };
                counter += 1;
                if counter == 32 { break }
                ptr = ptr.add(1);
            }
        }
    }
}

fn roundup(x: usize, multiplier: usize) -> usize {
    (x + multiplier - 1) / multiplier * multiplier
}

fn set_size(bytes: *mut u8, len: usize) {
    let mut rem: usize = len;
    unsafe {
        for i in 0..32 {
            *bytes.add(31 - i) = (rem & 0xff) as u8;
            rem >>= 8;
        }
    }
}

impl ABI for ADynamic {
    fn set_bytes(&mut self) {
        unsafe {
            let new_len: usize = roundup(self.data.len(), self.multiplier);
            self.bytes = Bytes::from(vec![0; new_len + 32]);
            let ptr = self.bytes.as_mut_ptr();
            set_size(ptr, self.data.len());
            // set data
            for i in 0..self.data.len() {
                *ptr.add(i + 32) = self.data[i];
            }
        }
    }
}

// FIXME: fix scope
impl ABI for AFixedArray {
    fn set_bytes(&mut self) {
        todo!()
    }
}

impl ABI for AArray {
    fn set_bytes(&mut self) {
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
