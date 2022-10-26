use bytes::{Buf, BufMut, Bytes, BytesMut};
use libafl::prelude::Prepend;
use serde::{Deserialize, Serialize};

// how can we deserialize this trait?
pub trait ABI: CloneABI + serde_traitobject::Serialize + serde_traitobject::Deserialize {
    fn set_bytes(&mut self);
    fn is_static(&self) -> bool;
    fn get_bytes(&self) -> &Bytes;
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
    b: Box<dyn ABI>,
}

impl BoxedABI {
    pub fn new(b: Box<dyn ABI>) -> Self {
        Self { b }
    }

    pub fn get(&self) -> &Box<dyn ABI> {
        &self.b
    }

    pub fn get_bytes(&self) -> &Bytes {
        self.b.get_bytes()
    }

    pub fn is_static(&self) -> bool {
        self.b.is_static()
    }
}

impl Clone for Box<dyn ABI> {
    fn clone(&self) -> Box<dyn ABI> {
        self.clone_box()
    }
}

// 0~256-bit data types
#[derive(Clone, Serialize, Deserialize)]
pub struct A256 {
    data: [u8; 32],
    // data len is a constant after initialization
    data_len: usize,
    pub bytes: Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ADynamic {
    data: Vec<u8>,
    multiplier: usize,
    pub bytes: Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AArray {
    data: Vec<BoxedABI>,
    dynamic_size: bool,
    pub bytes: Bytes,
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
            let ptr = self.bytes.as_mut_ptr();
            ptr = ptr.add(32 - self.data_len);
            for i in 0..self.data_len {
                *ptr.add(i) = self.data[i];
            }
        }
    }

    fn is_static(&self) -> bool {
        true
    }

    fn get_bytes(&self) -> &Bytes {
        &self.bytes
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

    fn is_static(&self) -> bool {
        false
    }

    fn get_bytes(&self) -> &Bytes {
        &self.bytes
    }
}

impl ABI for AArray {
    fn set_bytes(&mut self) {
        let mut tails: Vec<&Bytes> = Vec::new();
        let mut tails_offset: Vec<usize> = Vec::new();
        let mut head: Vec<&Bytes> = Vec::new();
        let mut head_data: Vec<&Bytes> = Vec::new();
        let mut head_size: usize = 0;
        let dummy_bytes = Bytes::new();
        for i in 0..self.data.len() {
            if self.data[i].is_static() {
                let encoded = self.data[i].get_bytes();
                head.push(encoded);
                tails.push(&dummy_bytes);
                head_size += encoded.len();
            } else {
                tails.push(self.data[i].get_bytes());
                head.push(&dummy_bytes);
                head_size += 32;
            }
        }
        let mut content_size: usize = 0;
        tails_offset.push(0);
        if tails.len() > 0 {
            for i in 0..tails.len() - 1 {
                content_size += tails[i].len();
                tails_offset.push(content_size);
            }
            for i in 0..tails_offset.len() {
                if head[i].len() == 0 {
                    head_data.push(&Bytes::from(vec![0; 32]));
                    set_size(head_data[i].as_mut_ptr(), tails_offset[i] + head_size);
                } else {
                    head_data.push(head[i]);
                }
            }
        }
        let mut bytes = Bytes::from(vec![
            0;
            head_data.into_iter().map(|x| x.len()).sum::<usize>()
                + tails.into_iter().map(|x| x.len()).sum::<usize>()
                + if self.dynamic_size { 32 } else { 0 }
        ]);

        if self.dynamic_size {
            set_size(bytes.as_mut_ptr(), self.data.len());
        }
        let mut offset: usize = if self.dynamic_size { 32 } else { 0 };
        for i in 0..head_data.len() {
            bytes[offset..offset + head_data[i].len()].copy_from_slice(head_data[i]);
            offset += head_data[i].len();
        }
        for i in 0..tails.len() {
            bytes[offset..offset + tails[i].len()].copy_from_slice(tails[i]);
            offset += tails[i].len();
        }
        self.bytes = bytes;
    }

    fn is_static(&self) -> bool {
        if self.dynamic_size {
            false
        } else {
            self.data.iter().all(|x| x.is_static())
        }
    }

    fn get_bytes(&self) -> &Bytes {
        &self.bytes
    }
}

pub fn get_abi_type(abi_name: &String) -> Box<dyn ABI> {
    let abi_name_str = abi_name.as_str();
    if abi_name_str.starts_with("uint") {
        let len = abi_name_str[4..].parse::<usize>().unwrap();
        get_abi_type_basic("uint", len)
    }
    if abi_name_str.starts_with("int") {
        let len = abi_name_str[3..].parse::<usize>().unwrap();
        get_abi_type_basic("int", len)
    }
    if abi_name_str.starts_with("bytes") {
        let len = abi_name_str[5..].parse::<usize>().unwrap();
        get_abi_type_basic("bytes", len)
    }
    // tuple
    if abi_name_str.starts_with("(") && abi_name_str.ends_with(")") {
        Box::new(AArray {
            data: abi_name_str[1..abi_name_str.len() - 1]
                .split(",")
                .map(|x| get_abi_type(&String::from(x)))
                .collect(),
            dynamic_size: false,
            bytes: Bytes::new(),
        })
    }
    if abi_name_str.ends_with("[]") {
        Box::new(AArray {
            data: vec![BoxedABI{
                b: get_abi_type(&String::from(abi_name_str[..abi_name_str.len() - 2]))
            }; 1],
            dynamic_size: true,
            bytes: Bytes::new(),
        })
    } else if abi_name_str.ends_with("]") && abi_name_str.contains("[") {
        let mut split = abi_name_str.split('[' as u8);
        let name = split.next().unwrap();
        let len = split.next().unwrap().trim_end_matches(']').parse::<usize>().unwrap();
        Box::new(AArray {
            data: vec![BoxedABI{
                b: get_abi_type(&String::from(name))
            }; len],
            dynamic_size: false,
            bytes: Bytes::new(),
        })
    }
    get_abi_type_basic(abi_name.as_str(), 0);
    panic!("not implemented");
}

fn get_abi_type_basic(abi_name: &str, abi_bs: usize) -> Box<dyn ABI> {
    match abi_name {
        "uint" | "int" => Box::new(
            A256 {
                data: [0; 32],
                data_len: abi_bs,
                bytes: Bytes::new(),
            }
        ),
        "address" => Box::new(
            A256 {
                data: [0; 32],
                data_len: 20,
                bytes: Bytes::new(),
            }
        ),
        "bool" => Box::new(
            A256 {
                data: [0; 32],
                data_len: 1,
                bytes: Bytes::new(),
            }
        ),
        "bytes" => Box::new(
            ADynamic {
                data: Vec::new(),
                multiplier: 32,
                bytes: Bytes::new(),
            }
        ),
        "string" => Box::new(
            ADynamic {
                data: Vec::new(),
                multiplier: 32,
                bytes: Bytes::new(),
            }
        ),
        _ => panic!("unsupported abi type"),
    }

}

// test serialization and deserialization
#[test]
fn test_abi() {}
