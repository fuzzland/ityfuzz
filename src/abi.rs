use bytes::{Buf, BufMut, Bytes, BytesMut};
use libafl::prelude::Prepend;
use serde::{Deserialize, Serialize};

// how can we deserialize this trait?
pub trait ABI: CloneABI + serde_traitobject::Serialize + serde_traitobject::Deserialize {
    fn is_static(&self) -> bool;
    fn get_bytes(&self) -> Vec<u8>;
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

    pub fn get_bytes(&self) -> Bytes {
        Bytes::from(self.b.get_bytes())
    }

    pub fn get_bytes_vec(&self) -> Vec<u8> {
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
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ADynamic {
    data: Vec<u8>,
    multiplier: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AArray {
    data: Vec<BoxedABI>,
    dynamic_size: bool,
}

// FIXME: fix scope
fn pad_bytes(bytes: &mut Bytes, len: usize) {
    let padding = len - bytes.len();
    if padding > 0 {
        bytes.prepend(vec![0; padding].as_slice());
    }
}

impl ABI for A256 {
    fn is_static(&self) -> bool {
        true
    }

    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0; 32];
        unsafe {
            let mut ptr = bytes.as_mut_ptr();
            ptr = ptr.add(32 - self.data_len);
            for i in 0..self.data_len {
                *ptr.add(i) = self.data[i];
            }
        }
        bytes
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
    fn is_static(&self) -> bool {
        false
    }

    fn get_bytes(&self) -> Vec<u8> {
        let new_len: usize = roundup(self.data.len(), self.multiplier);
        let mut bytes = vec![0; new_len + 32];
        unsafe {
            let ptr = bytes.as_mut_ptr();
            set_size(ptr, self.data.len());
            // set data
            for i in 0..self.data.len() {
                *ptr.add(i + 32) = self.data[i];
            }
        }
        bytes
    }

}

impl ABI for AArray {
    fn is_static(&self) -> bool {
        if self.dynamic_size {
            false
        } else {
            self.data.iter().all(|x| x.is_static())
        }
    }

    fn get_bytes(&self) -> Vec<u8> {
        let mut tails: Vec<Vec<u8>> = Vec::new();
        let mut tails_offset: Vec<usize> = Vec::new();
        let mut head: Vec<Vec<u8>> = Vec::new();
        let mut head_data: Vec<Vec<u8>> = Vec::new();
        let mut head_size: usize = 0;
        let dummy_bytes: Vec<u8> = vec![0;0];
        for i in 0..self.data.len() {
            if self.data[i].is_static() {
                let encoded = self.data[i].get_bytes_vec();
                head_size += encoded.len();
                head.push(encoded);
                tails.push(dummy_bytes.clone());
            } else {
                tails.push(self.data[i].get_bytes_vec());
                head.push(dummy_bytes.clone());
                head_size += 32;
            }
        }
        let mut content_size: usize = 0;
        tails_offset.push(0);
        let mut head_data_size:usize = 0;
        let mut tail_data_size:usize = 0;
        if tails.len() > 0 {
            for i in 0..tails.len() - 1 {
                content_size += tails[i].len();
                tails_offset.push(content_size);
            }
            for i in 0..tails_offset.len() {
                if head[i].len() == 0 {
                    head_data.push(vec![0; 32]);
                    head_data_size += 32;
                    set_size(head_data[i].as_mut_ptr(), tails_offset[i] + head_size);
                } else {
                    head_data.push(head[i].clone());
                    head_data_size += head[i].len();
                }
            }
            tail_data_size = content_size + tails[tails.len() - 1].len();
        }
        let mut bytes = vec![
            0;
            head_data_size + tail_data_size
                + if self.dynamic_size { 32 } else { 0 }
        ];

        if self.dynamic_size {
            set_size(bytes.as_mut_ptr(), self.data.len());
        }
        let mut offset: usize = if self.dynamic_size { 32 } else { 0 };
        for i in 0..head_data.len() {
            bytes[offset..offset + head_data[i].len()].copy_from_slice(head_data[i].to_vec().as_slice());
            offset += head_data[i].len();
        }
        for i in 0..tails.len() {
            bytes[offset..offset + tails[i].len()].copy_from_slice(tails[i].to_vec().as_slice());
            offset += tails[i].len();
        }
        bytes
    }
}

pub fn get_abi_type_boxed(abi_name: &String) -> BoxedABI {
    return BoxedABI {
        b: get_abi_type(abi_name),
    }
}

pub fn get_abi_type(abi_name: &String) -> Box<dyn ABI> {
    let abi_name_str = abi_name.as_str();
    if abi_name_str.starts_with("uint") {
        let len = abi_name_str[4..].parse::<usize>().unwrap();
        return get_abi_type_basic("uint", len);
    }
    if abi_name_str.starts_with("int") {
        let len = abi_name_str[3..].parse::<usize>().unwrap();
        return get_abi_type_basic("int", len);
    }
    if abi_name_str.starts_with("bytes") {
        let len = abi_name_str[5..].parse::<usize>().unwrap();
        return get_abi_type_basic("bytes", len);
    }
    // tuple
    if abi_name_str.starts_with("(") && abi_name_str.ends_with(")") {
        return Box::new(AArray {
            data: abi_name_str[1..abi_name_str.len() - 1]
                .split(",")
                .map(|x| BoxedABI {
                    b: get_abi_type(&String::from(x))
                })
                .collect(),
            dynamic_size: false,
        });
    }
    if abi_name_str.ends_with("[]") {
        return Box::new(AArray {
            data: vec![BoxedABI{
                b: get_abi_type(&abi_name[..abi_name_str.len() - 2].to_string())
            }; 1],
            dynamic_size: true,
        });
    } else if abi_name_str.ends_with("]") && abi_name_str.contains("[") {
        let mut split = abi_name_str.split('[');
        let name = split.next().unwrap();
        let len = split.next().unwrap().trim_end_matches(']').parse::<usize>().unwrap();
        return Box::new(AArray {
            data: vec![BoxedABI{
                b: get_abi_type(&String::from(name))
            }; len],
            dynamic_size: false,
        });
    }
    get_abi_type_basic(abi_name.as_str(), 0)
}

fn get_abi_type_basic(abi_name: &str, abi_bs: usize) -> Box<dyn ABI> {
    match abi_name {
        "uint" | "int" => Box::new(
            A256 {
                data: [0; 32],
                data_len: abi_bs,
            }
        ),
        "address" => Box::new(
            A256 {
                data: [0; 32],
                data_len: 20,
            }
        ),
        "bool" => Box::new(
            A256 {
                data: [0; 32],
                data_len: 1,
            }
        ),
        "bytes" => Box::new(
            ADynamic {
                data: Vec::new(),
                multiplier: 32,
            }
        ),
        "string" => Box::new(
            ADynamic {
                data: Vec::new(),
                multiplier: 32,
            }
        ),
        _ => panic!("unsupported abi type"),
    }

}

// test serialization and deserialization
#[test]
fn test_int() {
    let abi = get_abi_type_boxed(&String::from("int8"));
    abi.get_bytes();
}
