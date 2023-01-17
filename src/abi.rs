use std::any::Any;
use std::fmt::Debug;
use std::ops::DerefMut;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use libafl::inputs::{HasBytesVec, Input};
use libafl::mutators::{MutationResult, MutatorsTuple};
use libafl::prelude::{tuple_list, BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator, ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator, BytesExpandMutator, BytesInsertMutator, BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator, BytesSwapMutator, DwordAddMutator, DwordInterestingMutator, HasConstLen, Mutator, Prepend, QwordAddMutator, WordAddMutator, WordInterestingMutator, };
use libafl::state::{HasMaxSize, HasRand, State};
use rand::random;
use serde::{Deserialize, Serialize};
use crate::abi::ABILossyType::{T256, TArray, TDynamic};
use crate::mutation_utils::{byte_mutator, byte_mutator_with_expansion};


pub enum ABILossyType {
    T256,
    TArray,
    TDynamic,
}

// how can we deserialize this trait?
pub trait ABI: CloneABI + serde_traitobject::Serialize + serde_traitobject::Deserialize {
    fn is_static(&self) -> bool;
    fn get_bytes(&self) -> Vec<u8>;
    fn get_type(&self) -> ABILossyType;
    fn as_any(&mut self) -> &mut dyn Any;
}

impl Debug for dyn ABI {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ABI")
            .field("is_static", &self.is_static())
            .field("get_bytes", &self.get_bytes())
            .finish()
    }
}

pub trait CloneABI {
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
#[derive(Serialize, Deserialize, Clone, Debug)]
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

    pub fn get_mut(&mut self) -> &mut Box<dyn ABI> {
        &mut self.b
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

    pub fn get_type(&self) -> ABILossyType {
        self.b.get_type()
    }
}

impl BoxedABI {
    pub fn mutate<S>(&mut self, state: &mut S) -> MutationResult
        where
            S: State + HasRand + HasMaxSize
    {
        match self.get_type() {
            T256 => {
                let v = self.b.deref_mut().as_any();
                let a256 = v.downcast_mut::<A256>().unwrap();
                // self.b.downcast_ref::<A256>().unwrap().mutate(state);
                byte_mutator(state, a256)
            }
            TDynamic => {
                let adyn = self.b.deref_mut().as_any().downcast_mut::<ADynamic>().unwrap();
                // self.b.downcast_ref::<A256>().unwrap().mutate(state);
                byte_mutator_with_expansion(state, adyn)
            }
            TArray => {
                let aarray = self.b.deref_mut().as_any().downcast_mut::<AArray>().unwrap();

                let data_len = aarray.data.len();
                if data_len == 0 {
                    return MutationResult::Skipped;
                }
                if aarray.dynamic_size {
                    if (random::<u8>() % 2) == 0 {
                        let index: usize = random::<usize>() % data_len;
                        let mut result = aarray.data[index].mutate(state);
                        return result;
                    }

                    // increase size
                    // let base_type = &;
                    for _ in 0..random::<usize>() % state.max_size() {
                        aarray.data.push(aarray.data[0].clone());
                    }

                } else {
                    let mut index: usize = random::<usize>() % data_len;
                    return aarray.data[index].mutate(state);
                }
                MutationResult::Mutated
            }
        }
    }
}

impl Clone for Box<dyn ABI> {
    fn clone(&self) -> Box<dyn ABI> {
        self.clone_box()
    }
}

// 0~256-bit data types
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct A256 {
    data: Vec<u8>,
}

impl Input for A256 {
    fn generate_name(&self, idx: usize) -> String {
        format!("A256_{}", idx)
    }
}

impl HasBytesVec for A256 {
    fn bytes(&self) -> &[u8] {
        self.data.as_slice()
    }

    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        self.data.as_mut()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ADynamic {
    data: Vec<u8>,
    multiplier: usize,
}

impl Input for ADynamic {
    fn generate_name(&self, idx: usize) -> String {
        format!("ADynamic_{}", idx)
    }
}

impl HasBytesVec for ADynamic {
    fn bytes(&self) -> &[u8] {
        self.data.as_slice()
    }

    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        self.data.as_mut()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AArray {
    pub(crate) data: Vec<BoxedABI>,
    pub(crate) dynamic_size: bool,
}

impl Input for AArray {
    fn generate_name(&self, idx: usize) -> String {
        format!("AArray_{}", idx)
    }
}

impl ABI for A256 {
    fn is_static(&self) -> bool {
        true
    }

    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0; 32];
        let data_len = self.data.len();
        unsafe {
            let mut ptr = bytes.as_mut_ptr();
            ptr = ptr.add(32 - data_len);
            for i in 0..data_len {
                *ptr.add(i) = self.data[i];
            }
        }
        bytes
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn get_type(&self) -> ABILossyType { T256 }
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

    fn get_type(&self) -> ABILossyType { TDynamic }

    fn as_any(&mut self) -> &mut dyn Any {
        self
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
        let dummy_bytes: Vec<u8> = vec![0; 0];
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
        let mut head_data_size: usize = 0;
        let mut tail_data_size: usize = 0;
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
        let mut bytes =
            vec![0; head_data_size + tail_data_size + if self.dynamic_size { 32 } else { 0 }];

        if self.dynamic_size {
            set_size(bytes.as_mut_ptr(), self.data.len());
        }
        let mut offset: usize = if self.dynamic_size { 32 } else { 0 };
        for i in 0..head_data.len() {
            bytes[offset..offset + head_data[i].len()]
                .copy_from_slice(head_data[i].to_vec().as_slice());
            offset += head_data[i].len();
        }
        for i in 0..tails.len() {
            bytes[offset..offset + tails[i].len()].copy_from_slice(tails[i].to_vec().as_slice());
            offset += tails[i].len();
        }
        bytes
    }

    fn get_type(&self) -> ABILossyType { TArray }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

pub fn get_abi_type_boxed(abi_name: &String) -> BoxedABI {
    return BoxedABI {
        b: get_abi_type(abi_name),
    };
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
                    b: get_abi_type(&String::from(x)),
                })
                .collect(),
            dynamic_size: false,
        });
    }
    if abi_name_str.ends_with("[]") {
        return Box::new(AArray {
            data: vec![
                BoxedABI {
                    b: get_abi_type(&abi_name[..abi_name_str.len() - 2].to_string())
                };
                1
            ],
            dynamic_size: true,
        });
    } else if abi_name_str.ends_with("]") && abi_name_str.contains("[") {
        let mut split = abi_name_str.split('[');
        let name = split.next().unwrap();
        let len = split
            .next()
            .unwrap()
            .trim_end_matches(']')
            .parse::<usize>()
            .unwrap();
        return Box::new(AArray {
            data: vec![
                BoxedABI {
                    b: get_abi_type(&String::from(name))
                };
                len
            ],
            dynamic_size: false,
        });
    }
    get_abi_type_basic(abi_name.as_str(), 0)
}

fn get_abi_type_basic(abi_name: &str, abi_bs: usize) -> Box<dyn ABI> {
    match abi_name {
        "uint" | "int" => Box::new(A256 {
            data: vec![0; abi_bs],
        }),
        "address" => Box::new(A256 { data: vec![0; 20] }),
        "bool" => Box::new(A256 { data: vec![0; 1] }),
        "bytes" => Box::new(ADynamic {
            data: Vec::new(),
            multiplier: 32,
        }),
        "string" => Box::new(ADynamic {
            data: Vec::new(),
            multiplier: 32,
        }),
        _ => panic!("unsupported abi type"),
    }
}

// test serialization and deserialization
#[test]
fn test_int() {
    let abi = get_abi_type_boxed(&String::from("int8"));
    abi.get_bytes();
}
