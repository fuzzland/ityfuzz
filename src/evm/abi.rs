use crate::evm::abi::ABILossyType::{TArray, TDynamic, TEmpty, TUnknown, T256};
use crate::evm::mutation_utils::{byte_mutator, byte_mutator_with_expansion};
use crate::evm::vm::abi_max_size;
use crate::generic_vm::vm_state::VMStateT;
use crate::state::{HasCaller, HasItyState};
use bytes::Bytes;
use itertools::Itertools;
use libafl::inputs::{HasBytesVec, Input};
use libafl::mutators::MutationResult;
use libafl::prelude::{Mutator, Rand};
use libafl::state::{HasMaxSize, HasRand, State};
use primitive_types::{H160, U256};
use rand::random;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter, Write};
use std::ops::{Deref, DerefMut};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ABILossyType {
    T256,
    TArray,
    TDynamic,
    TEmpty,
    TUnknown,
}

// how can we deserialize this trait?
pub trait ABI: CloneABI + serde_traitobject::Serialize + serde_traitobject::Deserialize {
    fn is_static(&self) -> bool;
    fn get_bytes(&self) -> Vec<u8>;
    fn get_type(&self) -> ABILossyType;
    fn to_string(&self) -> String;
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
    pub b: Box<dyn ABI>,
    function: [u8; 4],
}

impl BoxedABI {
    pub fn new(b: Box<dyn ABI>) -> Self {
        Self {
            b,
            function: [0; 4],
        }
    }

    pub fn get(&self) -> &Box<dyn ABI> {
        &self.b
    }

    pub fn get_mut(&mut self) -> &mut Box<dyn ABI> {
        &mut self.b
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        [Vec::from(self.function), self.b.get_bytes()].concat()
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

    pub fn set_func(&mut self, function: [u8; 4]) {
        self.function = function;
    }

    pub fn to_string(&self) -> String {
        format!("{}{}\n", hex::encode(self.function), self.b.to_string())
    }
}

fn sample_abi<Loc, Addr, VS, S>(state: &mut S, size: usize) -> BoxedABI
where
    S: State + HasRand + HasItyState<Loc, Addr, VS> + HasMaxSize + HasCaller<H160>,
    VS: VMStateT + Default,
    Loc: Clone + Debug + Serialize + DeserializeOwned,
    Addr: Clone + Debug + Serialize + DeserializeOwned,
{
    // TODO(@shou): use a better sampling strategy
    if size == 32 {
        // sample a static type
        match state.rand_mut().below(100) % 2 {
            0 => BoxedABI::new(Box::new(A256 {
                data: vec![0; 32],
                is_address: false,
            })),
            1 => BoxedABI::new(Box::new(A256 {
                data: state.get_rand_caller().0.into(),
                is_address: true,
            })),
            _ => unreachable!(),
        }
    } else {
        // sample a dynamic type
        let max_size = state.max_size();
        let vec_size = state.rand_mut().below(max_size as u64) as usize;
        match state.rand_mut().below(100) % 4 {
            // dynamic
            0 => BoxedABI::new(Box::new(ADynamic {
                data: vec![state.rand_mut().below(255) as u8; vec_size],
                multiplier: 32,
            })),
            // tuple
            1 => BoxedABI::new(Box::new(AArray {
                data: vec![sample_abi(state, 32); vec_size],
                dynamic_size: false,
            })),
            // array[]
            2 => {
                let abi = sample_abi(state, 32);
                BoxedABI::new(Box::new(AArray {
                    data: vec![abi; vec_size],
                    dynamic_size: false,
                }))
            }
            // array[...]
            3 => {
                let abi = sample_abi(state, 32);
                BoxedABI::new(Box::new(AArray {
                    data: vec![abi; vec_size],
                    dynamic_size: true,
                }))
            }
            _ => unreachable!(),
        }
    }
}

impl BoxedABI {
    pub fn mutate<Loc, Addr, VS, S>(&mut self, state: &mut S) -> MutationResult
    where
        S: State + HasRand + HasMaxSize + HasItyState<Loc, Addr, VS> + HasCaller<H160>,
        VS: VMStateT + Default,
        Loc: Clone + Debug + Serialize + DeserializeOwned,
        Addr: Clone + Debug + Serialize + DeserializeOwned,
    {
        self.mutate_with_vm_slots(state, None)
    }

    pub fn mutate_with_vm_slots<Loc, Addr, VS, S>(
        &mut self,
        state: &mut S,
        vm_slots: Option<HashMap<U256, U256>>,
    ) -> MutationResult
    where
        S: State + HasRand + HasMaxSize + HasItyState<Loc, Addr, VS> + HasCaller<H160>,
        VS: VMStateT + Default,
        Loc: Clone + Debug + Serialize + DeserializeOwned,
        Addr: Clone + Debug + Serialize + DeserializeOwned,
    {
        match self.get_type() {
            TEmpty => MutationResult::Skipped,
            T256 => {
                let v = self.b.deref_mut().as_any();
                let a256 = v.downcast_mut::<A256>().unwrap();
                if a256.is_address {
                    if state.rand_mut().below(100) < 90 {
                        let new_caller = state.get_rand_caller();
                        a256.data = new_caller.0.to_vec();
                    } else {
                        a256.data = [0; 20].to_vec();
                    }

                    MutationResult::Mutated
                } else {
                    byte_mutator(state, a256, vm_slots)
                }
            }
            TDynamic => {
                let adyn = self
                    .b
                    .deref_mut()
                    .as_any()
                    .downcast_mut::<ADynamic>()
                    .unwrap();
                // self.b.downcast_ref::<A256>().unwrap().mutate(state);
                byte_mutator_with_expansion(state, adyn, vm_slots)
            }
            TArray => {
                let aarray = self
                    .b
                    .deref_mut()
                    .as_any()
                    .downcast_mut::<AArray>()
                    .unwrap();

                let data_len = aarray.data.len();
                if data_len == 0 {
                    return MutationResult::Skipped;
                }
                if aarray.dynamic_size {
                    if (state.rand_mut().below(100)) < 80 {
                        let index: usize = state.rand_mut().next() as usize % data_len;
                        let result = aarray.data[index].mutate_with_vm_slots(state, vm_slots);
                        return result;
                    }

                    // increase size
                    if state.max_size() <= aarray.data.len() {
                        return MutationResult::Skipped;
                    }
                    for _ in 0..state.rand_mut().next() as usize % state.max_size() {
                        aarray.data.push(aarray.data[0].clone());
                    }
                } else {
                    let index: usize = state.rand_mut().next() as usize % data_len;
                    return aarray.data[index].mutate_with_vm_slots(state, vm_slots);
                }
                MutationResult::Mutated
            }
            TUnknown => {
                let a_unknown = self
                    .b
                    .deref_mut()
                    .as_any()
                    .downcast_mut::<AUnknown>()
                    .unwrap();
                unsafe {
                    if a_unknown.size == 0 {
                        a_unknown.concrete_type = BoxedABI::new(Box::new(AEmpty {}));
                        return MutationResult::Skipped;
                    }
                    if (state.rand_mut().below(100)) < 90 {
                        a_unknown
                            .concrete_type
                            .mutate_with_vm_slots(state, vm_slots)
                    } else {
                        a_unknown.concrete_type = sample_abi(state, a_unknown.size);
                        MutationResult::Mutated
                    }
                }
            }
        }
    }
}

impl Clone for Box<dyn ABI> {
    fn clone(&self) -> Box<dyn ABI> {
        self.clone_box()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AEmpty {}

impl Input for AEmpty {
    fn generate_name(&self, idx: usize) -> String {
        format!("AEmpty_{}", idx)
    }
}

impl ABI for AEmpty {
    fn is_static(&self) -> bool {
        panic!("unreachable");
    }

    fn get_bytes(&self) -> Vec<u8> {
        Vec::new()
    }

    fn get_type(&self) -> ABILossyType {
        TEmpty
    }

    fn to_string(&self) -> String {
        "".to_string()
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

// 0~256-bit data types
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct A256 {
    data: Vec<u8>,
    pub is_address: bool,
}

fn vec_to_hex(v: &Vec<u8>) -> String {
    let mut s = String::new();
    s.push_str("0x");
    for i in v {
        s.push_str(&format!("{:02x}", i));
    }
    s
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

    fn get_type(&self) -> ABILossyType {
        T256
    }

    fn to_string(&self) -> String {
        vec_to_hex(&self.data)
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

    fn get_type(&self) -> ABILossyType {
        TDynamic
    }

    fn to_string(&self) -> String {
        vec_to_hex(&self.data)
    }

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

    fn get_type(&self) -> ABILossyType {
        TArray
    }

    fn to_string(&self) -> String {
        format!(
            "({})",
            self.data.iter().map(|x| x.b.deref().to_string()).join(",")
        )
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

pub fn get_abi_type_boxed(abi_name: &String) -> BoxedABI {
    return BoxedABI {
        b: get_abi_type(abi_name, &None),
        function: [0; 4],
    };
}

pub fn get_abi_type_boxed_with_address(abi_name: &String, address: Vec<u8>) -> BoxedABI {
    return BoxedABI {
        b: get_abi_type(abi_name, &Some(address)),
        function: [0; 4],
    };
}

fn split_with_parenthesis(s: &str) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    let mut current: String = String::new();
    let mut parenthesis: i32 = 0;
    for c in s.chars() {
        if c == '(' {
            parenthesis += 1;
        } else if c == ')' {
            parenthesis -= 1;
        }
        if c == ',' && parenthesis == 0 {
            result.push(current);
            current = String::new();
        } else {
            current.push(c);
        }
    }
    result.push(current);
    result
}

pub fn get_abi_type(abi_name: &String, with_address: &Option<Vec<u8>>) -> Box<dyn ABI> {
    let abi_name_str = abi_name.as_str();
    // tuple
    if abi_name_str == "()" {
        return Box::new(AEmpty {});
    }
    if abi_name_str.starts_with("(") && abi_name_str.ends_with(")") {
        return Box::new(AArray {
            data: split_with_parenthesis(&abi_name_str[1..abi_name_str.len() - 1])
                .iter()
                .map(|x| BoxedABI {
                    b: get_abi_type(&String::from(x), with_address),
                    function: [0; 4],
                })
                .collect(),
            dynamic_size: false,
        });
    }
    if abi_name_str.ends_with("[]") {
        return Box::new(AArray {
            data: vec![
                BoxedABI {
                    b: get_abi_type(
                        &abi_name[..abi_name_str.len() - 2].to_string(),
                        with_address
                    ),
                    function: [0; 4]
                };
                1
            ],
            dynamic_size: true,
        });
    } else if abi_name_str.ends_with("]") && abi_name_str.contains("[") {
        let split = abi_name_str.rsplit_once('[').unwrap();
        let name = split.0;
        let len = split
            .1
            .split(']')
            .next()
            .unwrap()
            .parse::<usize>()
            .expect("invalid array length");
        return Box::new(AArray {
            data: vec![
                BoxedABI {
                    b: get_abi_type(&String::from(name), with_address),
                    function: [0; 4]
                };
                len
            ],
            dynamic_size: false,
        });
    }
    get_abi_type_basic(abi_name.as_str(), 32, with_address)
}

fn get_abi_type_basic(
    abi_name: &str,
    abi_bs: usize,
    with_address: &Option<Vec<u8>>,
) -> Box<dyn ABI> {
    match abi_name {
        "uint" | "int" => Box::new(A256 {
            data: vec![0; abi_bs],
            is_address: false,
        }),
        "address" => Box::new(A256 {
            data: with_address.to_owned().unwrap_or(vec![0; 20]),
            is_address: true,
        }),
        "bool" => Box::new(A256 {
            data: vec![0; 1],
            is_address: false,
        }),
        "bytes" => Box::new(ADynamic {
            data: Vec::new(),
            multiplier: 32,
        }),
        "string" => Box::new(ADynamic {
            data: Vec::new(),
            multiplier: 32,
        }),
        _ => {
            if abi_name.starts_with("uint") {
                let len = abi_name[4..].parse::<usize>().unwrap();
                assert!(len % 8 == 0 && len >= 8);
                return get_abi_type_basic("uint", len / 8, with_address);
            } else if abi_name.starts_with("int") {
                let len = abi_name[3..].parse::<usize>().unwrap();
                assert!(len % 8 == 0 && len >= 8);
                return get_abi_type_basic("int", len / 8, with_address);
            } else if abi_name.starts_with("bytes") {
                let len = abi_name[5..].parse::<usize>().unwrap();
                return get_abi_type_basic("bytes", len, with_address);
            } else if abi_name.len() == 0 {
                return Box::new(AEmpty {});
            } else {
                panic!("unknown abi type {}", abi_name);
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AUnknown {
    pub concrete_type: BoxedABI,
    pub size: usize,
}

impl Input for AUnknown {
    fn generate_name(&self, idx: usize) -> String {
        format!("AUnknown_{}", idx)
    }
}

impl ABI for AUnknown {
    fn is_static(&self) -> bool {
        self.concrete_type.is_static()
    }

    fn get_bytes(&self) -> Vec<u8> {
        self.concrete_type.b.get_bytes()
    }

    fn get_type(&self) -> ABILossyType {
        TUnknown
    }

    fn to_string(&self) -> String {
        self.concrete_type.b.to_string()
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

// test serialization and deserialization

mod tests {
    use super::*;
    use crate::evm::types::EVMFuzzState;
    use crate::evm::vm::EVMState;
    use crate::state::FuzzState;
    use hex;

    #[test]
    fn test_int() {
        let mut abi = get_abi_type_boxed(&String::from("int8"));
        let mut test_state = FuzzState::new();
        let mutation_result = abi.mutate::<H160, H160, EVMState, EVMFuzzState>(&mut test_state);
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abi.get_bytes())
        );
    }

    #[test]
    fn test_int256() {
        let mut abi = get_abi_type_boxed(&String::from("int256"));
        let mut test_state = FuzzState::new();
        let mutation_result = abi.mutate::<H160, H160, EVMState, EVMFuzzState>(&mut test_state);
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abi.get_bytes())
        );
    }

    #[test]
    fn test_dynamic() {
        let mut abi = get_abi_type_boxed(&String::from("string"));
        let mut test_state = FuzzState::new();
        let mutation_result = abi.mutate::<H160, H160, EVMState, EVMFuzzState>(&mut test_state);
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abi.get_bytes())
        );
    }

    #[test]
    fn test_tuple_static() {
        let mut abi = get_abi_type_boxed(&String::from("(uint256,uint256)"));
        let mut test_state = FuzzState::new();
        let mutation_result = abi.mutate::<H160, H160, EVMState, EVMFuzzState>(&mut test_state);
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abi.get_bytes())
        );
    }

    #[test]
    fn test_tuple_dynamic() {
        let mut abi = get_abi_type_boxed(&String::from("(string)"));
        let mut test_state = FuzzState::new();
        let mutation_result = abi.mutate::<H160, H160, EVMState, EVMFuzzState>(&mut test_state);
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abi.get_bytes())
        );
    }

    #[test]
    fn test_tuple_mixed() {
        let mut abi = get_abi_type_boxed(&String::from("(string,uint256)"));
        let mut test_state = FuzzState::new();
        let mutation_result = abi.mutate::<H160, H160, EVMState, EVMFuzzState>(&mut test_state);
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abi.get_bytes())
        );
    }

    #[test]
    fn test_array_static() {
        let mut abi = get_abi_type_boxed(&String::from("uint256[2]"));
        let mut test_state = FuzzState::new();
        let mutation_result = abi.mutate::<H160, H160, EVMState, EVMFuzzState>(&mut test_state);
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abi.get_bytes())
        );
    }

    #[test]
    fn test_array_dynamic() {
        let mut abi = get_abi_type_boxed(&String::from("bytes[2]"));
        let mut test_state = FuzzState::new();
        let mutation_result = abi.mutate::<H160, H160, EVMState, EVMFuzzState>(&mut test_state);
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abi.get_bytes())
        );
    }

    #[test]
    fn test_array_mixed() {
        let mut abi = get_abi_type_boxed(&String::from("uint256[2][3]"));
        let mut test_state = FuzzState::new();
        let mutation_result = abi.mutate::<H160, H160, EVMState, EVMFuzzState>(&mut test_state);
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abi.get_bytes())
        );
    }

    #[test]
    fn test_array_dyn() {
        let mut abi = get_abi_type_boxed(&String::from("uint256[][]"));
        let mut test_state = FuzzState::new();
        let mutation_result = abi.mutate::<H160, H160, EVMState, EVMFuzzState>(&mut test_state);
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abi.get_bytes())
        );
    }

    #[test]
    fn test_null() {
        let mut abi = get_abi_type_boxed(&String::from("(int256,int256,int256,uint256,address)[]"));
        let mut test_state = FuzzState::new();
        let mutation_result = abi.mutate::<H160, H160, EVMState, EVMFuzzState>(&mut test_state);
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abi.get_bytes())
        );
    }
}
