/// Definition of ABI types and their encoding, decoding, mutating methods
use crate::evm::abi::ABILossyType::{TArray, TDynamic, TEmpty, TUnknown, T256};
use crate::evm::concolic::expr::Expr;
use crate::evm::types::{EVMAddress, EVMU256};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::ConciseSerde;
use crate::mutation_utils::{byte_mutator, byte_mutator_with_expansion};
use crate::state::{HasCaller, HasItyState};
use itertools::Itertools;
use libafl::inputs::{HasBytesVec, Input};
use libafl::mutators::MutationResult;
use libafl::prelude::HasMetadata;
use libafl::state::{HasMaxSize, HasRand, State};
use libafl_bolts::bolts_prelude::Rand;
use libafl_bolts::impl_serdeany;
use once_cell::sync::Lazy;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::ops::{Deref, DerefMut};

use super::types::checksum;

/// Mapping from known signature to function name
pub static mut FUNCTION_SIG: Lazy<HashMap<[u8; 4], String>> = Lazy::new(HashMap::new);

/// todo: remove this
static mut CONCOLIC_COUNTER: u64 = 0;

/// Convert a vector of bytes to hex string
fn vec_to_hex(v: &Vec<u8>) -> String {
    let mut s = String::new();
    s.push_str("0x");
    for i in v {
        s.push_str(&format!("{:02x}", i));
    }
    s
}

/// Calculate the smallest multiple of [`multiplier`] that is larger than or equal to [`x`] (round up)
fn roundup(x: usize, multiplier: usize) -> usize {
    (x + multiplier - 1) / multiplier * multiplier
}

/// Set the first 32 bytes of [`bytes`] to be [`len`] (LSB)
///
/// E.g. if len = 0x1234,
/// then bytes is set to 0x00000000000000000000000000000000000000000000001234
fn set_size(bytes: *mut u8, len: usize) {
    let mut rem: usize = len;
    unsafe {
        for i in 0..32 {
            *bytes.add(31 - i) = (rem & 0xff) as u8;
            rem >>= 8;
        }
    }
}

fn get_size(bytes: &[u8]) -> usize {
    let mut size: usize = 0;
    (0..32).for_each(|i| {
        size <<= 8;
        size += bytes[i] as usize;
    });
    size
}

/// ABI instance map from address
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ABIAddressToInstanceMap {
    /// Mapping from address to ABI instance
    pub map: HashMap<EVMAddress, Vec<BoxedABI>>,
}

impl_serdeany!(ABIAddressToInstanceMap);

impl ABIAddressToInstanceMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an ABI instance to the map
    pub fn add(&mut self, address: EVMAddress, abi: BoxedABI) {
        self.map.entry(address).or_default();
        self.map.get_mut(&address).unwrap().push(abi);
    }
}

pub fn register_abi_instance<S: HasMetadata>(address: EVMAddress, abi: BoxedABI, state: &mut S) {
    let abi_map = state
        .metadata_map_mut()
        .get_mut::<ABIAddressToInstanceMap>()
        .expect("ABIAddressToInstanceMap not found");
    abi_map.add(address, abi);
}

/// ABI types
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ABILossyType {
    /// All 256-bit types (uint8, uint16, uint32, uint64, uint128, uint256, address...)
    T256,
    /// All array types (X[], X[n], (X,Y,Z))
    TArray,
    /// All dynamic types (string, bytes...)
    TDynamic,
    /// Empty type (nothing)
    TEmpty,
    /// Unknown type (e.g., those we don't know ABI, it can be any type)
    TUnknown,
}

/// Traits of ABI types (encoding, decoding, etc.)
#[typetag::serde(tag = "type")]
pub trait ABI: CloneABI {
    /// Is the args static (i.e., fixed size)
    fn is_static(&self) -> bool;
    /// Get the ABI-encoded bytes of args
    fn get_bytes(&self) -> Vec<u8>;
    /// Get the ABI type of args
    fn get_type(&self) -> ABILossyType;
    /// Set the bytes to args, used for decoding
    fn set_bytes(&mut self, bytes: Vec<u8>) -> bool;
    /// Convert args to string (for debugging)
    fn to_string(&self) -> String;
    fn as_any(&mut self) -> &mut dyn Any;
    fn get_concolic(&self) -> Vec<Box<Expr>>;
    /// Get the size of args
    fn get_size(&self) -> usize;
}

impl Default for Box<dyn ABI> {
    fn default() -> Self {
        Box::new(AEmpty {})
    }
}

impl Debug for dyn ABI {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ABI")
            .field("is_static", &self.is_static())
            .field("get_bytes", &self.get_bytes())
            .finish()
    }
}

/// Cloneable trait object, to support serde serialization
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

/// ABI wrapper + function hash, to support serde serialization
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct BoxedABI {
    /// ABI wrapper
    // #[serde(with = "serde_traitobject")]
    pub b: Box<dyn ABI>,
    /// Function hash, if it is 0x00000000, it means the function hash is not set or
    /// this is to resume execution from a previous control leak
    pub function: [u8; 4],
}

impl Display for BoxedABI {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.function == [0; 4] {
            write!(
                f,
                "Stepping with return: {}",
                hex::encode(self.b.to_string())
            )
        } else {
            write!(f, "{}{}", self.get_func_name(), self.b.to_string())
        }
    }
}

impl BoxedABI {
    /// Create a new ABI wrapper with function hash = 0x00000000
    pub fn new(b: Box<dyn ABI>) -> Self {
        Self {
            b,
            function: [0; 4],
        }
    }

    /// Get the args in ABI form (unencoded)
    pub fn get(&self) -> &dyn ABI {
        self.b.deref()
    }

    /// Get the args in ABI form (unencoded) mutably
    pub fn get_mut(&mut self) -> &mut Box<dyn ABI> {
        &mut self.b
    }

    /// Get the function hash + encoded args (transaction data)
    pub fn get_bytes(&self) -> Vec<u8> {
        [Vec::from(self.function), self.b.get_bytes()].concat()
    }

    /// Get the function hash + encoded args (transaction data)
    pub fn get_bytes_vec(&self) -> Vec<u8> {
        self.b.get_bytes()
    }

    /// Determine if the args is static (i.e., fixed size)
    pub fn is_static(&self) -> bool {
        self.b.is_static()
    }

    /// Get the ABI type of args.
    /// If the function has more than one args, it will return Array type (tuple of args)
    pub fn get_type(&self) -> ABILossyType {
        self.b.get_type()
    }

    /// Get the ABI type of args in string format
    pub fn get_type_str(&self) -> String {
        match self.b.get_type() {
            T256 => "A256".to_string(),
            TArray => "AArray".to_string(),
            TDynamic => "ADynamic".to_string(),
            TEmpty => "AEmpty".to_string(),
            TUnknown => "AUnknown".to_string(),
        }
    }

    /// Set the function hash
    pub fn set_func(&mut self, function: [u8; 4]) {
        self.function = function;
    }

    /// Set the function hash with function signature, so that we can print the function signature or name instead of hash
    pub fn set_func_with_signature(&mut self, function: [u8; 4], fn_name: &str, fn_args: &str) {
        self.function = function;
        unsafe {
            FUNCTION_SIG.insert(function, format!("{}{}", fn_name, fn_args));
        }
    }

    /// Get function signature
    pub fn get_func_signature(&self) -> Option<String> {
        unsafe { FUNCTION_SIG.get(&self.function).cloned() }
    }

    /// Get function name
    pub fn get_func_name(&self) -> String {
        self.get_func_signature()
            .unwrap_or(hex::encode(self.function))
            .split("(")
            .next()
            .unwrap()
            .to_string()
    }

    /// todo: remove this
    pub fn get_concolic(self) -> Vec<Box<Expr>> {
        [
            self.function
                .iter()
                .map(|byte| Expr::const_byte(*byte))
                .collect_vec(),
            self.b.get_concolic(),
        ]
        .concat()
    }

    /// Set the bytes to args, used for decoding
    pub fn set_bytes(&mut self, bytes: Vec<u8>) -> bool {
        self.b.set_bytes(bytes[4..].to_vec())
    }
}

/// Randomly sample an args with any type with size `size`
fn sample_abi<Loc, Addr, VS, S, CI>(state: &mut S, size: usize) -> BoxedABI
where
    S: State + HasRand + HasItyState<Loc, Addr, VS, CI> + HasMaxSize + HasCaller<EVMAddress>,
    VS: VMStateT + Default,
    Loc: Clone + Debug + Serialize + DeserializeOwned,
    Addr: Clone + Debug + Serialize + DeserializeOwned,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    // TODO(@shou): use a better sampling strategy
    if size == 32 {
        // sample a static type
        match state.rand_mut().below(100) % 2 {
            0 => BoxedABI::new(Box::new(A256 {
                data: vec![0; 32],
                is_address: false,
                dont_mutate: false,
            })),
            1 => BoxedABI::new(Box::new(A256 {
                data: state.get_rand_address().0.into(),
                is_address: true,
                dont_mutate: false,
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
    /// Mutate the args
    pub fn mutate<Loc, Addr, VS, S, CI>(&mut self, state: &mut S) -> MutationResult
    where
        S: State
            + HasRand
            + HasMaxSize
            + HasItyState<Loc, Addr, VS, CI>
            + HasCaller<EVMAddress>
            + HasMetadata,
        VS: VMStateT + Default,
        Loc: Clone + Debug + Serialize + DeserializeOwned,
        Addr: Clone + Debug + Serialize + DeserializeOwned,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
    {
        self.mutate_with_vm_slots(state, None)
    }

    /// Mutate the args and crossover with slots in the VM state
    ///
    /// Check [`VMStateHintedMutator`] for more details
    pub fn mutate_with_vm_slots<Loc, Addr, VS, S, CI>(
        &mut self,
        state: &mut S,
        vm_slots: Option<HashMap<EVMU256, EVMU256>>,
    ) -> MutationResult
    where
        S: State
            + HasRand
            + HasMaxSize
            + HasItyState<Loc, Addr, VS, CI>
            + HasCaller<EVMAddress>
            + HasMetadata,
        VS: VMStateT + Default,
        Loc: Clone + Debug + Serialize + DeserializeOwned,
        Addr: Clone + Debug + Serialize + DeserializeOwned,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
    {
        match self.get_type() {
            // no need to mutate empty args
            TEmpty => MutationResult::Skipped,
            // mutate static args
            T256 => {
                let v = self.b.deref_mut().as_any();
                let a256 = v.downcast_mut::<A256>().unwrap();
                if a256.dont_mutate {
                    return MutationResult::Skipped;
                }
                if a256.is_address {
                    if state.rand_mut().below(100) < 90 {
                        a256.data = state.get_rand_address().0.to_vec();
                    } else {
                        a256.data = [0; 20].to_vec();
                    }

                    MutationResult::Mutated
                } else {
                    byte_mutator(state, a256, vm_slots)
                }
            }
            // mutate dynamic args
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
            // mutate tuple/array args
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
                    match state.rand_mut().below(100) {
                        0..=80 => {
                            let index: usize = state.rand_mut().next() as usize % data_len;
                            let result = aarray.data[index].mutate_with_vm_slots(state, vm_slots);
                            return result;
                        }
                        81..=90 => {
                            // increase size
                            if state.max_size() <= aarray.data.len() {
                                return MutationResult::Skipped;
                            }
                            for _ in 0..state.rand_mut().next() as usize % state.max_size() {
                                aarray.data.push(aarray.data[0].clone());
                            }
                        }
                        91..=100 => {
                            // decrease size
                            if aarray.data.is_empty() {
                                return MutationResult::Skipped;
                            }
                            let index: usize = state.rand_mut().next() as usize % data_len;
                            aarray.data.remove(index);
                        }
                        _ => {
                            unreachable!()
                        }
                    }
                } else {
                    let index: usize = state.rand_mut().next() as usize % data_len;
                    return aarray.data[index].mutate_with_vm_slots(state, vm_slots);
                }
                MutationResult::Mutated
            }
            // mutate unknown args, may change the type
            TUnknown => {
                let a_unknown = self
                    .b
                    .deref_mut()
                    .as_any()
                    .downcast_mut::<AUnknown>()
                    .unwrap();
                if a_unknown.size == 0 {
                    a_unknown.concrete = BoxedABI::new(Box::new(AEmpty {}));
                    return MutationResult::Skipped;
                }
                if (state.rand_mut().below(100)) < 80 {
                    a_unknown.concrete.mutate_with_vm_slots(state, vm_slots)
                } else {
                    a_unknown.concrete = sample_abi(state, a_unknown.size);
                    MutationResult::Mutated
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

/// AEmpty is used to represent empty args
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AEmpty {}

impl Input for AEmpty {
    fn generate_name(&self, idx: usize) -> String {
        format!("AEmpty_{}", idx)
    }
}

#[typetag::serde]
impl ABI for AEmpty {
    fn is_static(&self) -> bool {
        true
    }

    fn get_bytes(&self) -> Vec<u8> {
        Vec::new()
    }

    fn get_type(&self) -> ABILossyType {
        TEmpty
    }

    fn set_bytes(&mut self, bytes: Vec<u8>) -> bool {
        assert!(bytes.is_empty());
        true
    }

    fn to_string(&self) -> String {
        "".to_string()
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn get_concolic(&self) -> Vec<Box<Expr>> {
        Vec::new()
    }

    fn get_size(&self) -> usize {
        0
    }
}

/// [`A256`] is used to represent 256-bit args
/// (including uint8, uint16... as they are all 256-bit behind the scene)
///
/// For address type, we need to distinguish between it and rest so that we can mutate correctly.
/// Instead of mutating address as a 256-bit integer, we mutate it to known address or zero address.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct A256 {
    /// 256-bit or less data representing the arg
    pub data: Vec<u8>,
    /// whether this arg is an address
    pub is_address: bool,
    /// whether this arg should not be mutated
    pub dont_mutate: bool,
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

#[typetag::serde]
impl ABI for A256 {
    fn is_static(&self) -> bool {
        // 256-bit args are always static
        true
    }

    fn get_bytes(&self) -> Vec<u8> {
        // pad self.data to 32 bytes with 0s on the left
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

    fn set_bytes(&mut self, bytes: Vec<u8>) -> bool {
        if bytes.len() < 32 {
            return false;
        }
        self.data = bytes[..32].to_vec();
        true
    }

    fn to_string(&self) -> String {
        if self.is_address {
            checksum(&EVMAddress::from_slice(&self.data))
        } else {
            vec_to_hex(&self.data)
        }
    }

    fn get_concolic(&self) -> Vec<Box<Expr>> {
        let mut bytes = vec![Expr::const_byte(0u8); 32];
        let data_len = self.data.len();
        unsafe {
            let counter = CONCOLIC_COUNTER;
            CONCOLIC_COUNTER += 1;
            let mut ptr = bytes.as_mut_ptr();
            ptr = ptr.add(32 - data_len);
            for i in 0..data_len {
                println!("[concolic] AAAAAAAA {}_A256_{}", counter, i);
                *ptr.add(i) = Expr::sym_byte(format!("{}_A256_{}", counter, i));
            }
        }
        bytes
    }

    fn get_size(&self) -> usize {
        32
    }
}

/// [`ADynamic`] is used to represent dynamic args
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ADynamic {
    /// data representing the arg
    data: Vec<u8>,
    /// multiplier used to round up the size of the data
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

#[typetag::serde]
impl ABI for ADynamic {
    fn is_static(&self) -> bool {
        false
    }

    fn get_bytes(&self) -> Vec<u8> {
        // pad self.data to K bytes with 0s on the left
        // where K is the smallest multiple of self.multiplier that is larger than self.data.len()
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

    fn set_bytes(&mut self, bytes: Vec<u8>) -> bool {
        if bytes.is_empty() {
            self.data = Vec::new();
            return true;
        }
        self.data = bytes[32..32 + get_size(&bytes)].to_vec();
        true
    }

    fn get_concolic(&self) -> Vec<Box<Expr>> {
        let new_len: usize = roundup(self.data.len(), self.multiplier);
        let mut bytes = vec![Expr::const_byte(0u8); new_len + 32];
        unsafe {
            let counter = CONCOLIC_COUNTER;
            CONCOLIC_COUNTER += 1;
            let ptr = bytes.as_mut_ptr();
            // here we assume the size of the dynamic data
            // will not change. However, this may change as well
            let mut rem: usize = self.data.len();
            for i in 0..32 {
                *ptr.add(31 - i) = Expr::const_byte((rem & 0xff) as u8);
                rem >>= 8;
            }
            // set data
            for i in 0..self.data.len() {
                *ptr.add(i + 32) = Expr::sym_byte(format!("ADynamic_{}_{}", counter, i));
            }
        }
        bytes
    }

    fn get_size(&self) -> usize {
        self.data.len() + 32
    }
}

/// [`AArray`] is used to represent array or tuple
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AArray {
    /// vector of ABI objects in the array / tuple
    pub(crate) data: Vec<BoxedABI>,
    /// whether the size of the array is dynamic (i.e., is it dynamic size array)
    pub(crate) dynamic_size: bool,
}

impl Input for AArray {
    fn generate_name(&self, idx: usize) -> String {
        format!("AArray_{}", idx)
    }
}

fn set_size_concolic(bytes: *mut Box<Expr>, len: usize) {
    let mut rem: usize = len;
    unsafe {
        for i in 0..32 {
            *bytes.add(31 - i) = Expr::const_byte((rem & 0xff) as u8);
            rem >>= 8;
        }
    }
}

#[typetag::serde]
impl ABI for AArray {
    fn is_static(&self) -> bool {
        if self.dynamic_size {
            false
        } else {
            self.data.iter().all(|x| x.is_static())
        }
    }

    fn get_bytes(&self) -> Vec<u8> {
        // check Solidity spec for encoding of arrays
        let mut tail_data: Vec<Vec<u8>> = Vec::new();
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
                tail_data.push(dummy_bytes.clone());
            } else {
                tail_data.push(self.data[i].get_bytes_vec());
                head.push(dummy_bytes.clone());
                head_size += 32;
            }
        }
        let mut content_size: usize = 0;
        tails_offset.push(0);
        let mut head_data_size: usize = 0;
        let mut tail_data_size: usize = 0;
        if !tail_data.is_empty() {
            (0..tail_data.len() - 1).for_each(|i| {
                content_size += tail_data[i].len();
                tails_offset.push(content_size);
            });
            for i in 0..tails_offset.len() {
                if head[i].is_empty() {
                    head_data.push(vec![0; 32]);
                    head_data_size += 32;
                    set_size(head_data[i].as_mut_ptr(), tails_offset[i] + head_size);
                } else {
                    head_data.push(head[i].clone());
                    head_data_size += head[i].len();
                }
            }
            tail_data_size = content_size + tail_data[tail_data.len() - 1].len();
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
        for i in 0..tail_data.len() {
            bytes[offset..offset + tail_data[i].len()]
                .copy_from_slice(tail_data[i].to_vec().as_slice());
            offset += tail_data[i].len();
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

    // Input: packed concrete bytes produced by get_concolic
    // Set the bytes in self.data accordingly
    fn set_bytes(&mut self, bytes: Vec<u8>) -> bool {
        let base_offset = if self.dynamic_size {
            let array_size = get_size(&bytes);
            while self.data.len() < array_size {
                if self.data.is_empty() {
                    self.data.push(BoxedABI::default());
                } else {
                    self.data.push(self.data[0].clone());
                }
            }
            self.data.truncate(array_size);
            32
        } else {
            0
        };

        let mut offset: usize = 0;

        for item in self.data.iter_mut() {
            let (item_offset, size) = match item.get_type() {
                T256 => (offset, 32),
                TArray if item.is_static() => (offset, item.b.get_size()),
                TArray | TDynamic => (get_size(&bytes[offset + base_offset..]), 32),
                TEmpty => (0, 0),
                TUnknown => {
                    unreachable!()
                }
            };

            let start = item_offset + base_offset;
            if start + size >= bytes.len() {
                return false;
            }
            item.b.set_bytes(bytes[start..].to_vec());
            offset += size;
        }
        true
    }

    fn get_concolic(&self) -> Vec<Box<Expr>> {
        let mut tail_data: Vec<Vec<u8>> = Vec::new();
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
                tail_data.push(dummy_bytes.clone());
            } else {
                tail_data.push(self.data[i].get_bytes_vec());
                head.push(dummy_bytes.clone());
                head_size += 32;
            }
        }
        let mut content_size: usize = 0;
        tails_offset.push(0);
        let mut head_data_size: usize = 0;
        let mut tail_data_size: usize = 0;
        if !tail_data.is_empty() {
            (0..tail_data.len() - 1).for_each(|i| {
                content_size += tail_data[i].len();
                tails_offset.push(content_size);
            });
            for i in 0..tails_offset.len() {
                if head[i].is_empty() {
                    head_data.push(vec![0; 32]);
                    head_data_size += 32;
                    set_size(head_data[i].as_mut_ptr(), tails_offset[i] + head_size);
                } else {
                    head_data.push(head[i].clone());
                    head_data_size += head[i].len();
                }
            }
            tail_data_size = content_size + tail_data[tail_data.len() - 1].len();
        }
        let mut bytes =
            vec![
                Expr::const_byte(0);
                head_data_size + tail_data_size + if self.dynamic_size { 32 } else { 0 }
            ];

        if self.dynamic_size {
            set_size_concolic(bytes.as_mut_ptr(), self.data.len());
        }
        let mut offset: usize = if self.dynamic_size { 32 } else { 0 };
        for i in 0..head_data.len() {
            if self.data[i].is_static() {
                unsafe {
                    let counter = CONCOLIC_COUNTER;

                    CONCOLIC_COUNTER += 1;
                    for j in 0..head_data[i].len() {
                        bytes[offset + j] = Expr::sym_byte(format!(
                            "{}_{}_{}_{}",
                            counter,
                            self.data[i].get_type_str(),
                            i,
                            j
                        ));
                    }
                }
            } else {
                bytes[offset..offset + head_data[i].len()].clone_from_slice(
                    head_data[i]
                        .iter()
                        .map(|x| Expr::const_byte(*x))
                        .collect_vec()
                        .as_slice(),
                );
            }
            offset += head_data[i].len();
        }
        (0..tail_data.len()).for_each(|i| {
            if !tail_data[i].is_empty() {
                unsafe {
                    let counter = CONCOLIC_COUNTER;

                    CONCOLIC_COUNTER += 1;
                    for j in 0..tail_data[i].len() {
                        bytes[offset + j] = Expr::sym_byte(format!(
                            "{}_{}_{}_{}",
                            counter,
                            self.data[i].get_type_str(),
                            i,
                            j
                        ));
                    }
                }
                offset += tail_data[i].len();
            }
        });
        bytes
    }

    fn get_size(&self) -> usize {
        let data_size = self.data.iter().map(|x| x.b.get_size()).sum::<usize>();
        if self.dynamic_size {
            32 + data_size
        } else {
            data_size
        }
    }
}

/// [`AUnknown`] represents arg with no known types (can be any type)
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AUnknown {
    /// Current concrete arg
    pub concrete: BoxedABI,
    /// Size constraint
    pub size: usize,
}

impl Input for AUnknown {
    fn generate_name(&self, idx: usize) -> String {
        format!("AUnknown_{}", idx)
    }
}

#[typetag::serde]
impl ABI for AUnknown {
    fn is_static(&self) -> bool {
        self.concrete.is_static()
    }

    fn get_bytes(&self) -> Vec<u8> {
        self.concrete.b.get_bytes()
    }

    fn get_type(&self) -> ABILossyType {
        TUnknown
    }

    fn set_bytes(&mut self, bytes: Vec<u8>) -> bool {
        self.concrete.b.set_bytes(bytes);
        true
    }

    fn to_string(&self) -> String {
        self.concrete.b.to_string()
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn get_concolic(&self) -> Vec<Box<Expr>> {
        panic!("[Concolic] sAUnknown not supported")
    }

    fn get_size(&self) -> usize {
        self.concrete.b.get_size()
    }
}

/// Create a [`BoxedABI`] with default arg given the ABI type in string
pub fn get_abi_type_boxed(abi_name: &str) -> BoxedABI {
    BoxedABI {
        b: get_abi_type(abi_name, &None),
        function: [0; 4],
    }
}

/// Create a [`BoxedABI`] with default arg given the ABI type in string and address
/// todo: remove this function
pub fn get_abi_type_boxed_with_address(abi_name: &str, address: Vec<u8>) -> BoxedABI {
    BoxedABI {
        b: get_abi_type(abi_name, &Some(address)),
        function: [0; 4],
    }
}

/// Split a string with parenthesis
///
/// # Example
/// ```
/// use ityfuzz::evm::abi::split_with_parenthesis;
/// let s = "a,b,(c,d),e";
/// let result = split_with_parenthesis(s);
/// assert_eq!(result, vec!["a", "b", "(c,d)", "e"]);
/// ```
pub fn split_with_parenthesis(s: &str) -> Vec<String> {
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

/// Get the arg with default value given the ABI type in string
///
/// # Example
/// ```
/// use ityfuzz::evm::abi::get_abi_type;
/// let result = get_abi_type(&"uint256".to_string(), &None);
/// // result is a A256 with default value 0
/// ```
pub fn get_abi_type(abi_name: &str, with_address: &Option<Vec<u8>>) -> Box<dyn ABI> {
    let abi_name_str = abi_name;
    // tuple
    if abi_name_str == "()" {
        return Box::new(AEmpty {});
    }
    if abi_name_str.starts_with('(') && abi_name_str.ends_with(')') {
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
                    b: get_abi_type(&abi_name[..abi_name_str.len() - 2], with_address),
                    function: [0; 4]
                };
                1
            ],
            dynamic_size: true,
        });
    } else if abi_name_str.ends_with(']') && abi_name_str.contains('[') {
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
    get_abi_type_basic(abi_name, 32, with_address)
}

/// Get the arg with default value given the ABI type in string.
/// Only support basic types.
fn get_abi_type_basic(
    abi_name: &str,
    abi_bs: usize,
    with_address: &Option<Vec<u8>>,
) -> Box<dyn ABI> {
    match abi_name {
        "uint" | "int" => Box::new(A256 {
            data: vec![0; abi_bs],
            is_address: false,
            dont_mutate: false,
        }),
        "address" => Box::new(A256 {
            data: with_address.to_owned().unwrap_or(vec![0; 20]),
            is_address: true,
            dont_mutate: false,
        }),
        "bool" => Box::new(A256 {
            data: vec![0; 1],
            is_address: false,
            dont_mutate: false,
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
            if let Some(stripped) = abi_name.strip_prefix("uint") {
                let len = stripped.parse::<usize>().unwrap();
                assert!(len % 8 == 0 && len >= 8);
                get_abi_type_basic("uint", len / 8, with_address)
            } else if let Some(stripped) = abi_name.strip_prefix("int") {
                let len = stripped.parse::<usize>().unwrap();
                assert!(len % 8 == 0 && len >= 8);
                return get_abi_type_basic("int", len / 8, with_address);
            } else if abi_name == "unknown" {
                return Box::new(AUnknown {
                    concrete: BoxedABI {
                        b: get_abi_type_basic("uint", 32, with_address),
                        function: [0; 4],
                    },
                    size: 1,
                });
            } else if let Some(stripped) = abi_name.strip_prefix("bytes") {
                let len = stripped.parse::<usize>().unwrap();
                return Box::new(A256 {
                    data: vec![0; len],
                    is_address: false,
                    dont_mutate: false,
                });
            } else if abi_name.is_empty() {
                return Box::new(AEmpty {});
            } else {
                panic!("unknown abi type {}", abi_name);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::input::ConciseEVMInput;
    use crate::evm::types::EVMFuzzState;
    use crate::evm::vm::EVMState;
    use crate::state::FuzzState;
    use hex;

    #[test]
    fn test_int() {
        let mut abi = get_abi_type_boxed(&String::from("int8"));
        let mut test_state = FuzzState::new(0);
        let mutation_result = abi
            .mutate::<EVMAddress, EVMAddress, EVMState, EVMFuzzState, ConciseEVMInput>(
                &mut test_state,
            );
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abi.get_bytes())
        );
    }

    #[test]
    fn test_int256() {
        let mut abi = get_abi_type_boxed(&String::from("int256"));
        let mut test_state = FuzzState::new(0);
        let mutation_result = abi
            .mutate::<EVMAddress, EVMAddress, EVMState, EVMFuzzState, ConciseEVMInput>(
                &mut test_state,
            );
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abi.get_bytes())
        );
    }

    #[test]
    fn test_dynamic() {
        let mut abi = get_abi_type_boxed(&String::from("string"));
        let mut test_state = FuzzState::new(0);
        let mutation_result = abi
            .mutate::<EVMAddress, EVMAddress, EVMState, EVMFuzzState, ConciseEVMInput>(
                &mut test_state,
            );
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abi.get_bytes())
        );
    }

    #[test]
    fn test_tuple_static() {
        let mut abi = get_abi_type_boxed(&String::from("(uint256,uint256)"));
        let mut test_state = FuzzState::new(0);
        let mutation_result = abi
            .mutate::<EVMAddress, EVMAddress, EVMState, EVMFuzzState, ConciseEVMInput>(
                &mut test_state,
            );
        let abibytes = abi.get_bytes();
        abi.set_bytes(abibytes.clone());
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abibytes)
        );
    }

    #[test]
    fn test_tuple_dynamic() {
        let mut abi = get_abi_type_boxed(&String::from("(string)"));
        let mut test_state = FuzzState::new(0);
        let mutation_result = abi
            .mutate::<EVMAddress, EVMAddress, EVMState, EVMFuzzState, ConciseEVMInput>(
                &mut test_state,
            );
        let abibytes = abi.get_bytes();
        abi.set_bytes(abibytes.clone());
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abibytes)
        );
    }

    #[test]
    fn test_tuple_mixed() {
        let mut abi = get_abi_type_boxed(&String::from("(string,uint256)"));
        let mut test_state = FuzzState::new(0);
        let mutation_result = abi
            .mutate::<EVMAddress, EVMAddress, EVMState, EVMFuzzState, ConciseEVMInput>(
                &mut test_state,
            );
        let abibytes = abi.get_bytes();
        abi.set_bytes(abibytes.clone());
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abibytes)
        );
    }

    #[test]
    fn test_array_static() {
        let mut abi = get_abi_type_boxed(&String::from("uint256[2]"));
        let mut test_state = FuzzState::new(0);
        let mutation_result = abi
            .mutate::<EVMAddress, EVMAddress, EVMState, EVMFuzzState, ConciseEVMInput>(
                &mut test_state,
            );
        let abibytes = abi.get_bytes();
        abi.set_bytes(abibytes.clone());
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abibytes)
        );
    }

    #[test]
    fn test_array_dynamic() {
        let mut abi = get_abi_type_boxed(&String::from("bytes[2]"));
        let mut test_state = FuzzState::new(0);
        let mutation_result = abi
            .mutate::<EVMAddress, EVMAddress, EVMState, EVMFuzzState, ConciseEVMInput>(
                &mut test_state,
            );
        let abibytes = abi.get_bytes();
        abi.set_bytes(abibytes.clone());
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abibytes)
        );
    }

    #[test]
    fn test_array_mixed() {
        let mut abi = get_abi_type_boxed(&String::from("uint256[2][3]"));
        let mut test_state = FuzzState::new(0);
        let mutation_result = abi
            .mutate::<EVMAddress, EVMAddress, EVMState, EVMFuzzState, ConciseEVMInput>(
                &mut test_state,
            );
        let abibytes = abi.get_bytes();
        abi.set_bytes(abibytes.clone());
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abibytes)
        );
    }

    #[test]
    fn test_array_dyn() {
        let mut abi = get_abi_type_boxed(&String::from("uint256[][]"));
        let mut test_state = FuzzState::new(0);
        let mutation_result = abi
            .mutate::<EVMAddress, EVMAddress, EVMState, EVMFuzzState, ConciseEVMInput>(
                &mut test_state,
            );
        let abibytes = abi.get_bytes();
        abi.set_bytes(abibytes.clone());
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abibytes)
        );
    }

    #[test]
    fn test_null() {
        let mut abi = get_abi_type_boxed(&String::from("(int256,int256,int256,uint256,address)[]"));
        let mut test_state = FuzzState::new(0);
        test_state.addresses_pool.push(EVMAddress::zero());
        let mutation_result = abi
            .mutate::<EVMAddress, EVMAddress, EVMState, EVMFuzzState, ConciseEVMInput>(
                &mut test_state,
            );
        let abibytes = abi.get_bytes();
        abi.set_bytes(abibytes.clone());
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abibytes)
        );
    }

    #[test]
    fn test_complex() {
        let mut abi = get_abi_type_boxed(&String::from("((bytes[3],uint256)[],string)[]"));

        let mut test_state = FuzzState::new(0);
        let mutation_result = abi
            .mutate::<EVMAddress, EVMAddress, EVMState, EVMFuzzState, ConciseEVMInput>(
                &mut test_state,
            );
        let abibytes = abi.get_bytes();

        println!("abibytes: {:?}", hex::encode(abibytes.clone()));

        abi.set_bytes(abibytes.clone());

        let newbytes = abi.get_bytes();
        if newbytes != abibytes {
            println!("oldbytes: {:?}", hex::encode(abibytes));
            println!("newbytes: {:?}", hex::encode(newbytes));
            panic!("bytes mismatch");
        }
        println!(
            "result: {:?} abi: {:?}",
            mutation_result,
            hex::encode(abibytes)
        );
    }

    #[test]
    fn test_100_times() {
        for _ in 0..100 {
            test_complex();
        }
    }
}
