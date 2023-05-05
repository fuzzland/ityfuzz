use crate::evm::abi::BoxedABI;
use crate::input::VMInputT;
use crate::r#move::types::MoveStagedVMState;
use crate::r#move::vm_state::MoveVMState;
use crate::state::{HasCaller, HasItyState};

use libafl::inputs::Input;
use libafl::prelude::{HasBytesVec, HasMaxSize, HasMetadata, MutationResult, Rand, State};
use libafl::state::HasRand;

use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::{ModuleId, TypeTag};

use move_vm_types::values::{Container, ContainerRef, Value, ValueImpl};
use primitive_types::U256;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::any;
use std::borrow::BorrowMut;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use itertools::Itertools;
use move_vm_runtime::loader::{Function, Module};
use move_vm_types::loaded_data::runtime_types::Type;
use crate::mutation_utils::byte_mutator;

pub trait MoveFunctionInputT {
    fn module_id(&self) -> &ModuleId;
    fn function_name(&self) -> &Identifier;
    fn args(&self) -> &Vec<CloneableValue>;
    fn ty_args(&self) -> &Vec<Type>;
}

pub struct FunctionDefaultable {
    pub function: Option<Function>
}

impl Default for FunctionDefaultable {
    fn default() -> Self {
        FunctionDefaultable {
            function: None
        }
    }
}

impl FunctionDefaultable {
    pub fn get_function(&self) -> &Function {
        self.function.as_ref().unwrap()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MoveFunctionInput {
    pub module: ModuleId,
    pub function: Identifier,

    #[serde(skip_serializing,skip_deserializing)]
    pub function_info: Arc<FunctionDefaultable>,

    pub args: Vec<CloneableValue>,
    pub ty_args: Vec<Type>,

    pub caller: AccountAddress,

    pub vm_state: MoveStagedVMState,
    pub vm_state_idx: usize,
}

impl Debug for MoveFunctionInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MoveFunctionInput")
            .field("module", &self.module)
            .field("args", &self.args)
            .field("ty_args", &self.ty_args)
            .field("caller", &self.caller)
            .field("vm_state", &self.vm_state)
            .field("vm_state_idx", &self.vm_state_idx)
            .finish()
    }
}


#[derive(Debug)]
pub struct CloneableValue {
    pub value: Value,
    // for mutator
    pub bytes: Vec<u8>,
}

impl Clone for CloneableValue {
    fn clone(&self) -> Self {
        CloneableValue {
            value: self.value.clone(),
            bytes: vec![],
        }
    }
}

impl Serialize for CloneableValue {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        unreachable!()
    }
}

impl<'de> Deserialize<'de> for CloneableValue {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        unreachable!()
    }
}

impl CloneableValue {
    pub fn from(value: Value) -> Self {
        CloneableValue { value, bytes: vec![] }
    }

    pub fn get_value(&self) -> &Value {
        &self.value
    }

    pub fn get_value_mut(&mut self) -> &mut Value {
        &mut self.value
    }
}

impl MoveFunctionInputT for MoveFunctionInput {
    fn module_id(&self) -> &ModuleId {
        &self.module
    }

    fn function_name(&self) -> &Identifier {
        &self.function
    }

    fn args(&self) -> &Vec<CloneableValue> {
        &self.args
    }

    fn ty_args(&self) -> &Vec<Type> {
        &self.ty_args
    }
}

impl Input for MoveFunctionInput {
    fn generate_name(&self, idx: usize) -> String {
        format!("{}_{}_{}", idx, self.module, self.function)
    }
}


impl Input for CloneableValue {
    fn generate_name(&self, idx: usize) -> String {
        format!("{}_{}", idx, self.value)
    }
}

impl HasBytesVec for CloneableValue {
    fn bytes(&self) -> &[u8] {
        unimplemented!()
    }

    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        macro_rules! leb_tns {
            ($v: expr) => {
                {
                    self.bytes.copy_from_slice(&$v.to_le_bytes());
                    &mut self.bytes
                }
            };
            (vec, $v: expr) => {
                {
                    let sl = $v.borrow().deref().iter().map(|x| x.to_le_bytes()).flatten().collect::<Vec<u8>>();
                    self.bytes.copy_from_slice(sl.as_slice());
                    &mut self.bytes
                }
            };
        }
        match &self.value.0 {
            ValueImpl::Container(v) => {
                match v {
                    Container::VecU8(v) => {
                        return leb_tns!(vec, v)
                    }
                    Container::VecU64(v) => {
                        return leb_tns!(vec, v)
                    }
                    Container::VecU128(v) => {
                        return leb_tns!(vec, v)
                    }
                    Container::VecU16(v) => {
                        return leb_tns!(vec, v)
                    }
                    Container::VecU32(v) => {
                        return leb_tns!(vec, v)
                    }
                    Container::VecU256(v) => {
                        return leb_tns!(vec, v)
                    }
                    // cant be mutated
                    _ => unreachable!()
                }
            }
            ValueImpl::U128(v) => {
                self.bytes = v.to_le_bytes().to_vec();
                &mut self.bytes
            }
            ValueImpl::U256(v) => {
                self.bytes = v.to_le_bytes().to_vec();
                &mut self.bytes
            }
            // ValueImpl::ContainerRef(_) => {}
            // ValueImpl::IndexedRef(_) => {}
            _ => unreachable!()
        }
    }
}

impl CloneableValue {
    fn commit(&mut self) {
        macro_rules! from_le {
            ($ty: ty, $v: expr) => {
                {
                    let num_bytes = (<$ty>::BITS / 8) as usize;
                    let vc = self.bytes.chunks(num_bytes)
                        .filter(|x| x.len() == num_bytes)
                        .map(|x| <$ty>::from_le_bytes(x.try_into().unwrap())).collect_vec();
                    $v.borrow_mut()
                        .take()
                        .copy_from_slice(
                            &vc
                        )
                }
            };

            (u256, $ty: ty, $v: expr) => {
                {
                    let num_bytes = 32;
                    let vc = self.bytes.chunks(num_bytes)
                        .filter(|x| x.len() == num_bytes)
                        .map(|x| <$ty>::from_le_bytes(x.try_into().unwrap())).collect_vec();
                    $v.borrow_mut()
                        .take()
                        .copy_from_slice(
                            &vc
                        )
                }
            };
        }
        match &mut self.value.0 {
            ValueImpl::Container(v) => {
                match v {
                    Container::VecU8(vv) => {
                        vv.borrow_mut()
                            .take()
                            .copy_from_slice(&self.bytes)
                    }
                    Container::VecU64(vv) => {
                        from_le!(u64, vv)
                    }
                    Container::VecU128(v) => {
                        from_le!(u128, v)
                    }
                    Container::VecU16(v) => {
                        from_le!(u16, v)
                    }
                    Container::VecU32(v) => {
                        from_le!(u32, v)
                    }
                    Container::VecU256(v) => {
                        from_le!(u256, move_core_types::u256::U256, v)
                    }
                    // cant be mutated
                    _ => unreachable!()
                }
            }
            ValueImpl::U128(v) => {
                *v = u128::from_le_bytes(self.bytes.as_slice().try_into().unwrap())
            }
            ValueImpl::U256(v) => {
                *v = move_core_types::u256::U256::from_le_bytes(self.bytes.as_slice().try_into().unwrap())
            }
            // ValueImpl::ContainerRef(_) => {}
            // ValueImpl::IndexedRef(_) => {}
            _ => unreachable!()
        }
    }
}


macro_rules! mutate_by {
    ( $state: expr, $value: expr) => {
        {
            let res = byte_mutator($state, $value, Default::default());
            $value.commit();
            res
        }
    };
}
impl MoveFunctionInput {

    pub fn mutate_container<S>(
                               _state: &mut S,
                               container: &mut Container,
                               useful_value: &mut HashMap<Type, Vec<Value>>,
                               ty: &Type
    ) -> MutationResult
    where
        S: State
        + HasRand
        + HasMaxSize
        + HasItyState<ModuleId, AccountAddress, MoveVMState>
        + HasCaller<AccountAddress> + HasMetadata,
    {

        let mut value = CloneableValue::from(Value(
            ValueImpl::Container(container.clone())
        ));
        match container {
            Container::Locals(_) => {unreachable!("locals cant be mutated")}
            Container::Vec(v) => {unreachable!("wtf is this")}
            Container::Struct(ref mut v) => {
                match useful_value.get(&ty) {
                    None => {panic!("wtf")} // todo: fix this
                    Some(vs) => {
                        let nth = _state.rand_mut().below(vs.len() as u64);
                        if let ValueImpl::Container(Container::Struct(new_struct)) = vs[nth as usize].0.clone() {
                            *v.borrow_mut() = new_struct.clone();
                            return MutationResult::Mutated
                        } else {
                            panic!("wtf")
                        }
                    }
                }
            }
            Container::VecU8(_) => {mutate_by!( _state, &mut value)}
            Container::VecU64(_) => {mutate_by!( _state, &mut value)}
            Container::VecU128(_) => {mutate_by!( _state, &mut value)}
            Container::VecBool(_) => {todo!("bool")}
            Container::VecAddress(_) => {todo!("address")}
            Container::VecU16(_) => {mutate_by!( _state, &mut value)}
            Container::VecU32(_) => {mutate_by!( _state, &mut value)}
            Container::VecU256(_) => {mutate_by!( _state, &mut value)}
        }
    }

    pub fn mutate_value_impl<S>(&mut self, _state: &mut S, nth: usize, ty: &Type) -> MutationResult
        where
            S: State
            + HasRand
            + HasMaxSize
            + HasItyState<ModuleId, AccountAddress, MoveVMState>
            + HasCaller<AccountAddress> + HasMetadata,
    {
        macro_rules! mutate_u {
            ($ty: ty, $v: expr) => {
                {
                    let orig = $v;
                    while $v == orig {
                        $v = _state.rand_mut().below(<$ty>::MAX as u64) as $ty;
                    }
                    MutationResult::Mutated
                }
            };
        }

        enum MutateType<'a> {
            U128,
            U256,
            Container(&'a mut Container),
        }

        let further_mutation = match &mut self.args[nth].value.0 {
            ValueImpl::Invalid => {
                unreachable!()
            }
            // value level mutation
            ValueImpl::U8(mut v) => {
                return mutate_u!(u8, v);
            }
            ValueImpl::U16(mut v) => {
                return mutate_u!(u16, v);
            }
            ValueImpl::U32(mut v) => {
                return mutate_u!(u32, v);
            }
            ValueImpl::U64(mut v) => {
                return mutate_u!(u64, v);
            }
            ValueImpl::Bool(mut v) => {
                v=!v;
                return MutationResult::Mutated;
            }
            ValueImpl::Address(mut v) => {
                v = _state.get_rand_address();
                return MutationResult::Mutated;
            }
            ValueImpl::U128(_) => {
                MutateType::U128
                // return mutate_by!(_state, value);
            }
            ValueImpl::U256(_) => {
                MutateType::U256
                // return mutate_by!(_state, value);
            }
            ValueImpl::Container(ref mut cont) => {
                MutateType::Container(cont)
            }
            ValueImpl::ContainerRef(ref mut cont) => {
                match cont {
                    ContainerRef::Local(v) => {
                        MutateType::Container(v)
                    }
                    ContainerRef::Global { .. } => {unreachable!("global cant be mutated")}
                }
            }
            ValueImpl::IndexedRef(_) => {unreachable!("indexed ref cant be mutated")}
        };

        match further_mutation {
            MutateType::U128 => {
                mutate_by!( _state, &mut self.args[nth])
            }
            MutateType::U256 => {
                mutate_by!( _state, &mut self.args[nth])
            }
            MutateType::Container(cont) => {
                Self::mutate_container(_state, cont, &mut self.vm_state.state.useful_value, ty);
                return MutationResult::Mutated;
            }
        }


    }
}

impl VMInputT<MoveVMState, ModuleId, AccountAddress> for MoveFunctionInput {
    fn mutate<S>(&mut self, _state: &mut S) -> MutationResult
    where
        S: State
            + HasRand
            + HasMaxSize
            + HasItyState<ModuleId, AccountAddress, MoveVMState>
            + HasCaller<AccountAddress> + HasMetadata,
    {
        let nth = _state.rand_mut().below(self.args.len() as u64) as usize;
        let ty = self.function_info.get_function().parameter_types[nth].clone();
        self.mutate_value_impl(
            _state,
            nth,
            &ty,
        );


        MutationResult::Mutated
    }

    fn get_caller_mut(&mut self) -> &mut AccountAddress {
        &mut self.caller
    }

    fn get_caller(&self) -> AccountAddress {
        self.caller
    }

    fn set_caller(&mut self, caller: AccountAddress) {
        self.caller = caller;
    }

    fn get_contract(&self) -> AccountAddress {
        self.module.address().clone()
    }
    fn get_state(&self) -> &MoveVMState {
        &self.vm_state.state
    }

    fn get_state_mut(&mut self) -> &mut MoveVMState {
        &mut self.vm_state.state
    }

    fn set_staged_state(&mut self, state: MoveStagedVMState, idx: usize) {
        self.vm_state = state;
        self.vm_state_idx = idx;
    }
    fn get_state_idx(&self) -> usize {
        self.vm_state_idx
    }
    fn get_staged_state(&self) -> &MoveStagedVMState {
        &self.vm_state
    }

    // fn get_abi_cloned(&self) -> Option<BoxedABI>;
    fn set_as_post_exec(&mut self, _out_size: usize) {
        todo!()
    }

    fn is_step(&self) -> bool {
        todo!()
    }

    fn set_step(&mut self, _gate: bool) {
        todo!()
    }

    fn pretty_txn(&self) -> Option<String> {
        Some(format!(
            "{}::{}({:?})",
            self.module, self.function, self.args
        ))

    }
    fn as_any(&self) -> &dyn any::Any {
        self
    }

    fn fav_factor(&self) -> f64 {
        todo!()
    }

    #[cfg(feature = "evm")]
    fn get_data_abi(&self) -> Option<BoxedABI> {
        unreachable!("MoveVM does not have an ABI")
    }

    #[cfg(feature = "evm")]
    fn get_data_abi_mut(&mut self) -> &mut Option<BoxedABI> {
        unreachable!("MoveVM does not have an ABI")
    }

    #[cfg(feature = "evm")]
    fn get_txn_value_temp(&self) -> Option<U256> {
        unreachable!("MoveVM does not have an ABI")
    }

    #[cfg(any(test, feature = "reexecution"))]
    fn get_direct_data(&self) -> Vec<u8> {
        todo!()
    }
}
