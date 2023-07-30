use crate::evm::abi::BoxedABI;
use crate::input::{ConciseSerde, VMInputT};
use crate::r#move::types::MoveStagedVMState;
use crate::r#move::vm_state::{MoveVMState, MoveVMStateT};
use crate::state::{HasCaller, HasItyState};

use libafl::inputs::Input;
use libafl::prelude::{HasBytesVec, HasMaxSize, HasMetadata, MutationResult, Rand, State};
use libafl::state::HasRand;
use std::rc::Rc;
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::{ModuleId, TypeTag};

use move_vm_types::values::{Container, ContainerRef, IndexedRef, Value, ValueImpl};
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
use libafl::impl_serdeany;
use move_binary_format::file_format::AbilitySet;
use move_vm_runtime::loader::{Function, Module};
use move_vm_types::loaded_data::runtime_types::Type;
use crate::evm::types::EVMU256;
use crate::mutation_utils::byte_mutator;
use crate::r#move::movevm::MoveVM;
use crate::generic_vm::vm_executor::ExecutionResult;

pub trait MoveFunctionInputT {
    fn module_id(&self) -> &ModuleId;
    fn function_name(&self) -> &Identifier;
    fn args(&self) -> &Vec<CloneableValue>;
    fn ty_args(&self) -> &Vec<Type>;

    /// === helper functions ===

    /// Cache the struct dependencies of this function
    fn cache_deps(&mut self);

    /// Ensure the deps and deps_amount are satisfied with the current vm_state
    ///
    /// Check for each type in deps, if the number of values in value_to_drop and useful_value
    /// is greater than or equal to the corresponding amount in deps_amount.
    fn ensure_deps<VS>(&self, vm_state: &VS) -> bool
        where VS: MoveVMStateT;

    /// Slash all structs in the input, and sample from new vm_state
    ///
    /// This ensures all the structs in the input are valid!
    fn slash<S>(&mut self, state: &mut S)
        where S: HasMetadata + HasRand;


    /// Does the input have all its dependencies resolved?
    fn deps_resolved(&self) -> bool;
}

pub struct FunctionDefaultable {
    pub function: Option<Arc<Function>>
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

    pub fn new(function: Arc<Function>) -> Self {
        FunctionDefaultable {
            function: Some(function)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StructAbilities {
    pub abilities: HashMap<Type, AbilitySet>
}

impl StructAbilities {
    pub fn new() -> Self {
        StructAbilities {
            abilities: HashMap::new()
        }
    }

    pub fn get_ability(&self, ty: &Type) -> Option<&AbilitySet> {
        self.abilities.get(ty)
    }

    pub fn set_ability(&mut self, ty: Type, ability: AbilitySet) {
        self.abilities.insert(ty, ability);
    }
}

impl_serdeany!(StructAbilities);


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

    pub _deps: HashMap<Type, usize>,
    pub _resolved: bool,
}


#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ConciseMoveInput {
    pub module: ModuleId,
    pub function: Identifier,
    pub args: Vec<CloneableValue>,
    pub ty_args: Vec<Type>,
    pub caller: AccountAddress,
}


impl ConciseSerde for ConciseMoveInput {
    fn serialize_concise(&self) -> Vec<u8> {
        todo!()
    }

    fn deserialize_concise(data: &[u8]) -> Self {
        todo!()
    }

    fn serialize_string(&self) -> String {
        todo!()
    }
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


impl ConciseSerde for MoveFunctionInput {
    fn serialize_concise(&self) -> Vec<u8> {
        todo!()
    }

    fn deserialize_concise(data: &[u8]) -> Self {
        todo!()
    }

    fn serialize_string(&self) -> String {
        todo!()
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

    /// Record the deps and deps_amount of the current args
    fn cache_deps(&mut self) {
        for ty in self.function_info.get_function().parameter_types.clone() {
            self._cache_deps(&ty);
        }
    }

    /// Ensure the deps and deps_amount are satisfied with the current vm_state
    ///
    /// Check for each type in deps, if the number of values in value_to_drop and useful_value
    /// is greater than or equal to the corresponding amount in deps_amount.
    fn ensure_deps<VS>(&self, vm_state: &VS) -> bool
        where VS: MoveVMStateT {
        for (ty, amount) in &self._deps {
            let counts = match vm_state.get_value_to_drop().get(ty) {
                Some(v) => v.len(),
                None => 0
            } + match vm_state.get_useful_value().get(ty) {
                Some(v) => v.len(),
                None => 0
            };
            if counts < *amount {
                return false;
            }
        }
        true
    }

    /// Slash all structs in the input, and sample from new vm_state
    ///
    /// This ensures all the structs in the input are valid!
    fn slash<S>(&mut self, state: &mut S)
        where S: HasMetadata + HasRand
    {
        for (arg, ty) in self.args.iter_mut()
            .zip(self.function_info.get_function().parameter_types.iter()) {
            match ty {

                // If the final vector inner type is a struct, we need to slash it (clear all)
                Type::Vector(inner_ty) => {
                    let mut final_ty = (*inner_ty).clone();
                    while let Type::Vector(inner_ty) = (*final_ty) {
                        final_ty = inner_ty;
                    }
                    match *final_ty {
                        Type::Struct(_) | Type::MutableReference(_) | Type::Reference(_) => {
                            if let Value(ValueImpl::Container(Container::Vec(inner))) = &mut arg.value {
                                (**inner).borrow_mut().clear()
                            } else {
                                unreachable!("vector should be container")
                            }
                        }
                        _ => {}
                    }
                }
                // resample all the structs in the input
                Type::Struct(_) => {
                    let new_struct = self.vm_state.state.sample_value(state, ty, false);
                    arg.value = new_struct;
                }
                Type::Reference(inner_ty) | Type::MutableReference(inner_ty) => {
                    let new_struct = self.vm_state.state.sample_value(state, inner_ty.as_ref(), true);
                    arg.value = new_struct;
                }
                Type::StructInstantiation(_, _) => todo!("StructInstantiation"),
                _ => {}
            }

        }
    }

    fn deps_resolved(&self) -> bool {
        self._resolved
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
        &self.bytes
    }

    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }
}

impl CloneableValue {
    fn sync(&mut self) {
        macro_rules! leb_tns {
            ($v: expr) => {
                {
                    self.bytes = &$v.to_le_bytes().to_vec();
                }
            };
            (vec, $v: expr) => {
                {
                    self.bytes = $v.borrow().deref().iter().map(|x| x.to_le_bytes()).flatten().collect::<Vec<u8>>();
                }
            };
        }
        match &self.value.0 {
            ValueImpl::Container(v) => {
                match v {
                    Container::VecU8(v) => {
                        // println!("{:?}", v.borrow().deref());
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
            }
            ValueImpl::U256(v) => {
                self.bytes = v.to_le_bytes().to_vec();
            }
            // ValueImpl::ContainerRef(_) => {}
            // ValueImpl::IndexedRef(_) => {}
            _ => unreachable!()
        }
    }

    fn commit(&mut self) {
        macro_rules! from_le {
            ($ty: ty, $v: expr) => {
                {
                    let num_bytes = (<$ty>::BITS / 8) as usize;
                    let vc = self.bytes.chunks(num_bytes)
                        .filter(|x| x.len() == num_bytes)
                        .map(|x| <$ty>::from_le_bytes(x.try_into().unwrap())).collect_vec();
                    (*(*$v)).borrow_mut().copy_from_slice(vc.as_slice());
                }
            };

            (u256, $ty: ty, $v: expr) => {
                {
                    let num_bytes = 32;
                    let vc = self.bytes.chunks(num_bytes)
                        .filter(|x| x.len() == num_bytes)
                        .map(|x| <$ty>::from_le_bytes(x.try_into().unwrap())).collect_vec();
                    (*(*$v)).borrow_mut().copy_from_slice(vc.as_slice());
                }
            };
        }
        let r = match &mut self.value.0 {
            ValueImpl::Container(v) => {
                match v {
                    Container::VecU8(v) => {
                        from_le!(u8, v);
                    }
                    Container::VecU64(v) => {
                        from_le!(u64, v)
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
        };

        self.bytes.clear();
        r
    }
}


macro_rules! mutate_by {
    ( $state: expr, $value: expr) => {
        {
            $value.sync();
            let res = byte_mutator($state, $value, Default::default());
            $value.commit();
            res
        }
    };
}

pub const MOVE_MAX_VEC_SIZE: u64 = 10;

impl MoveFunctionInput {
    fn _cache_deps(&mut self, ty: &Type) {
        match ty {
            Type::Struct(t) => {
                match self._deps.get_mut(ty) {
                    Some(v) => {
                        *v += 1;
                    }
                    None => {
                        self._deps.insert(ty.clone(), 1);
                    }
                }
            }
            Type::StructInstantiation(_, _) => todo!("StructInstantiation"),
            Type::Reference(t) => {
                self._cache_deps(t.as_ref());
            }
            Type::MutableReference(t) => {
                self._cache_deps(t.as_ref());
            }
            _ => {}
        }
    }

    pub fn mutate_container<S>(
                               _state: &mut S,
                               container: &mut Container,
                               vm_state: &mut MoveVMState,
                               is_ref: bool,
                               ty: &Type,
    ) -> MutationResult
    where
        S: State
        + HasRand
        + HasMaxSize
        + HasItyState<ModuleId, AccountAddress, MoveVMState, ConciseMoveInput>
        + HasCaller<AccountAddress> + HasMetadata,
    {

        let mut value = CloneableValue::from(Value(
            ValueImpl::Container(container.clone())
        ));
        match container {
            Container::Locals(_) => {unreachable!("locals cant be mutated")}
            Container::Vec(v) => {unreachable!("wtf is this")}
            Container::Struct(ref mut v) => {
                vm_state.restock(
                    ty,
                    value.value,
                    is_ref,
                    _state
                );

                if let Value(ValueImpl::Container(Container::Struct(new_struct))) = vm_state.sample_value(
                    _state,
                    ty,
                    is_ref,
                ) {
                    *v.borrow_mut() = new_struct.clone();
                    return MutationResult::Mutated
                } else {
                    panic!("wtf")
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

    pub fn mutate_value_impl<S>(
        _state: &mut S,
        value: &mut CloneableValue,
        ty: Type,
        vm_state: &mut MoveVMState,
        is_ref: bool,
    ) -> MutationResult
        where
            S: State
            + HasRand
            + HasMaxSize
            + HasItyState<ModuleId, AccountAddress, MoveVMState, ConciseMoveInput>
            + HasCaller<AccountAddress> + HasMetadata,
    {
        macro_rules! mutate_u {
            ($ty: ty, $v: expr) => {
                {
                    let orig = *$v;
                    while *$v == orig {
                        *$v = _state.rand_mut().below(<$ty>::MAX as u64) as $ty;
                        // println!("mutate_u: {} {}", $v, orig);
                    }
                    MutationResult::Mutated
                }
            };
        }

        enum MutateType<'a> {
            U128,
            U256,
            Container(&'a mut Container, Type, bool),
            Indexed(&'a mut Container, usize),
        }

        let further_mutation = match value.value.0 {
            ValueImpl::Invalid => {
                unreachable!()
            }
            // value level mutation
            ValueImpl::U8(ref mut v) => {
                return mutate_u!(u8, v);
            }
            ValueImpl::U16(ref mut v) => {
                return mutate_u!(u16, v);
            }
            ValueImpl::U32(ref mut v) => {
                return mutate_u!(u32, v);
            }
            ValueImpl::U64(ref mut v) => {
                return mutate_u!(u64, v);
            }
            ValueImpl::Bool(ref mut v) => {
                *v=!*v;
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
                MutateType::Container(cont, ty.clone(), false)
            }
            ValueImpl::ContainerRef(ref mut cont) => {
                match cont {
                    ContainerRef::Local(v) => {
                        let inner_ty = if let Type::Reference(inner_ty) = ty.clone() {
                            *inner_ty
                        } else {
                            unreachable!("non mutable reference")
                        };
                        MutateType::Container(v, inner_ty, true)
                    }
                    ContainerRef::Global { .. } => {unreachable!("global cant be mutated")}
                }
            }
            ValueImpl::IndexedRef(ref mut cont) => {
                match &mut cont.container_ref {
                    ContainerRef::Local(vec_container) => {
                        // MutateType::Indexed(v, cont.idx)
                        MutateType::Indexed(vec_container, cont.idx)
                    }
                    ContainerRef::Global { .. } => {unreachable!("global cant be mutated")}
                }
            }
        };

        match further_mutation {
            MutateType::U128 => {
                mutate_by!( _state, value)
            }
            MutateType::U256 => {
                mutate_by!( _state, value)
            }
            MutateType::Container(cont, inner_ty,is_ref) => {
                Self::mutate_container(_state, cont,
                                       vm_state,
                                       is_ref,
                                       &inner_ty)
            }
            MutateType::Indexed(vec_container, index) => {
                match vec_container {
                    Container::Vec(inner_vec) => {
                        let inner_ty = if let Type::MutableReference(inner_ty) = ty{
                            *inner_ty
                        } else {
                            unreachable!("non mutable reference")
                        };

                        let mut mutable_value = CloneableValue::from(Value((**inner_vec).borrow().get(index).unwrap().clone()));
                        let res = Self::mutate_value_impl(
                            _state,
                            &mut mutable_value,
                            inner_ty,
                            vm_state,
                            true
                        );
                        (**inner_vec).borrow_mut()[index] = mutable_value.value.0.clone();
                        res
                    }
                    _ => unreachable!("wtf is this")
                }
            }
        }


    }
}

impl VMInputT<MoveVMState, ModuleId, AccountAddress, ConciseMoveInput> for MoveFunctionInput {
    fn mutate<S>(&mut self, _state: &mut S) -> MutationResult
    where
        S: State
            + HasRand
            + HasMaxSize
            + HasItyState<ModuleId, AccountAddress, MoveVMState, ConciseMoveInput>
            + HasCaller<AccountAddress> + HasMetadata,
    {
        let nth = _state.rand_mut().below(self.args.len() as u64) as usize;
        Self::mutate_value_impl(
            _state,
            &mut self.args[nth],
            self.function_info.get_function().parameter_types[nth].clone(),
            &mut self.vm_state.state,
            false
        )
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
    fn get_txn_value_temp(&self) -> Option<EVMU256> {
        unreachable!("MoveVM does not have an ABI")
    }

    fn get_direct_data(&self) -> Vec<u8> {
        todo!()
    }

    fn get_concise<Out: Default>(&self, exec_res: &ExecutionResult<ModuleId, AccountAddress, MoveVMState, Out, ConciseMoveInput>) -> ConciseMoveInput {
        ConciseMoveInput {
            module: self.module.clone(),
            function: self.function.clone(),
            args: self.args.clone(),
            ty_args: self.ty_args.clone(),
            caller: self.caller.clone(),
        }
    }
}


mod tests {
    use std::sync::Arc;
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;
    use move_core_types::language_storage::ModuleId;
    use move_core_types::u256;
    use move_vm_types::values::{Container, Value, ValueImpl, values_impl};
    use crate::input::VMInputT;
    use crate::r#move::input::{CloneableValue, FunctionDefaultable, MoveFunctionInput, MoveFunctionInputT, StructAbilities};
    use crate::r#move::types::MoveFuzzState;
    use crate::state::FuzzState;
    use crate::state_input::StagedVMState;
    use std::rc::Rc;
    use std::cell::RefCell;
    use move_vm_runtime::loader::{Function, Scope};
    use move_vm_types::loaded_data::runtime_types::{CachedStructIndex, Type};
    use crate::r#move::vm_state::MoveVMState;
    use std::collections::HashMap;
    use libafl::mutators::MutationResult;
    use libafl::prelude::HasMetadata;
    use move_binary_format::file_format::{Ability, AbilitySet};
    use crate::r#move::types::MoveStagedVMState;

    macro_rules! get_dummy_func {
        ($tys: expr) => {
            {
                let mut f = FunctionDefaultable::default();
                f.function = Some(
                    Arc::new(

                        Function {
                            file_format_version: 0,
                            index: Default::default(),
                            code: vec![],
                            parameters: Default::default(),
                            return_: Default::default(),
                            locals: Default::default(),
                            type_parameters: vec![],
                            native: None,
                            def_is_native: false,
                            def_is_friend_or_private: false,
                            scope: Scope::Module(ModuleId::new(AccountAddress::from([0; 32]), Identifier::new("test").unwrap())),
                            name: Identifier::new("test").unwrap(),
                            return_types: vec![],
                            local_types: vec![],
                            parameter_types: $tys,
                        }
                    )
                );
                f
            }
        };
        () => {
            get_dummy_func!(vec![])
        }
    }

    macro_rules! dummy_input {
        ($init_v: expr, $sstate: expr, $tys: expr) => {
            {
                let dummy_addr = AccountAddress::from([0; 32]);
                MoveFunctionInput {
                    module: ModuleId::new(dummy_addr.clone(), Identifier::new("test").unwrap()),
                    function: Identifier::new("test").unwrap(),
                    function_info: Arc::new(get_dummy_func!($tys)),
                    args: vec![
                        CloneableValue::from(Value(
                            $init_v.clone()
                        ))
                    ],
                    ty_args: vec![],
                    caller: dummy_addr,
                    vm_state: $sstate,
                    vm_state_idx: 0,
                    _deps: Default::default(),
                }
            }
        };

        ($init_v: expr, $tys: expr) => {
            dummy_input!($init_v, StagedVMState::new_uninitialized(), $tys)
        };
    }

    macro_rules! test_lb {
        ($init_v: expr, $tys: expr) => {
            let mut v = dummy_input!($init_v, $tys);
            v.mutate::<MoveFuzzState>(&mut Default::default());
            // println!("{:?}", v.args[0]);
            let o = (v.args[0].value.equals(&Value($init_v)).expect("failed to compare"));
            assert!(!o, "value was not mutated");
        };
        ($init_v: expr) => {
            test_lb!($init_v, vec![])
        };
    }
    #[test]
    fn test_integer() {
        test_lb!(ValueImpl::U8(0), vec![Type::U8]);
        test_lb!(ValueImpl::U16(0), vec![Type::U16]);
        test_lb!(ValueImpl::U32(0), vec![Type::U32]);
        test_lb!(ValueImpl::U64(0), vec![Type::U64]);
        test_lb!(ValueImpl::U128(0), vec![Type::U128]);
        test_lb!(ValueImpl::U256(u256::U256::zero()), vec![Type::U256]);
    }

    #[test]
    fn test_vec() {
        test_lb!(
            ValueImpl::Container(
                Container::VecU8(
                    Rc::new(RefCell::new(vec![2; 32]))
                )
            ),
            vec![Type::Vector(Box::new(Type::U8))]
        );

        test_lb!(
            ValueImpl::Container(
                Container::VecU64(
                    Rc::new(RefCell::new(vec![2; 32]))
                )
            ),
            vec![Type::Vector(Box::new(Type::U64))]
        );

        test_lb!(
            ValueImpl::Container(
                Container::VecU16(
                    Rc::new(RefCell::new(vec![2; 32]))
                )
            ),
            vec![Type::Vector(Box::new(Type::U16))]
        );

        test_lb!(
            ValueImpl::Container(
                Container::VecU32(
                    Rc::new(RefCell::new(vec![2; 32]))
                )
            ),
            vec![Type::Vector(Box::new(Type::U32))]
        );

        test_lb!(
            ValueImpl::Container(
                Container::VecU256(
                    Rc::new(RefCell::new(vec![u256::U256::zero(); 32]))
                )
            ),
            vec![Type::Vector(Box::new(Type::U256))]
        );
    }

    macro_rules! test_struct {
        ($init_v: expr, $tys: expr, $sstate: expr, $struct_abilities: expr) => {
            {
                let mut state: MoveFuzzState = Default::default();
                state.metadata_mut().insert($struct_abilities);

                let (v, res) = {
                    let mut v = dummy_input!($init_v, $sstate, $tys);
                    let res = v.mutate::<MoveFuzzState>(&mut state);
                    (v, res)
                };
                // println!("{:?}", v.args[0]);
                (res, Value($init_v), v.args[0].value.clone(), v.vm_state.clone())
            }
        };

    }

    #[test]
    fn test_struct() {
        let mut sstate = MoveStagedVMState::new_with_state(
            MoveVMState::new()
        );

        sstate.state.add_new_value(
            Value(ValueImpl::Container(
                Container::Struct(
                    Rc::new(RefCell::new(vec![
                        ValueImpl::U8(5),
                        ValueImpl::U8(5),
                    ]))
                )
            )),
            &Type::Struct(CachedStructIndex(1)),
            false,
        );

        let (mutation_result, init_v, mutated_v, vm_state) = test_struct!(
            ValueImpl::Container(
                Container::Struct(
                    Rc::new(RefCell::new(vec![
                        ValueImpl::U8(0),
                        ValueImpl::U8(0),
                    ]))
                )
            ),
            vec![Type::Struct(CachedStructIndex(1))],
            sstate,
            {
                let mut abilities = StructAbilities::new();
                abilities.set_ability(Type::Struct(CachedStructIndex(1)), AbilitySet(Ability::Copy as u8));
                abilities
            }
        );
        println!("initial value {:?}", init_v);
        println!("mutated value {:?}", mutated_v);
        println!("remaining value to drop {:?}", vm_state.state.value_to_drop);
        println!("remaining useful_value {:?}", vm_state.state.useful_value);
        println!("ref in use {:?}", vm_state.state.ref_in_use);
        assert_eq!(mutation_result, MutationResult::Mutated);
    }

    #[test]
    fn test_struct_ref() {
        let mut sstate = MoveStagedVMState::new_with_state(
            MoveVMState::new()
        );

        sstate.state.add_new_value(
            Value(ValueImpl::Container(
                Container::Struct(
                    Rc::new(RefCell::new(vec![
                        ValueImpl::U8(5),
                        ValueImpl::U8(5),
                    ]))
                )
            )),
            &Type::Struct(CachedStructIndex(1)),
            false,
        );
        sstate.state.ref_in_use.push(
            (
                Type::Struct(CachedStructIndex(1)),
                Value(
                    ValueImpl::Container(
                        Container::Struct(
                            Rc::new(RefCell::new(vec![
                                ValueImpl::U8(0),
                                ValueImpl::U8(0),
                            ]))
                        )
                    )
                )
            )
        );

        let (mutation_result, init_v, mutated_v, vm_state) = test_struct!(
            ValueImpl::ContainerRef(
                values_impl::ContainerRef::Local(
                    Container::Struct(
                        Rc::new(RefCell::new(vec![
                            ValueImpl::U8(0),
                            ValueImpl::U8(0),
                        ]))
                    )
                )
            ),
            vec![Type::Reference(Box::new(Type::Struct(CachedStructIndex(1))))],
            sstate,
            {
                let mut abilities = StructAbilities::new();
                abilities.set_ability(Type::Struct(CachedStructIndex(1)), AbilitySet(Ability::Copy as u8));
                abilities
            }
        );
        println!("initial value {:?}", init_v);
        println!("mutated value {:?}", mutated_v);
        println!("remaining value to drop {:?}", vm_state.state.value_to_drop);
        println!("remaining useful_value {:?}", vm_state.state.useful_value);
        println!("ref in use {:?}", vm_state.state.ref_in_use);
        assert!(vm_state.state.ref_in_use.len() > 0);
        assert_eq!(mutation_result, MutationResult::Mutated);
    }

    #[test]
    fn test_slash() {
        let mut sstate = MoveStagedVMState::new_with_state(
            MoveVMState::new()
        );
        sstate.state.add_new_value(
            Value(ValueImpl::Container(
                Container::Struct(
                    Rc::new(RefCell::new(vec![
                        ValueImpl::U8(123),
                        ValueImpl::U8(123),
                    ]))
                )
            )),
            &Type::Struct(CachedStructIndex(1)),
            false,
        );

        let mut inp = dummy_input!(
            ValueImpl::ContainerRef(
                values_impl::ContainerRef::Local(
                    Container::Struct(
                        Rc::new(RefCell::new(vec![
                            ValueImpl::U8(0),
                            ValueImpl::U8(0),
                        ]))
                    )
                )
            ),
            sstate,
            vec![Type::Reference(Box::new(Type::Struct(CachedStructIndex(1))))]
        );
        inp.slash(&mut MoveFuzzState::default());
        println!("{:?}", inp.args[0].value);
    }

    #[test]
    fn test_slash_vec() {
        let mut sstate = MoveStagedVMState::new_with_state(
            MoveVMState::new()
        );
        sstate.state.add_new_value(
            Value(ValueImpl::Container(
                Container::Struct(
                    Rc::new(RefCell::new(vec![
                        ValueImpl::U8(123),
                        ValueImpl::U8(123),
                    ]))
                )
            )),
            &Type::Struct(CachedStructIndex(1)),
            false,
        );

        let mut inp = dummy_input!(
            ValueImpl::Container(
                Container::Vec(
                    Rc::new(RefCell::new(
                        vec![ValueImpl::ContainerRef(
                            values_impl::ContainerRef::Local(
                                Container::Struct(
                                    Rc::new(RefCell::new(vec![
                                        ValueImpl::U8(0),
                                        ValueImpl::U8(0),
                                    ]))
                                )
                            )
                        )]
                    ))
                )
            ),
            sstate,
            vec![Type::Vector(Box::new(Type::Reference(Box::new(Type::Struct(CachedStructIndex(1))))))]
        );
        inp.slash(&mut MoveFuzzState::default());
        assert!(
            inp.args[0].value.equals(
                &Value(
                    ValueImpl::Container(Container::Vec(Rc::new(RefCell::new(vec![]))))
                )
            ).expect("equals")

        )
    }


}

