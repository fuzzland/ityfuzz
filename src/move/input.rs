use std::{any, borrow::BorrowMut, cell::RefCell, collections::HashMap, fmt::Debug, ops::Deref, rc::Rc, sync::Arc};

use itertools::Itertools;
use libafl::{
    inputs::Input,
    prelude::{HasBytesVec, HasMaxSize, HasMetadata, MutationResult, State},
    state::HasRand,
};
use libafl_bolts::{impl_serdeany, prelude::Rand};
use move_binary_format::file_format::AbilitySet;
use move_core_types::{account_address::AccountAddress, identifier::Identifier, language_storage::ModuleId};
use move_vm_runtime::loader::Function;
use move_vm_types::{
    loaded_data::runtime_types::Type,
    values::{Container, ContainerRef, IndexedRef, Value, ValueImpl},
};
use serde::{Deserialize, Serialize};

use super::input_printer::print_value;
use crate::{
    evm::{abi::BoxedABI, types::EVMU256},
    generic_vm::vm_executor::ExecutionResult,
    input::{ConciseSerde, SolutionTx, VMInputT},
    mutation_utils::byte_mutator,
    r#move::{
        movevm::TypeTagInfoMeta,
        types::MoveStagedVMState,
        vm_state::{Gate, MoveVMState, MoveVMStateT},
    },
    state::{HasCaller, HasItyState},
};

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
    /// Check for each type in deps, if the number of values in value_to_drop
    /// and useful_value is greater than or equal to the corresponding
    /// amount in deps_amount.
    fn ensure_deps<VS>(&self, vm_state: &VS) -> bool
    where
        VS: MoveVMStateT;

    /// Slash all structs in the input, and sample from new vm_state
    ///
    /// This ensures all the structs in the input are valid!
    fn slash<S>(&mut self, state: &mut S)
    where
        S: HasMetadata + HasRand;

    fn set_resolved(&mut self);

    fn get_resolved(&self) -> bool;
}

#[derive(Default)]
pub struct FunctionDefaultable {
    pub function: Option<Arc<Function>>,
}

impl FunctionDefaultable {
    pub fn get_function(&self) -> &Function {
        self.function.as_ref().unwrap()
    }

    pub fn new(function: Arc<Function>) -> Self {
        FunctionDefaultable {
            function: Some(function),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StructAbilities {
    pub abilities: HashMap<Type, AbilitySet>,
}

impl Default for StructAbilities {
    fn default() -> Self {
        Self::new()
    }
}

impl StructAbilities {
    pub fn new() -> Self {
        StructAbilities {
            abilities: HashMap::new(),
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

    #[serde(skip_serializing, skip_deserializing)]
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
        serde_json::to_vec(self).expect("Failed to deserialize concise input")
    }

    fn deserialize_concise(data: &[u8]) -> Self {
        serde_json::from_slice(data).expect("Failed to deserialize concise input")
    }

    fn serialize_string(&self) -> String {
        let mut res = format!("{:?} => {}::{}", self.caller, self.module, self.function);
        if !self.ty_args.is_empty() {
            res.push_str(format!("<{}>", self.ty_args.iter().map(|ty| format!("{:?}", ty)).join(",")).as_str())
        }
        res.push_str(format!("({})", self.args.iter().map(|arg| print_value(&arg.value)).join(", ")).as_str());

        res
    }
}

impl SolutionTx for ConciseMoveInput {}

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

    fn deserialize_concise(_data: &[u8]) -> Self {
        todo!()
    }

    fn serialize_string(&self) -> String {
        todo!()
    }
}

#[derive(Debug, Serialize, Deserialize)]
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

pub fn convert_ref(value: Value) -> Value {
    match value.0 {
        ValueImpl::Invalid => unreachable!("Invalid value"),
        ValueImpl::Container(container) => Value(ValueImpl::ContainerRef(ContainerRef::Local(container))),
        _ => Value(ValueImpl::IndexedRef(IndexedRef {
            idx: 0,
            container_ref: ContainerRef::Local(Container::Locals(Rc::new(RefCell::new(vec![value.0])))),
        })),
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
    /// Check for each type in deps, if the number of values in value_to_drop
    /// and useful_value is greater than or equal to the corresponding
    /// amount in deps_amount.
    fn ensure_deps<VS>(&self, vm_state: &VS) -> bool
    where
        VS: MoveVMStateT,
    {
        for (ty, amount) in &self._deps {
            let counts = match vm_state.values().get(ty) {
                Some(v) => v.len(),
                None => 0,
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
    where
        S: HasMetadata + HasRand,
    {
        for (arg, ty) in self
            .args
            .iter_mut()
            .zip(self.function_info.get_function().parameter_types.iter())
        {
            if state
                .metadata_map()
                .get::<TypeTagInfoMeta>()
                .expect("type tag info")
                .is_tx_context(ty)
            {
                continue;
            }

            // debug!("Slash arg {:?} with type {:?}", arg, ty);
            match ty {
                // If the final vector inner type is a struct, we need to slash it (clear all)
                Type::Vector(inner_ty) => {
                    let mut final_ty = (*inner_ty).clone();
                    while let Type::Vector(inner_ty) = *final_ty {
                        final_ty = inner_ty;
                    }
                    match *final_ty {
                        Type::Struct(_) |
                        Type::StructInstantiation(_, _) |
                        Type::MutableReference(_) |
                        Type::Reference(_) => {
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
                Type::Struct(_) | Type::StructInstantiation(_, _) => {
                    let new_struct = self.vm_state.state.sample_value(state, ty, &Gate::Own);
                    arg.value = new_struct;
                }
                Type::Reference(inner_ty) => {
                    let new_struct = self.vm_state.state.sample_value(state, inner_ty.as_ref(), &Gate::Ref);
                    arg.value = convert_ref(new_struct);
                }
                Type::MutableReference(inner_ty) => {
                    let new_struct = self
                        .vm_state
                        .state
                        .sample_value(state, inner_ty.as_ref(), &Gate::MutRef);
                    arg.value = convert_ref(new_struct);
                }
                _ => {}
            }
        }
    }

    fn set_resolved(&mut self) {
        self._resolved = true;
    }

    fn get_resolved(&self) -> bool {
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
            ($v: expr) => {{
                self.bytes = &$v.to_le_bytes().to_vec();
            }};
            (vec, $v: expr) => {{
                self.bytes = $v
                    .borrow()
                    .deref()
                    .iter()
                    .map(|x| x.to_le_bytes())
                    .flatten()
                    .collect::<Vec<u8>>();
            }};
        }
        match &self.value.0 {
            ValueImpl::Container(v) => {
                match v {
                    Container::VecU8(v) => {
                        // debug!("{:?}", v.borrow().deref());
                        leb_tns!(vec, v)
                    }
                    Container::VecU64(v) => leb_tns!(vec, v),
                    Container::VecU128(v) => leb_tns!(vec, v),
                    Container::VecU16(v) => leb_tns!(vec, v),
                    Container::VecU32(v) => leb_tns!(vec, v),
                    Container::VecU256(v) => leb_tns!(vec, v),
                    // cant be mutated
                    _ => unreachable!(),
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
            _ => unreachable!(),
        }
    }

    fn commit(&mut self) {
        macro_rules! from_le {
            ($ty: ty, $v: expr) => {{
                let num_bytes = (<$ty>::BITS / 8) as usize;
                let vc = self
                    .bytes
                    .chunks(num_bytes)
                    .filter(|x| x.len() == num_bytes)
                    .map(|x| <$ty>::from_le_bytes(x.try_into().unwrap()))
                    .collect_vec();
                (*(*$v)).borrow_mut().copy_from_slice(vc.as_slice());
            }};

            (u256, $ty: ty, $v: expr) => {{
                let num_bytes = 32;
                let vc = self
                    .bytes
                    .chunks(num_bytes)
                    .filter(|x| x.len() == num_bytes)
                    .map(|x| <$ty>::from_le_bytes(x.try_into().unwrap()))
                    .collect_vec();
                (*(*$v)).borrow_mut().copy_from_slice(vc.as_slice());
            }};
        }
        match &mut self.value.0 {
            ValueImpl::Container(v) => match v {
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
                _ => unreachable!(),
            },
            ValueImpl::U128(v) => *v = u128::from_le_bytes(self.bytes.as_slice().try_into().unwrap()),
            ValueImpl::U256(v) => {
                *v = move_core_types::u256::U256::from_le_bytes(self.bytes.as_slice().try_into().unwrap())
            }
            _ => unreachable!(),
        };

        self.bytes.clear();
    }
}

macro_rules! mutate_by {
    ( $state: expr, $value: expr) => {{
        $value.sync();
        let res = byte_mutator($state, $value, Default::default());
        $value.commit();
        res
    }};
}

pub const MOVE_MAX_VEC_SIZE: u64 = 10;

impl MoveFunctionInput {
    fn _cache_deps(&mut self, ty: &Type) {
        match ty {
            Type::Struct(_t) => match self._deps.get_mut(ty) {
                Some(v) => {
                    *v += 1;
                }
                None => {
                    self._deps.insert(ty.clone(), 1);
                }
            },
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
        ref_ty: &Gate,
        ty: &Type,
        is_resolved: bool,
    ) -> MutationResult
    where
        S: State
            + HasRand
            + HasMaxSize
            + HasItyState<ModuleId, AccountAddress, MoveVMState, ConciseMoveInput>
            + HasCaller<AccountAddress>
            + HasMetadata,
    {
        let mut value = CloneableValue::from(Value(ValueImpl::Container(container.clone())));
        match container {
            Container::Locals(_) => {
                unreachable!("locals cant be mutated")
            }
            Container::Vec(_v) => {
                unreachable!("wtf is this")
            }
            Container::Struct(ref mut v) => {
                // debug!("vm_state.sample_value(is_resolved:{}, value:{:?}) {:?} for {:?}",
                // is_resolved, value, vm_state, ty); resolved structs shall be
                // returned to the vm state
                if is_resolved {
                    // debug!("returing resolved struct to vm state {:?} for {:?}", value, ref_ty);
                    vm_state.restock_struct(ty, value.value, ref_ty, _state);
                }
                if let Value(ValueImpl::Container(Container::Struct(new_struct))) =
                    vm_state.sample_value(_state, ty, ref_ty)
                {
                    *v.borrow_mut() = new_struct.clone();
                    MutationResult::Mutated
                } else {
                    panic!("wtf")
                }
            }
            Container::VecU8(_) => {
                mutate_by!(_state, &mut value)
            }
            Container::VecU64(_) => {
                mutate_by!(_state, &mut value)
            }
            Container::VecU128(_) => {
                mutate_by!(_state, &mut value)
            }
            Container::VecBool(_) => {
                todo!("bool")
            }
            Container::VecAddress(_) => {
                todo!("address")
            }
            Container::VecU16(_) => {
                mutate_by!(_state, &mut value)
            }
            Container::VecU32(_) => {
                mutate_by!(_state, &mut value)
            }
            Container::VecU256(_) => {
                mutate_by!(_state, &mut value)
            }
        }
    }

    pub fn mutate_value_impl<S>(
        _state: &mut S,
        value: &mut CloneableValue,
        ty: Type,
        vm_state: &mut MoveVMState,
        ref_ty: &Gate,
        is_resolved: bool,
    ) -> MutationResult
    where
        S: State
            + HasRand
            + HasMaxSize
            + HasItyState<ModuleId, AccountAddress, MoveVMState, ConciseMoveInput>
            + HasCaller<AccountAddress>
            + HasMetadata,
    {
        macro_rules! mutate_u {
            ($ty: ty, $v: expr) => {{
                let orig = *$v;
                while *$v == orig {
                    *$v = _state.rand_mut().below(<$ty>::MAX as u64) as $ty;
                    // debug!("mutate_u: {} {}", $v, orig);
                }
                MutationResult::Mutated
            }};
        }

        enum MutateType<'a> {
            U128,
            U256,
            Container(&'a mut Container, Type, Gate),
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
                *v = !*v;
                return MutationResult::Mutated;
            }
            ValueImpl::Address(mut _v) => {
                _v = _state.get_rand_address();
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
            ValueImpl::Container(ref mut cont) => MutateType::Container(cont, ty.clone(), ref_ty.clone()),
            ValueImpl::ContainerRef(ref mut cont) => {
                match cont {
                    ContainerRef::Local(v) => {
                        let mut gate = Gate::Ref;
                        let inner_ty = if let Type::Reference(inner_ty) = ty.clone() {
                            *inner_ty
                        } else if let Type::MutableReference(inner_ty) = ty.clone() {
                            gate = Gate::MutRef;
                            *inner_ty
                        } else {
                            unreachable!("not a reference")
                        };
                        // debug!("mutating container ref {:?} {:?} {:?}", v, inner_ty, gate);
                        MutateType::Container(v, inner_ty, gate)
                    }
                    ContainerRef::Global { .. } => {
                        unreachable!("global cant be mutated")
                    }
                }
            }
            ValueImpl::IndexedRef(ref mut cont) => {
                match &mut cont.container_ref {
                    ContainerRef::Local(vec_container) => {
                        // MutateType::Indexed(v, cont.idx)
                        MutateType::Indexed(vec_container, cont.idx)
                    }
                    ContainerRef::Global { .. } => {
                        unreachable!("global cant be mutated")
                    }
                }
            }
        };

        match further_mutation {
            MutateType::U128 => {
                mutate_by!(_state, value)
            }
            MutateType::U256 => {
                mutate_by!(_state, value)
            }
            MutateType::Container(cont, inner_ty, ref_ty) => {
                Self::mutate_container(_state, cont, vm_state, &ref_ty, &inner_ty, is_resolved)
            }
            MutateType::Indexed(vec_container, index) => match vec_container {
                Container::Vec(inner_vec) => {
                    let inner_ty = if let Type::MutableReference(inner_ty) = ty {
                        *inner_ty
                    } else {
                        unreachable!("non mutable reference")
                    };

                    let mut mutable_value =
                        CloneableValue::from(Value((*inner_vec).borrow().get(index).unwrap().clone()));
                    let res = Self::mutate_value_impl(
                        _state,
                        &mut mutable_value,
                        inner_ty,
                        vm_state,
                        &Gate::MutRef,
                        is_resolved,
                    );
                    (**inner_vec).borrow_mut()[index] = mutable_value.value.0.clone();
                    res
                }
                _ => unreachable!("wtf is this"),
            },
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
            + HasCaller<AccountAddress>
            + HasMetadata,
    {
        if self.function_info.get_function().parameter_types.is_empty() {
            return MutationResult::Skipped;
        }
        let nth = _state.rand_mut().below(self.args.len() as u64) as usize;
        let ty = self.function_info.get_function().parameter_types[nth].clone();
        if _state
            .metadata_map()
            .get::<TypeTagInfoMeta>()
            .expect("type tag info")
            .is_tx_context(&ty)
        {
            return MutationResult::Skipped;
        }

        // debug!("mutating arg!!!! {:?} {:?}", self.args[nth], ty.clone());

        // debug!("after mutating arg!!!! {:?}", self.args[nth]);
        Self::mutate_value_impl(
            _state,
            &mut self.args[nth],
            ty,
            &mut self.vm_state.state,
            &Gate::Own,
            self._resolved,
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

    fn set_origin(&mut self, _origin: AccountAddress) {
        todo!()
    }

    fn get_origin(&self) -> AccountAddress {
        todo!()
    }

    fn get_contract(&self) -> AccountAddress {
        *self.module.address()
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
        f64::MAX
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

    fn get_concise<Out: Default + Into<Vec<u8>> + Clone>(
        &self,
        _exec_res: &ExecutionResult<ModuleId, AccountAddress, MoveVMState, Out, ConciseMoveInput>,
    ) -> ConciseMoveInput {
        ConciseMoveInput {
            module: self.module.clone(),
            function: self.function.clone(),
            args: self.args.clone(),
            ty_args: self.ty_args.clone(),
            caller: self.caller,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc, sync::Arc};

    use libafl::{mutators::MutationResult, prelude::HasMetadata};
    use move_core_types::{account_address::AccountAddress, identifier::Identifier, language_storage::ModuleId, u256};
    use move_vm_runtime::loader::Function;
    use move_vm_types::{
        loaded_data::runtime_types::{CachedStructIndex, Type},
        values::{values_impl, Container, Value, ValueImpl},
    };
    use tracing::debug;

    use crate::{
        input::VMInputT,
        r#move::{
            input::{CloneableValue, FunctionDefaultable, MoveFunctionInput, MoveFunctionInputT, StructAbilities},
            movevm::{self, TypeTagInfoMeta},
            types::{MoveFuzzState, MoveStagedVMState},
            vm_state::{Gate, GatedValue, MoveVMState},
        },
        state_input::StagedVMState,
    };

    macro_rules! get_dummy_func {
        ($tys: expr) => {{
            let mut f = FunctionDefaultable::default();
            f.function = Some(Arc::new(Function::new_dummy($tys)));
            f
        }};
        () => {
            get_dummy_func!(vec![])
        };
    }

    macro_rules! dummy_input {
        ($init_v: expr, $sstate: expr, $tys: expr) => {{
            let dummy_addr = AccountAddress::ZERO;
            MoveFunctionInput {
                module: ModuleId::new(dummy_addr.clone(), Identifier::new("test").unwrap()),
                function: Identifier::new("test").unwrap(),
                function_info: Arc::new(get_dummy_func!($tys)),
                args: vec![CloneableValue::from(Value($init_v.clone()))],
                ty_args: vec![],
                caller: dummy_addr,
                vm_state: $sstate,
                vm_state_idx: 0,
                _deps: Default::default(),
                _resolved: true,
            }
        }};

        ($init_v: expr, $tys: expr) => {
            dummy_input!($init_v, StagedVMState::new_uninitialized(), $tys)
        };
    }

    macro_rules! test_lb {
        ($init_v: expr, $tys: expr) => {
            let mut state = MoveFuzzState::new(0);
            state.metadata_map_mut().insert(TypeTagInfoMeta::new());

            let mut v = dummy_input!($init_v, $tys);
            v.mutate::<MoveFuzzState>(&mut state);
            // debug!("{:?}", v.args[0]);
            let o = (v.args[0]
                .value
                .equals(&Value($init_v))
                .expect("failed to compare"));
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
            ValueImpl::Container(Container::VecU8(Rc::new(RefCell::new(vec![2; 32])))),
            vec![Type::Vector(Box::new(Type::U8))]
        );

        test_lb!(
            ValueImpl::Container(Container::VecU64(Rc::new(RefCell::new(vec![2; 32])))),
            vec![Type::Vector(Box::new(Type::U64))]
        );

        test_lb!(
            ValueImpl::Container(Container::VecU16(Rc::new(RefCell::new(vec![2; 32])))),
            vec![Type::Vector(Box::new(Type::U16))]
        );

        test_lb!(
            ValueImpl::Container(Container::VecU32(Rc::new(RefCell::new(vec![2; 32])))),
            vec![Type::Vector(Box::new(Type::U32))]
        );

        test_lb!(
            ValueImpl::Container(Container::VecU256(Rc::new(RefCell::new(vec![u256::U256::zero(); 32])))),
            vec![Type::Vector(Box::new(Type::U256))]
        );
    }

    macro_rules! test_struct {
        ($init_v: expr, $tys: expr, $sstate: expr, $struct_abilities: expr, $state: expr) => {{
            let (v, res) = {
                let mut v = dummy_input!($init_v, $sstate, $tys);
                let res = v.mutate::<MoveFuzzState>($state);
                (v, res)
            };
            // debug!("{:?}", v.args[0]);
            (res, Value($init_v), v.args[0].value.clone(), v.vm_state.clone())
        }};
    }

    #[test]
    fn test_struct() {
        let mut sstate = MoveStagedVMState::new_with_state(MoveVMState::new());

        let value = GatedValue {
            v: Value(ValueImpl::Container(Container::Struct(Rc::new(RefCell::new(vec![
                ValueImpl::U8(5),
                ValueImpl::U8(5),
            ]))))),
            gate: Gate::Own,
        };

        let mut state = setup_state();
        sstate_add_new_value(&mut sstate, &mut state, value, &Type::Struct(CachedStructIndex(0)));

        let (mutation_result, init_v, mutated_v, vm_state) = test_struct!(
            ValueImpl::Container(Container::Struct(Rc::new(RefCell::new(vec![
                ValueImpl::U8(0),
                ValueImpl::U8(0),
            ])))),
            vec![Type::Struct(CachedStructIndex(0))],
            sstate,
            {
                let mut abilities = StructAbilities::new();
                abilities.set_ability(Type::Struct(CachedStructIndex(0)), AbilitySet(Ability::Copy as u8));
                abilities
            },
            &mut state
        );
        debug!("initial value {:?}", init_v);
        debug!("mutated value {:?}", mutated_v);
        debug!("ref in use {:?}", vm_state.state.ref_in_use);
        assert_eq!(mutation_result, MutationResult::Mutated);
    }

    #[test]
    fn test_struct_ref() {
        let mut sstate = MoveStagedVMState::new_with_state(MoveVMState::new());

        let value = GatedValue {
            v: Value(ValueImpl::Container(Container::Struct(Rc::new(RefCell::new(vec![
                ValueImpl::U8(5),
                ValueImpl::U8(5),
            ]))))),
            gate: Gate::Own,
        };

        let mut state = setup_state();
        sstate_add_new_value(&mut sstate, &mut state, value, &Type::Struct(CachedStructIndex(0)));

        let new_value = GatedValue {
            v: Value(ValueImpl::Container(Container::Struct(Rc::new(RefCell::new(vec![
                ValueImpl::U8(0),
                ValueImpl::U8(0),
            ]))))),
            gate: Gate::Ref,
        };
        sstate
            .state
            .ref_in_use
            .push((Type::Struct(CachedStructIndex(0)), new_value));

        let (mutation_result, init_v, mutated_v, vm_state) = test_struct!(
            ValueImpl::ContainerRef(values_impl::ContainerRef::Local(Container::Struct(Rc::new(
                RefCell::new(vec![ValueImpl::U8(0), ValueImpl::U8(0),])
            )))),
            vec![Type::Reference(Box::new(Type::Struct(CachedStructIndex(0))))],
            sstate,
            {
                let mut abilities = StructAbilities::new();
                abilities.set_ability(Type::Struct(CachedStructIndex(0)), AbilitySet(Ability::Copy as u8));
                abilities
            },
            &mut state
        );
        debug!("initial value {:?}", init_v);
        debug!("mutated value {:?}", mutated_v);
        debug!("ref in use {:?}", vm_state.state.ref_in_use);
        assert!(!vm_state.state.ref_in_use.is_empty());
        assert_eq!(mutation_result, MutationResult::Mutated);
    }

    #[test]
    fn test_slash() {
        let mut sstate = MoveStagedVMState::new_with_state(MoveVMState::new());

        let value = GatedValue {
            v: Value(ValueImpl::Container(Container::Struct(Rc::new(RefCell::new(vec![
                ValueImpl::U8(123),
                ValueImpl::U8(123),
            ]))))),
            gate: Gate::Own,
        };

        let mut state = setup_state();
        sstate_add_new_value(&mut sstate, &mut state, value, &Type::Struct(CachedStructIndex(0)));

        let mut inp = dummy_input!(
            ValueImpl::ContainerRef(values_impl::ContainerRef::Local(Container::Struct(Rc::new(
                RefCell::new(vec![ValueImpl::U8(0), ValueImpl::U8(0),])
            )))),
            sstate,
            vec![Type::Reference(Box::new(Type::Struct(CachedStructIndex(0))))]
        );
        inp.slash(&mut state);
        debug!("{:?}", inp.args[0].value);
    }

    #[test]
    fn test_slash_vec() {
        let mut sstate = MoveStagedVMState::new_with_state(MoveVMState::new());

        let value = GatedValue {
            v: Value(ValueImpl::Container(Container::Struct(Rc::new(RefCell::new(vec![
                ValueImpl::U8(123),
                ValueImpl::U8(123),
            ]))))),
            gate: Gate::Own,
        };

        let mut state = setup_state();
        sstate_add_new_value(&mut sstate, &mut state, value, &Type::Struct(CachedStructIndex(0)));

        let mut inp = dummy_input!(
            ValueImpl::Container(Container::Vec(Rc::new(RefCell::new(vec![ValueImpl::ContainerRef(
                values_impl::ContainerRef::Local(Container::Struct(Rc::new(RefCell::new(vec![
                    ValueImpl::U8(0),
                    ValueImpl::U8(0),
                ]))))
            )])))),
            sstate,
            vec![Type::Vector(Box::new(Type::Reference(Box::new(Type::Struct(
                CachedStructIndex(0)
            )))))]
        );
        inp.slash(&mut state);
        assert!(inp.args[0]
            .value
            .equals(&Value(ValueImpl::Container(Container::Vec(Rc::new(RefCell::new(
                vec![]
            ))))))
            .expect("equals"))
    }

    fn setup_state() -> MoveFuzzState {
        let mut state = MoveFuzzState::new(0);
        state.metadata_map_mut().insert(TypeTagInfoMeta::new());
        state.metadata_map_mut().insert(StructAbilities::new());
        state
    }

    fn sstate_add_new_value(sstate: &mut MoveStagedVMState, state: &mut MoveFuzzState, value: GatedValue, ty: &Type) {
        let loader = movevm::dummy_loader(state);
        let resolver = movevm::dummy_resolver(&loader);
        sstate.state.add_new_value(value, ty, &resolver, state);
    }
}
