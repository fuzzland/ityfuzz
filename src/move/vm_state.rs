use std::{
    any::Any,
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
};

use libafl::{prelude::HasMetadata, state::HasRand};
use libafl_bolts::prelude::Rand;
use move_binary_format::errors::{PartialVMResult, VMResult};
use move_core_types::{
    account_address::AccountAddress,
    effects::Op,
    gas_algebra::NumBytes,
    identifier::IdentStr,
    language_storage::ModuleId,
    value::MoveTypeLayout,
};
use move_vm_runtime::loader::Resolver;
use move_vm_types::{
    data_store::DataStore,
    loaded_data::runtime_types::Type,
    values::{Container, ContainerRef, GlobalValue, Value, ValueImpl},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tracing::debug;

use crate::{
    generic_vm::vm_state::VMStateT,
    r#move::{input::StructAbilities, movevm::TypeTagInfoMeta},
};

pub trait MoveVMStateT {
    fn values(&self) -> &HashMap<Type, Vec<(GatedValue, usize)>>;

    /// Called after each time the function is called, we should return all
    /// values that are borrowed as reference / mutable reference from the
    /// vm_state.
    fn finished_call<S>(&mut self, state: &mut S)
    where
        S: HasMetadata;
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Gate {
    Ref = 0,
    MutRef = 1,
    Own = 2,
}

impl Gate {
    pub fn satisfied_by(&self, other: &Self) -> bool {
        match self {
            Gate::Ref => true,
            Gate::MutRef => *other == Gate::Own || *other == Gate::MutRef,
            Gate::Own => *other == Gate::Own,
        }
    }

    pub fn is_ref(&self) -> bool {
        *self == Gate::Ref || *self == Gate::MutRef
    }
}

#[derive(Debug, Clone)]
pub struct GatedValue {
    pub v: Value,
    pub gate: Gate,
}

impl GatedValue {
    pub fn equals(&self, other: &Self) -> PartialVMResult<bool> {
        Ok(self.v.equals(&other.v)? && self.gate == other.gate)
    }
}

#[derive(Debug, Default)]
pub struct MoveVMState {
    pub resources: HashMap<AccountAddress, HashMap<Type, Value>>,
    pub _gv_slot: HashMap<(AccountAddress, Type), GlobalValue>,
    pub _hot_potato: usize,

    pub values: HashMap<Type, Vec<(GatedValue, usize)>>,

    pub typed_bug: Vec<String>,

    pub ref_in_use: Vec<(Type, GatedValue)>,
}

impl MoveVMStateT for MoveVMState {
    fn values(&self) -> &HashMap<Type, Vec<(GatedValue, usize)>> {
        &self.values
    }

    /// Called after each time the function is called, we should return all
    /// values that are borrowed as reference / mutable reference from the
    /// vm_state.
    fn finished_call<S>(&mut self, state: &mut S)
    where
        S: HasMetadata,
    {
        for (t, v) in self.ref_in_use.clone() {
            // we'll clear the ref_in_use vector to save CPU time
            self.restock_args(&t, v, false, state);
        }
        self.ref_in_use.clear();
    }
}

impl MoveVMState {
    pub fn new() -> Self {
        Self {
            resources: HashMap::new(),
            _gv_slot: HashMap::new(),
            _hot_potato: 0,
            values: HashMap::new(),
            typed_bug: vec![],
            ref_in_use: vec![],
        }
    }

    /// Add a new value of struct type to the state
    ///
    /// Checks if the value is already in the state, if it is, it will not be
    /// added but the amount of the value will be increased.
    pub fn add_new_value<S: HasMetadata>(
        &mut self,
        value: GatedValue,
        ty: &Type,
        resolver: &Resolver,
        state: &mut S,
    ) -> bool {
        let gate = value.gate.clone();
        match ty {
            Type::Vector(inner_ty) => {
                if let Value(ValueImpl::Container(Container::Vec(inner_v))) = &value.v {
                    let mut added = false;
                    for v in (**inner_v).borrow().iter() {
                        added |= self.add_new_value(
                            GatedValue {
                                v: Value(v.clone()),
                                gate: gate.clone(),
                            },
                            inner_ty,
                            resolver,
                            state,
                        )
                    }
                    return added;
                } else if let Value(ValueImpl::Container(Container::Locals(inner_v))) = &value.v {
                    let mut added = false;
                    for v in (**inner_v).borrow().iter() {
                        added |= self.add_new_value(
                            GatedValue {
                                v: Value(v.clone()),
                                gate: gate.clone(),
                            },
                            inner_ty,
                            resolver,
                            state,
                        )
                    }
                    return added;
                }
                unreachable!("Should not be a vector");
            }
            Type::Struct(_) | Type::StructInstantiation(_, _) => {}
            Type::Reference(_) | Type::MutableReference(_) => unreachable!("Should not be a reference"),
            _ => {
                return false;
            }
        }

        let abilities = resolver.loader.abilities(ty).expect("unknown type");
        let it = match self.values.get_mut(ty) {
            Some(it) => it,
            None => {
                self.values.insert(ty.clone(), vec![]);
                self.values.get_mut(ty).unwrap()
            }
        };
        let mut exists = false;
        let allow_clone = abilities.has_copy();
        for (v, amt) in it {
            if (*v).equals(&value).unwrap() {
                exists = true;
                if allow_clone {
                    *amt = usize::MAX;
                } else {
                    *amt += 1;
                }
                break;
            }
        }

        if !exists {
            self.values.get_mut(ty).unwrap().push((value, 1));
        }

        if !gate.is_ref() && !abilities.has_drop() && !abilities.has_store() {
            self._hot_potato += 1;
        }

        if !state.has_metadata::<StructAbilities>() {
            state.metadata_map_mut().insert(StructAbilities::new());
        }

        state
            .metadata_map_mut()
            .get_mut::<StructAbilities>()
            .unwrap()
            .set_ability(ty.clone(), abilities);

        true
    }

    /// Randomly sample a value from the state
    ///
    /// If the value is a reference, it will be added to the ref_in_use vector
    ///
    /// When a value is sampled, it will be removed from the state.
    pub fn sample_value<S>(&mut self, state: &mut S, ty: &Type, minimum_gate: &Gate) -> Value
    where
        S: HasRand + HasMetadata,
    {
        match self.values.get_mut(ty) {
            None => None,
            Some(it) => {
                if it.is_empty() {
                    None
                } else {
                    let mut offset = state.rand_mut().next() as usize % it.len();

                    loop {
                        if minimum_gate.satisfied_by(&it[offset].0.gate) {
                            break;
                        } else {
                            offset = state.rand_mut().next() as usize % it.len();
                        }
                    }

                    let (val, val_count) = it[offset].clone();

                    // remove from vec
                    if val_count > 0 {
                        if val_count == 1 {
                            it.remove(offset);
                        } else {
                            it[offset].1 -= 1;
                        }
                    } else {
                        unreachable!("Value count is 0")
                    }

                    // add to ref_in_use
                    if minimum_gate.is_ref() {
                        self.ref_in_use.push((ty.clone(), val.clone()));
                    } else {
                        let struct_abilities = state
                            .metadata_map()
                            .get::<StructAbilities>()
                            .expect("StructAbilities not found")
                            .get_ability(ty)
                            .expect("StructAbilities of specific struct not inserted");
                        if !struct_abilities.has_drop() && !struct_abilities.has_store() {
                            self._hot_potato -= 1;
                        }
                    }
                    Some(val.v)
                }
            }
        }
        .expect("Cannot sample value from state")
    }

    /// Restock a value to the state
    ///
    /// If the value is a reference, it will be removed from the ref_in_use
    /// vector. Used by mutator when trying to mutate a struct.
    pub fn restock_args<S>(&mut self, ty: &Type, value: GatedValue, is_ref: bool, state: &mut S)
    where
        S: HasMetadata,
    {
        if state.metadata_map().get::<TypeTagInfoMeta>().unwrap().is_tx_context(ty) {
            return;
        }

        if is_ref {
            let offset = self
                .ref_in_use
                .iter()
                .position(|(_t, v)| v.equals(&value).unwrap())
                .expect("Cannot find value in ref_in_use, is this struct not a reference?");
            self.ref_in_use.remove(offset);
        }
        let struct_abilities = state
            .metadata_map()
            .get::<StructAbilities>()
            .expect("StructAbilities not found")
            .get_ability(ty)
            .expect("StructAbilities of specific struct not inserted");

        if !struct_abilities.has_drop() && !struct_abilities.has_store() && !is_ref {
            self._hot_potato += 1;
        }

        let it = self.values.get_mut(ty).unwrap();
        match it.iter().position(|(val, _val_count)| val.equals(&value).unwrap()) {
            Some(offset) => {
                it[offset].1 += 1;
            }
            None => {
                it.push((value.clone(), 1));
            }
        }
    }

    pub fn restock_struct<S>(&mut self, ty: &Type, value: Value, ret_ty: &Gate, state: &mut S)
    where
        S: HasMetadata,
    {
        if state.metadata_map().get::<TypeTagInfoMeta>().unwrap().is_tx_context(ty) {
            return;
        }

        let value = GatedValue {
            v: value,
            gate: ret_ty.clone(),
        };

        if ret_ty.is_ref() {
            let offset = self
                .ref_in_use
                .iter()
                .position(|(_t, v)| v.equals(&value).unwrap())
                .expect("Cannot find value in ref_in_use, is this struct not a reference?");
            self.ref_in_use.remove(offset);
        }

        if !ret_ty.is_ref() {
            debug!("looking for struct abilities for {:?} {:?}", value, ty);
            let struct_abilities = state
                .metadata_map()
                .get::<StructAbilities>()
                .expect("StructAbilities not found")
                .get_ability(ty)
                .expect("StructAbilities of specific struct not inserted");

            if !struct_abilities.has_drop() && !struct_abilities.has_store() {
                self._hot_potato += 1;
            }
        }

        let it = self.values.get_mut(ty).unwrap();
        match it.iter().position(|(val, _val_count)| val.equals(&value).unwrap()) {
            Some(offset) => {
                it[offset].1 += 1;
            }
            None => {
                it.push((value, 1));
            }
        }
    }
}

impl Clone for MoveVMState {
    fn clone(&self) -> Self {
        assert!(self._gv_slot.is_empty());
        MoveVMState {
            resources: self.resources.clone(),
            _gv_slot: self._gv_slot.clone(),
            _hot_potato: self._hot_potato,
            values: self.values.clone(),
            typed_bug: self.typed_bug.clone(),
            ref_in_use: self.ref_in_use.clone(),
        }
    }
}

impl Serialize for MoveVMState {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        unreachable!()
    }
}

impl<'de> Deserialize<'de> for MoveVMState {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        unreachable!()
    }
}

impl MoveVMState {
    pub fn commit(&mut self) {
        for ((addr, ty), gv) in self._gv_slot.iter() {
            match gv.clone().into_effect() {
                None => {}
                Some(op) => match op {
                    Op::New(val) => {
                        self.resources.entry(*addr).or_default().insert(ty.clone(), val.clone());
                    }
                    Op::Modify(val) => {
                        self.resources.entry(*addr).or_default().insert(ty.clone(), val.clone());
                    }
                    Op::Delete => {
                        self.resources.entry(*addr).or_default().remove(ty);
                    }
                },
            }
        }
        self._gv_slot.clear();
    }
}

impl DataStore for MoveVMState {
    fn load_resource(
        &mut self,
        _addr: AccountAddress,
        _ty: &Type,
    ) -> PartialVMResult<(&mut GlobalValue, Option<Option<NumBytes>>)> {
        unreachable!("Sui doesn't support load_resource");
    }

    fn load_module(&self, _module_id: &ModuleId) -> VMResult<Vec<u8>> {
        unreachable!("Sui doesn't support load_module");
    }

    fn emit_event(&mut self, _guid: Vec<u8>, _seq_num: u64, _ty: Type, _val: Value) -> PartialVMResult<()> {
        unreachable!()
    }

    fn events(&self) -> &Vec<(Vec<u8>, u64, Type, MoveTypeLayout, Value)> {
        unreachable!()
    }

    fn link_context(&self) -> AccountAddress {
        AccountAddress::ZERO
    }

    fn relocate(&self, module_id: &ModuleId) -> PartialVMResult<ModuleId> {
        Ok(module_id.clone())
    }

    fn defining_module(&self, module_id: &ModuleId, _struct_: &IdentStr) -> PartialVMResult<ModuleId> {
        Ok(module_id.clone())
    }

    fn publish_module(&mut self, _module_id: &ModuleId, _blob: Vec<u8>) -> VMResult<()> {
        unreachable!("ItyFuzz does not support publishing modules")
    }
}

pub fn value_to_hash(v: &ValueImpl, hasher: &mut DefaultHasher) {
    macro_rules! hash_vec {
        ($v: expr) => {{
            let _ = (**$v).borrow().iter().for_each(|inner| {
                inner.hash(hasher);
            });
        }};
    }

    macro_rules! hash_container {
        ($v: expr) => {
            match $v {
                Container::Locals(v) => {
                    let _ = (**v).borrow().iter().for_each(|inner| {
                        value_to_hash(inner, hasher);
                    });
                }
                Container::Vec(v) => {
                    let _ = (**v).borrow().iter().for_each(|inner| {
                        value_to_hash(inner, hasher);
                    });
                }
                Container::Struct(v) => {
                    let _ = (**v).borrow().iter().for_each(|inner| {
                        value_to_hash(inner, hasher);
                    });
                }
                Container::VecU8(v) => hash_vec!(v),
                Container::VecU64(v) => hash_vec!(v),
                Container::VecU128(v) => hash_vec!(v),
                Container::VecBool(v) => hash_vec!(v),
                Container::VecAddress(v) => hash_vec!(v),
                Container::VecU16(v) => hash_vec!(v),
                Container::VecU32(v) => hash_vec!(v),
                Container::VecU256(v) => hash_vec!(v),
            }
        };
    }

    match v {
        ValueImpl::U8(v) => {
            (*v).hash(hasher);
        }
        ValueImpl::U16(v) => {
            (*v).hash(hasher);
        }
        ValueImpl::U32(v) => {
            (*v).hash(hasher);
        }
        ValueImpl::U64(v) => {
            (*v).hash(hasher);
        }
        ValueImpl::U128(v) => {
            (*v).hash(hasher);
        }
        ValueImpl::U256(v) => {
            (*v).hash(hasher);
        }
        ValueImpl::Bool(v) => {
            (*v).hash(hasher);
        }
        ValueImpl::Address(v) => {
            (*v).hash(hasher);
        }
        ValueImpl::Container(v) => hash_container!(v),
        ValueImpl::ContainerRef(v) => match v {
            ContainerRef::Local(v) => hash_container!(v),
            ContainerRef::Global { .. } => {
                unreachable!("not supported")
            }
        },
        ValueImpl::IndexedRef(v) => {
            v.idx.hash(hasher);
            match &v.container_ref {
                ContainerRef::Local(v) => hash_container!(v),
                ContainerRef::Global { .. } => {
                    unreachable!("not supported")
                }
            }
        }
        _ => {
            unreachable!("not supported")
        }
    }
}

impl VMStateT for MoveVMState {
    fn get_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.resources.iter().for_each(|(addr, ty)| {
            addr.hash(&mut hasher);
            ty.iter().for_each(|(t, v)| {
                t.hash(&mut hasher);
                value_to_hash(&v.0, &mut hasher);
            });
        });
        self.values.iter().for_each(|(t, v)| {
            t.hash(&mut hasher);
            v.iter().for_each(|(v, amt)| {
                value_to_hash(&v.v.0, &mut hasher);
                v.gate.hash(&mut hasher);
                amt.hash(&mut hasher);
            });
        });

        hasher.finish()
    }

    fn has_post_execution(&self) -> bool {
        self._hot_potato > 0
    }

    fn get_post_execution_needed_len(&self) -> usize {
        0
    }

    fn get_post_execution_pc(&self) -> usize {
        0
    }

    fn get_post_execution_len(&self) -> usize {
        self._hot_potato
    }

    #[cfg(feature = "full_trace")]
    fn get_flashloan(&self) -> String {
        todo!()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }

    fn is_subset_of(&self, _other: &Self) -> bool {
        todo!()
    }
}
