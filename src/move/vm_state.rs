use crate::generic_vm::vm_state::VMStateT;

use move_binary_format::errors::{PartialVMResult, VMResult};
use move_core_types::account_address::AccountAddress;
use move_core_types::effects::Op;
use move_core_types::gas_algebra::NumBytes;

use move_core_types::language_storage::ModuleId;

use move_core_types::value::MoveTypeLayout;

use move_vm_types::data_store::DataStore;
use move_vm_types::loaded_data::runtime_types::Type;
use move_vm_types::values::{Container, GlobalValue, Value, ValueImpl};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::any::Any;
use std::collections::HashMap;
use std::ops::Index;
use libafl::prelude::{HasMetadata, Rand};
use libafl::state::HasRand;
use move_core_types::identifier::IdentStr;
use serde_json::ser::State;
use crate::evm::onchain::endpoints::Chain::POLYGON;
use crate::r#move::input::StructAbilities;

pub trait MoveVMStateT {
    fn get_value_to_drop(&self) -> (&HashMap<Type, Vec<(Value, usize)>>);
    fn get_useful_value(&self) -> (&HashMap<Type, Vec<(Value, usize)>>);

    /// Called after each time the function is called, we should return all values that are borrowed
    /// as reference / mutable reference from the vm_state.
    fn finished_call<S>(&mut self, state: &mut S)
        where S: HasMetadata;
}


#[derive(Debug)]
pub struct MoveVMState {
    pub resources: HashMap<AccountAddress, HashMap<Type, Value>>,
    pub _gv_slot: HashMap<(AccountAddress, Type), GlobalValue>,

    pub value_to_drop: HashMap<Type, Vec<(Value, usize)>>,
    pub useful_value: HashMap<Type, Vec<(Value, usize)>>,

    pub ref_in_use: Vec<(Type, Value)>,
}

impl MoveVMStateT for MoveVMState {
    fn get_value_to_drop(&self) -> (&HashMap<Type, Vec<(Value, usize)>>) {
        &self.value_to_drop
    }

    fn get_useful_value(&self) -> (&HashMap<Type, Vec<(Value, usize)>>) {
        &self.useful_value
    }


    /// Called after each time the function is called, we should return all values that are borrowed
    /// as reference / mutable reference from the vm_state.
    fn finished_call<S>(&mut self, state: &mut S)
    where S: HasMetadata {
        for (t, v) in self.ref_in_use.clone() {
            // we'll clear the ref_in_use vector to save CPU time
            self.restock(&t, v, false, state);
        }
        self.ref_in_use.clear();
    }
}

impl MoveVMState {
    pub fn new() -> Self {
        Self {
            resources: HashMap::new(),
            _gv_slot: HashMap::new(),
            value_to_drop: Default::default(),
            useful_value: Default::default(),
            ref_in_use: vec![],
        }
    }


    /// Add a new value of struct type to the state
    ///
    /// Checks if the value is already in the state, if it is, it will not be added
    /// but the amount of the value will be increased.
    ///
    /// If value is not droppable, it will be added to the useful_value hashmap
    /// If value is droppable, it will be added to the value_to_drop hashmap
    pub fn add_new_value(&mut self, value: Value, ty: &Type, is_droppable: bool) {
        macro_rules! add_new_v {
            ($loc: ident) => {
                {
                    let it = match self.$loc.get_mut(ty) {
                        Some(it) => it,
                        None => {
                            self.$loc.insert(ty.clone(), vec![]);
                            self.$loc.get_mut(ty).unwrap()
                        }
                    };
                    let mut exists = false;
                    for (v, amt) in it {
                        if (*v).equals(&value).unwrap() {
                            exists = true;
                            *amt += 1;
                            break;
                        }
                    }

                    if !exists {
                        self.$loc.get_mut(ty).unwrap().push((value, 1));
                    }
                }
            };
        }

        if is_droppable {
            add_new_v!(value_to_drop);
        } else {
            add_new_v!(useful_value);
        }
    }


    /// Randomly sample a value from the state
    ///
    /// If the value is a reference, it will be added to the ref_in_use vector
    ///
    /// When a value is sampled, it will be removed from the state.
    pub fn sample_value<S>(&mut self, state: &mut S, ty: &Type, is_ref: bool) -> Value
    where S: HasRand {
        macro_rules! sample_value_inner {
            ($loc: ident, $struct_src: ident) => {
                {
                    match self.$loc.get_mut(ty) {
                        None => None,
                        Some(it) => {
                            if it.len() == 0 {
                                None
                            } else {
                                let offset = (state.rand_mut().next() as usize % it.len()) as usize;
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
                                if is_ref {
                                    self.ref_in_use.push((ty.clone(), val.clone()));
                                }
                                Some(val)
                            }
                        }
                    }


                }
            };
        }
        let rand = state.rand_mut().next();

        let res = if rand % 2 == 0 {
            sample_value_inner!(useful_value, Useful)
        } else {
            sample_value_inner!(value_to_drop, Drop)
        };

        if res.is_none() {
            {
                if rand % 2 == 0 {
                    sample_value_inner!(value_to_drop, Drop)
                } else {
                    sample_value_inner!(useful_value, Useful)
                }
            }.unwrap()
        } else {
            res.unwrap()
        }
    }

    /// Restock a value to the state
    ///
    /// If the value is a reference, it will be removed from the ref_in_use vector.
    /// Used by mutator when trying to mutate a struct.
    pub fn restock<S>(&mut self, ty: &Type, value: Value, is_ref: bool, _state: &mut S)
    where S: HasMetadata {
        if is_ref {
            let offset = self.ref_in_use
                .iter()
                .position(|(t, v)| v.equals(&value).unwrap())
                .expect("Cannot find value in ref_in_use, is this struct not a reference?");
            self.ref_in_use.remove(offset);
        }
        let struct_abilities = _state
            .metadata()
            .get::<StructAbilities>()
            .expect("StructAbilities not found")
            .get_ability(ty)
            .expect("StructAbilities of specific struct not inserted");

        if struct_abilities.has_drop() {
            let it = self.value_to_drop.get_mut(ty).unwrap();
            match it.iter().position(|(val, val_count)| val.equals(&value).unwrap()) {
                Some(offset) => {
                    it[offset].1 += 1;
                }
                None => {
                    it.push((value.clone(), 1));
                }
            }
        } else {
            let it = self.useful_value.get_mut(ty).unwrap();
            match it.iter().position(|(val, val_count)| val.equals(&value).unwrap()) {
                Some(offset) => {
                    it[offset].1 += 1;
                }
                None => {
                    it.push((value.clone(), 1));
                }
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
            value_to_drop: self.value_to_drop.clone(),
            useful_value: self.useful_value.clone(),
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
        let mut idx: usize = 0;
        for ((addr, ty), gv) in self._gv_slot.iter() {
            match gv.clone().into_effect() {
                None => {}
                Some(op) => match op {
                    Op::New(val) => {
                        self.resources
                            .entry(addr.clone())
                            .or_insert(HashMap::new())
                            .insert(ty.clone(), val.clone());
                    }
                    Op::Modify(val) => {
                        self.resources
                            .entry(addr.clone())
                            .or_insert(HashMap::new())
                            .insert(ty.clone(), val.clone());
                    }
                    Op::Delete => {
                        self.resources
                            .entry(addr.clone())
                            .or_insert(HashMap::new())
                            .remove(&ty);
                    }
                },
            }
            idx += 1;
        }
        self._gv_slot.clear();
    }
}

impl DataStore for MoveVMState {
    fn load_resource(
        &mut self,
        addr: AccountAddress,
        ty: &Type,
    ) -> PartialVMResult<(&mut GlobalValue, Option<Option<NumBytes>>)> {
        let data = self.resources.get(&addr).unwrap().get(ty).unwrap();

        self._gv_slot.insert(
            (addr, ty.clone()),
            GlobalValue::cached(data.clone()).unwrap(),
        );

        return Ok((self._gv_slot.get_mut(&(addr, ty.clone())).unwrap(), None));
    }

    fn load_module(&self, _module_id: &ModuleId) -> VMResult<Vec<u8>> {
        unreachable!()
    }



    fn emit_event(
        &mut self,
        _guid: Vec<u8>,
        _seq_num: u64,
        _ty: Type,
        _val: Value,
    ) -> PartialVMResult<()> {
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

    fn defining_module(&self, module_id: &ModuleId, struct_: &IdentStr) -> PartialVMResult<ModuleId> {
        Ok(module_id.clone())
    }

    fn publish_module(&mut self, module_id: &ModuleId, blob: Vec<u8>) -> VMResult<()> {
        unreachable!()
    }
}

impl VMStateT for MoveVMState {
    fn get_hash(&self) -> u64 {
        todo!()
    }

    fn has_post_execution(&self) -> bool {
        false
    }

    fn get_post_execution_needed_len(&self) -> usize {
        0
    }

    fn get_post_execution_pc(&self) -> usize {
        0
    }

    fn get_post_execution_len(&self) -> usize {
        0
    }

    #[cfg(feature = "full_trace")]
    fn get_flashloan(&self) -> String {
        todo!()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Default for MoveVMState {
    fn default() -> Self {
        Self {
            resources: HashMap::new(),
            _gv_slot: HashMap::new(),
            value_to_drop: Default::default(),
            useful_value: Default::default(),
            ref_in_use: vec![],
        }
    }
}
