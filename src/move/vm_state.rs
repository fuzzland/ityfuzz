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
use libafl::prelude::Rand;
use libafl::state::HasRand;
use serde_json::ser::State;
use crate::evm::onchain::endpoints::Chain::POLYGON;

#[derive(Debug)]
pub struct MoveVMState {
    pub resources: HashMap<AccountAddress, HashMap<Type, Value>>,
    pub _gv_slot: HashMap<(AccountAddress, Type), GlobalValue>,

    pub value_to_drop: HashMap<Type, Vec<Value>>,
    pub _value_to_drop_amt: HashMap<Type, Vec<usize>>,
    pub useful_value: HashMap<Type, Vec<Value>>,
    pub _useful_value_amt: HashMap<Type, Vec<usize>>,

    pub ref_in_use: Vec<(Type, Value)>,
}

impl MoveVMState {
    pub fn new() -> Self {
        Self {
            resources: HashMap::new(),
            _gv_slot: HashMap::new(),
            value_to_drop: Default::default(),
            _value_to_drop_amt: Default::default(),
            useful_value: Default::default(),
            _useful_value_amt: Default::default(),
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
            ($loc: ident, $amt_loc: ident) => {
                {
                    let it = match self.$loc.get_mut(ty) {
                        Some(it) => it,
                        None => {
                            self.$loc.insert(ty.clone(), vec![]);
                            self.$amt_loc.insert(ty.clone(), vec![]);
                            self.$loc.get_mut(ty).unwrap()
                        }
                    };
                    let mut offset: i64 = -1;
                    for (off, v) in it.iter().enumerate() {
                        if (*v).equals(&value).unwrap() {
                            offset = off as i64;
                            break;
                        }
                    }

                    if offset > 0 {
                        self.$amt_loc.get_mut(ty).unwrap()[offset as usize] += 1;
                    } else {
                        it.push(value.clone());
                        self.$amt_loc.get_mut(ty).unwrap().push(1);
                    }
                }
            };
        }

        if is_droppable {
            add_new_v!(value_to_drop, _value_to_drop_amt);
        } else {
            add_new_v!(useful_value, _useful_value_amt);
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
            ($loc: ident, $amt_loc: ident, $struct_src: ident) => {
                {
                    match self.$loc.get_mut(ty) {
                        None => None,
                        Some(it) => {
                            if it.len() == 0 {
                                None
                            } else {
                                let offset = (state.rand_mut().next() as usize % it.len()) as usize;
                                let val = it[offset].clone();
                                let val_count = self.$amt_loc.get_mut(ty).unwrap();

                                // remove from vec
                                if val_count[offset] > 0 {
                                    val_count[offset] -= 1;
                                    if val_count[offset] == 0 {
                                        it.remove(offset);
                                        val_count.remove(offset);
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
            sample_value_inner!(useful_value, _useful_value_amt, Useful)
        } else {
            sample_value_inner!(value_to_drop, _value_to_drop_amt, Drop)
        };

        if res.is_none() {
            {
                if rand % 2 == 0 {
                    sample_value_inner!(value_to_drop, _value_to_drop_amt, Drop)
                } else {
                    sample_value_inner!(useful_value, _useful_value_amt, Useful)
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
    pub fn restock(&mut self, ty: &Type, value: Value, is_ref: bool) {
        if is_ref {
            let offset = self.ref_in_use.iter().position(|(t, v)| v.equals(&value).unwrap()).unwrap();
            self.ref_in_use.remove(offset);
        }
        // match value {
        //     StructUsage::Useful(v) => {
        //         let it = self.useful_value.get_mut(ty).unwrap();
        //         match it.iter().position(|x| x.equals(&Value(ValueImpl::Container(Container::Struct(v.clone())))).unwrap()) {
        //             Some(offset) => {
        //                 self._useful_value_amt.get_mut(ty).unwrap()[offset] += 1;
        //             }
        //             None => {
        //                 it.push(Value(ValueImpl::Container(Container::Struct(v.clone()))));
        //                 self._useful_value_amt.get_mut(ty).unwrap().push(1);
        //             }
        //         }
        //     }
        //     StructUsage::Drop(v) => {
        //         let it = self.value_to_drop.get_mut(ty).unwrap();
        //         match it.iter().position(|x| x.equals(&Value(ValueImpl::Container(Container::Struct(v.clone())))).unwrap()) {
        //             Some(offset) => {
        //                 self._value_to_drop_amt.get_mut(ty).unwrap()[offset] += 1;
        //             }
        //             None => {
        //                 it.push(Value(ValueImpl::Container(Container::Struct(v.clone()))));
        //                 self._value_to_drop_amt.get_mut(ty).unwrap().push(1);
        //             }
        //         }
        //     }
        // }
    }
}

impl Clone for MoveVMState {
    fn clone(&self) -> Self {
        assert!(self._gv_slot.is_empty());
        MoveVMState {
            resources: self.resources.clone(),
            _gv_slot: self._gv_slot.clone(),
            value_to_drop: self.value_to_drop.clone(),
            _value_to_drop_amt: self._value_to_drop_amt.clone(),
            useful_value: self.useful_value.clone(),
            _useful_value_amt: self._useful_value_amt.clone(),
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

    fn publish_module(
        &mut self,
        _module_id: &ModuleId,
        _blob: Vec<u8>,
        _is_republishing: bool,
    ) -> VMResult<()> {
        unreachable!()
    }

    fn exists_module(&self, _module_id: &ModuleId) -> VMResult<bool> {
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
}

impl VMStateT for MoveVMState {
    fn get_hash(&self) -> u64 {
        todo!()
    }

    fn has_post_execution(&self) -> bool {
        todo!()
    }

    fn get_post_execution_needed_len(&self) -> usize {
        todo!()
    }

    fn get_post_execution_pc(&self) -> usize {
        todo!()
    }

    fn get_post_execution_len(&self) -> usize {
        todo!()
    }

    #[cfg(feature = "full_trace")]
    fn get_flashloan(&self) -> String {
        todo!()
    }

    fn as_any(&self) -> &dyn Any {
        todo!()
    }
}

impl Default for MoveVMState {
    fn default() -> Self {
        Self {
            resources: HashMap::new(),
            _gv_slot: HashMap::new(),
            value_to_drop: Default::default(),
            _value_to_drop_amt: Default::default(),
            useful_value: Default::default(),
            _useful_value_amt: Default::default(),
            ref_in_use: vec![],
        }
    }
}
