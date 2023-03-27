use crate::generic_vm::vm_state::VMStateT;
use crate::r#move::types::MoveAddress;
use move_binary_format::errors::{PartialVMResult, VMResult};
use move_core_types::account_address::AccountAddress;
use move_core_types::effects::Op;
use move_core_types::gas_algebra::NumBytes;
use move_core_types::identifier::{IdentStr, Identifier};
use move_core_types::language_storage::{ModuleId, StructTag};
use move_core_types::resolver::{ModuleResolver, ResourceResolver};
use move_core_types::value::MoveTypeLayout;
use move_vm_runtime::interpreter::Frame;
use move_vm_runtime::loader::Loader;
use move_vm_runtime::move_vm::MoveVM;
use move_vm_types::data_store::DataStore;
use move_vm_types::loaded_data::runtime_types::Type;
use move_vm_types::values::{GlobalValue, Value};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::any::Any;
use std::collections::HashMap;

#[derive(Debug)]
pub struct MoveVMState {
    pub resources: HashMap<AccountAddress, HashMap<Type, Value>>,
    pub _gv_slot: HashMap<(AccountAddress, Type), GlobalValue>,
}

impl MoveVMState {
    pub fn new() -> Self {
        Self {
            resources: HashMap::new(),
            _gv_slot: HashMap::new(),
        }
    }
}

impl Clone for MoveVMState {
    fn clone(&self) -> Self {
        assert!(self._gv_slot.is_empty());
        MoveVMState {
            resources: self.resources.clone(),
            _gv_slot: HashMap::new(),
        }
    }
}

impl Serialize for MoveVMState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        unreachable!()
    }
}

impl<'de> Deserialize<'de> for MoveVMState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
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

    fn load_module(&self, module_id: &ModuleId) -> VMResult<Vec<u8>> {
        unreachable!()
    }

    fn publish_module(
        &mut self,
        module_id: &ModuleId,
        blob: Vec<u8>,
        is_republishing: bool,
    ) -> VMResult<()> {
        unreachable!()
    }

    fn exists_module(&self, module_id: &ModuleId) -> VMResult<bool> {
        unreachable!()
    }

    fn emit_event(
        &mut self,
        guid: Vec<u8>,
        seq_num: u64,
        ty: Type,
        val: Value,
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
        }
    }
}
