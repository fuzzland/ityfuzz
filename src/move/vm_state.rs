use crate::generic_vm::vm_state::VMStateT;
use crate::r#move::types::MoveAddress;
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::{IdentStr, Identifier};
use move_core_types::language_storage::{ModuleId, StructTag};
use move_core_types::resolver::{ModuleResolver, ResourceResolver};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveVMState {
    pub modules: HashMap<MoveAddress, HashMap<Identifier, Vec<u8>>>,
    pub resources: HashMap<MoveAddress, HashMap<StructTag, Vec<u8>>>,
}

impl ModuleResolver for MoveVMState {
    type Error = ();

    fn get_module(&self, id: &ModuleId) -> Result<Option<Vec<u8>>, Self::Error> {
        let module_account = self.modules.get(id.address()).unwrap();
        return Ok(module_account.get(id.name()).cloned());
    }
}

impl ResourceResolver for MoveVMState {
    type Error = ();

    fn get_resource(
        &self,
        address: &AccountAddress,
        typ: &StructTag,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        let resource_account = self.resources.get(address).unwrap();
        return Ok(resource_account.get(typ).cloned());
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

    fn as_any(&self) -> &dyn Any {
        todo!()
    }
}

impl Default for MoveVMState {
    fn default() -> Self {
        Self {
            modules: HashMap::new(),
            resources: HashMap::new(),
        }
    }
}
