use move_core_types::identifier::Identifier;
use move_core_types::language_storage::{ModuleId, TypeTag};
use move_vm_types::values::Value;

pub trait MoveFunctionInputT {
    fn module_id(&self) -> &ModuleId;
    fn function_name(&self) -> &Identifier;
    fn args(&self) -> Vec<Vec<u8>>;
    fn ty_args(&self) -> Vec<TypeTag>;
}

pub struct MoveFunctionInput {
    pub module: ModuleId,
    pub function: Identifier,
    pub args: Vec<Value>,
    pub ty_args: Vec<TypeTag>,
}
