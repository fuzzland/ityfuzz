use crate::generic_vm::vm_executor::{ExecutionResult, GenericVM, MAP_SIZE};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::r#move::input::{MoveFunctionInput, MoveFunctionInputT};
use crate::r#move::vm_state::MoveVMState;
use crate::state_input::StagedVMState;
use move_binary_format::CompiledModule;
use move_core_types::language_storage::ModuleId;
use move_core_types::resolver::ModuleResolver;
use move_vm_runtime::{loader, move_vm};
use move_vm_types::gas::UnmeteredGasMeter;
use move_vm_types::values;
use std::collections::HashMap;
use std::sync::Arc;
use move_binary_format::access::ModuleAccess;
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::{Identifier, IdentStr};
use move_vm_runtime::interpreter::{CallStack, Frame, Interpreter, Stack};
use move_vm_runtime::loader::{Function, Loader, Resolver};
use move_vm_runtime::loader::BinaryType::Module;
use move_vm_runtime::native_functions::{NativeFunction, NativeFunctions};
use move_vm_types::values::Locals;

struct MoveVM {
    state: MoveVMState,
    modules: HashMap<ModuleId, Arc<loader::Module>>,
    functions: HashMap<ModuleId, HashMap<Identifier, Arc<Function>>>,
}

impl<I, S> GenericVM<MoveVMState, CompiledModule, MoveFunctionInput, AccountAddress, values::Value, I, S>
    for MoveVM
where
    I: VMInputT<MoveVMState, AccountAddress> + MoveFunctionInputT,
{
    fn deploy(
        &mut self,
        code: CompiledModule,
        constructor_args: MoveFunctionInput,
        deployed_address: AccountAddress,
    ) -> Option<AccountAddress> {
        // todo(@shou): directly use CompiledModule
        // let mut data = vec![];
        // code.serialize(&mut data).unwrap();
        // let account_modules = self.state.modules.get_mut(&deployed_address);
        // match account_modules {
        //     Some(account_modules) => {
        //         account_modules.insert(code.name().to_owned(), data);
        //     }
        //     None => {
        //         let mut account_modules = HashMap::new();
        //         account_modules.insert(code.name().to_owned(), data);
        //         self.state
        //             .modules
        //             .insert(deployed_address, account_modules);
        //     }
        // }
        Some(deployed_address)
    }

    fn execute(&mut self, input: &I, state: Option<&mut S>) -> ExecutionResult<MoveVMState>
    where
        MoveVMState: VMStateT,
    {
        let module = self.modules.get(&input.module_id()).unwrap();
        let function = self.functions
            .get(&input.module_id())
            .unwrap()
            .get(input.function_name())
            .unwrap();

        let mut locals = Locals::new(function.local_count());
        for (i, value) in input.args().into_iter().enumerate() {
            locals.store_loc(i, value.clone().value).unwrap();
        }

        let mut current_frame = Frame {
            pc: 0,
            locals,
            function: function.clone(),
            ty_args: vec![]
        };

        let mut interp = Interpreter{
            operand_stack: Stack::new(),
            call_stack: CallStack::new(),
            paranoid_type_checks: false
        };

        let loader = Loader::new(
            NativeFunctions::new(vec![]).unwrap(),
            Default::default(),
        );

        let resolver = Resolver {
            loader: &loader,
            binary: Module(module.clone()),
        };

        let ret = current_frame.execute_code(
            &resolver,
            &mut interp,
            &mut self.state,
            &mut UnmeteredGasMeter
        );

        // let ret = sess.execute_function_bypass_visibility(
        //     &input.module_id(),
        //     &input.function_name(),
        //     input.ty_args().clone(),
        //     input.args().clone(),
        //     &mut UnmeteredGasMeter,
        // );


        //
        // match ret {
        //     Ok(ret) => ExecutionResult {
        //         new_state: StagedVMState::new_with_state(self.state.clone()),
        //         output: ret
        //             .return_values
        //             .into_iter()
        //             .map(|(bytes, _layout)| bytes)
        //             .collect::<Vec<Vec<u8>>>()
        //             .into_iter()
        //             .flatten()
        //             .collect(),
        //         reverted: false,
        //     },
        //     Err(err) => ExecutionResult {
        //         new_state: StagedVMState::new_uninitialized(),
        //         output: vec![],
        //         reverted: false,
        //     },
        // }
        ExecutionResult {
            new_state: StagedVMState::new_with_state(self.state.clone()),
            output: vec![],
            reverted: false,
        }
    }

    fn get_jmp(&self) -> &'static mut [u8; MAP_SIZE] {
        todo!()
    }

    fn get_read(&self) -> &'static mut [bool; MAP_SIZE] {
        todo!()
    }

    fn get_write(&self) -> &'static mut [u8; MAP_SIZE] {
        todo!()
    }

    fn get_cmp(&self) -> &'static mut [values::Value; MAP_SIZE] {
        todo!()
    }

    fn state_changed(&self) -> bool {
        todo!()
    }
}
