use crate::generic_vm::vm_executor::{ExecutionResult, GenericVM, MAP_SIZE};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::r#move::input::{MoveFunctionInput, MoveFunctionInputT};
use crate::r#move::vm_state::MoveVMState;
use crate::state_input::StagedVMState;
use move_binary_format::access::ModuleAccess;
use move_binary_format::file_format::{FunctionDefinitionIndex, TableIndex};
use move_binary_format::CompiledModule;
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::{IdentStr, Identifier};
use move_core_types::language_storage::ModuleId;
use move_core_types::resolver::ModuleResolver;
use move_vm_runtime::interpreter::{CallStack, Frame, Interpreter, Stack};
use move_vm_runtime::loader::BinaryType::Module;
use move_vm_runtime::loader::{Function, Loader, ModuleCache, Resolver};
use move_vm_runtime::native_functions::{NativeFunction, NativeFunctions};
use move_vm_runtime::{loader, move_vm};
use move_vm_types::gas::UnmeteredGasMeter;
use move_vm_types::values;
use move_vm_types::values::Locals;
use std::collections::HashMap;
use std::sync::Arc;

struct MoveVM<I, S> {
    modules: HashMap<ModuleId, Arc<loader::Module>>,
    // for comm with move_vm
    _module_cache: ModuleCache,
    functions: HashMap<ModuleId, HashMap<Identifier, Arc<Function>>>,
    _phantom: std::marker::PhantomData<(I, S)>,
}

impl<I, S> MoveVM<I, S> {
    pub fn new() -> Self {
        let modules = HashMap::new();
        let _module_cache = ModuleCache::new();
        let functions = HashMap::new();
        Self {
            modules,
            _module_cache,
            functions,
            _phantom: Default::default(),
        }
    }

    pub fn get_natives(&self) -> NativeFunctions {
        NativeFunctions {
            0: Default::default(),
        }
    }
}

impl<I, S>
    GenericVM<
        MoveVMState,
        CompiledModule,
        MoveFunctionInput,
        ModuleId,
        AccountAddress,
        values::Value,
        I,
        S,
    > for MoveVM<I, S>
where
    I: VMInputT<MoveVMState, ModuleId, AccountAddress> + MoveFunctionInputT,
{
    fn deploy(
        &mut self,
        module: CompiledModule,
        _constructor_args: Option<MoveFunctionInput>,
        _deployed_address: AccountAddress,
    ) -> Option<AccountAddress> {
        let pre_mc_func_idx = self._module_cache.functions.len();
        self._module_cache
            .insert(&self.get_natives(), module.self_id(), module.clone())
            .expect("internal deploy error");
        self.modules.insert(
            module.self_id(),
            Arc::new(
                loader::Module::new(module.clone(), &self._module_cache).expect("module failed"),
            ),
        );
        for (idx, (func_def, func_handle)) in module
            .function_defs()
            .iter()
            .zip(module.function_handles())
            .enumerate()
        {
            let name = module.identifier_at(func_handle.name);
            let function: Arc<Function> = self._module_cache.function_at(pre_mc_func_idx + idx);
            self.functions
                .entry(module.self_id())
                .or_insert_with(HashMap::new)
                .insert(name.to_owned(), function);
        }
        Some(module.self_id().address().clone())
    }

    fn execute(
        &mut self,
        input: &I,
        state: Option<&mut S>,
    ) -> ExecutionResult<ModuleId, AccountAddress, MoveVMState>
    where
        MoveVMState: VMStateT,
    {
        let module = self.modules.get(&input.module_id()).unwrap();
        let function = self
            .functions
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
            ty_args: vec![],
        };

        let mut interp = Interpreter {
            operand_stack: Stack::new(),
            call_stack: CallStack::new(),
            paranoid_type_checks: false,
        };

        let loader = Loader::new(NativeFunctions::new(vec![]).unwrap(), Default::default());

        let resolver = Resolver {
            loader: &loader,
            binary: Module(module.clone()),
        };

        let mut state = input.get_state().clone();

        let ret =
            current_frame.execute_code(&resolver, &mut interp, &mut state, &mut UnmeteredGasMeter);

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
            new_state: StagedVMState::new_with_state(state),
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

mod tests {
    use super::*;
    use crate::r#move::input::CloneableValue;
    use crate::state::FuzzState;
    use move_binary_format::file_format::{FunctionDefinitionIndex, TableIndex};
    use move_vm_types::values::Value;

    #[test]
    fn test_move_vm_simple() {
        let module_hex = "a11ceb0b0500000006010002030205050703070a0e0818200c38130000000100000001030007546573744d6f6405746573743100000000000000000000000000000000000000000000000000000000000000030001000001040b00060200000000000000180200";
        let module_bytecode = hex::decode(module_hex).unwrap();
        let module = CompiledModule::deserialize(&module_bytecode).unwrap();
        let mut mv = MoveVM::<
            MoveFunctionInput,
            FuzzState<MoveFunctionInput, MoveVMState, ModuleId, AccountAddress>,
        >::new();
        let loc = mv
            .deploy(module, None, AccountAddress::new([0; 32]))
            .unwrap();

        assert_eq!(mv.modules.len(), 1);
        assert_eq!(mv.functions.len(), 1);

        let mut input = MoveFunctionInput {
            module: mv.modules.iter().next().unwrap().0.clone(),
            function: Identifier::new("test1").unwrap(),
            args: vec![CloneableValue {
                value: Value::u64(20),
            }],
            ty_args: vec![],
            caller: AccountAddress::new([1; 32]),
            vm_state: StagedVMState {
                state: MoveVMState {
                    resources: Default::default(),
                    _gv_slot: Default::default(),
                },
                stage: vec![],
                initialized: false,
                trace: Default::default(),
            },
            vm_state_idx: 0,
        };

        let res = mv.execute(&input, None);
        println!("{:?}", res);
    }
}
