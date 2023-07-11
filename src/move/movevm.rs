use crate::generic_vm::vm_executor::{ExecutionResult, GenericVM, MAP_SIZE};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::r#move::input::{MoveFunctionInput, MoveFunctionInputT};
use crate::r#move::types::MoveOutput;
use crate::r#move::vm_state::MoveVMState;
use crate::state_input::StagedVMState;

use move_binary_format::access::ModuleAccess;

use move_binary_format::CompiledModule;
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::ModuleId;

use move_vm_runtime::interpreter::{CallStack, DummyTracer, Frame, Interpreter, Stack};
use move_vm_runtime::loader;
use move_vm_runtime::loader::BinaryType::Module;
use move_vm_runtime::loader::{Function, Loader, ModuleCache, Resolver};
use move_vm_runtime::native_functions::NativeFunctions;
use move_vm_types::gas::UnmeteredGasMeter;
use move_vm_types::values;
use move_vm_types::values::Locals;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::Debug;
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
        MoveOutput,
        I,
        S,
        MoveFunctionInput
    > for MoveVM<I, S>
where
    I: VMInputT<MoveVMState, ModuleId, AccountAddress, MoveFunctionInput> + MoveFunctionInputT,
{
    fn deploy(
        &mut self,
        module: CompiledModule,
        _constructor_args: Option<MoveFunctionInput>,
        _deployed_address: AccountAddress,
        _state: &mut S,
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
        for (idx, (_func_def, func_handle)) in module
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

        println!("deployed structs: {:?}", self._module_cache.structs);

        Some(module.self_id().address().clone())
    }


    fn fast_static_call(
        &mut self,
        _data: &Vec<(AccountAddress, MoveFunctionInput)>,
        _vm_state: &MoveVMState,
        _state: &mut S,
    ) -> Vec<MoveOutput>
    where
        MoveVMState: VMStateT,
        AccountAddress: Serialize + DeserializeOwned + Debug,
        ModuleId: Serialize + DeserializeOwned + Debug,
        MoveOutput: Default,
    {
        todo!()
    }

    fn execute(
        &mut self,
        input: &I,
        _state: &mut S,
    ) -> ExecutionResult<ModuleId, AccountAddress, MoveVMState, MoveOutput, MoveFunctionInput>
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

        let mut loader = Loader::new(NativeFunctions::new(vec![]).unwrap(), Default::default());

        loader.set_structs(self._module_cache.structs.clone());

        let resolver = Resolver {
            loader: &loader,
            binary: Module(module.clone()),
        };

        let mut state = input.get_state().clone();

        let ret =
            current_frame.execute_code(&resolver, &mut interp, &mut state, &mut UnmeteredGasMeter, &mut DummyTracer{});

        for v in interp.operand_stack.value {
            println!("val: {:?}", v);
        }

        function.return_types().iter().for_each(|ty| {
            let abilities = resolver.loader.abilities(ty);
            println!("ty: {:?} - ability {:?}", ty, abilities);
        });

        println!("ret: {:?}", ret);

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
            additional_info: None
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

    use move_vm_types::values::Value;

    fn _run(
        bytecode: &str,
    ) -> MoveVM<
        MoveFunctionInput,
        FuzzState<MoveFunctionInput, MoveVMState, ModuleId, AccountAddress, MoveOutput, MoveFunctionInput>,
    > {
        let module_bytecode = hex::decode(bytecode).unwrap();
        let module = CompiledModule::deserialize(&module_bytecode).unwrap();
        let mut mv = MoveVM::<
            MoveFunctionInput,
            FuzzState<MoveFunctionInput, MoveVMState, ModuleId, AccountAddress, MoveOutput, MoveFunctionInput>,
        >::new();
        let _loc = mv
            .deploy(
                module,
                None,
                AccountAddress::new([0; 32]),
                &mut FuzzState::new(0),
            )
            .unwrap();

        assert_eq!(mv.modules.len(), 1);
        assert_eq!(mv.functions.len(), 1);

        let input = MoveFunctionInput {
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

        let res = mv.execute(&input, &mut FuzzState::new(0));
        println!("{:?}", res);
        return mv;
    }

    #[test]
    fn test_move_vm_simple() {
        // module 0x3::TestMod {
        //         public fun test1(data: u64) : u64 {
        //         data * 2
        //     }
        // }

        let module_hex = "a11ceb0b0500000006010002030205050703070a0e0818200c38130000000100000001030007546573744d6f6405746573743100000000000000000000000000000000000000000000000000000000000000030001000001040b00060200000000000000180200";
        _run(module_hex);
    }

    #[test]
    fn test_dropping() {
        // module 0x3::TestMod {
        //     resource struct TestStruct {
        //         data: u64
        //     }
        //     public fun test1(data: u64) : TestStruct {
        //         TestStruct { data };
        //     }
        // }

        let module_hex = "a11ceb0b0500000008010002020204030605050b0607111e082f200a4f050c540b000000010200000200010001030108000007546573744d6f640a546573745374727563740574657374310464617461000000000000000000000000000000000000000000000000000000000000000300020103030001000002030b0012000200";
        _run(module_hex);
    }
}
