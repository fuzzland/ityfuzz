use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use glob::glob;
use itertools::Itertools;
use libafl::corpus::{Corpus, Testcase};
use libafl::prelude::Rand;
use libafl::schedulers::Scheduler;
use libafl::state::{HasCorpus, HasMetadata, HasRand, State};
use move_binary_format::CompiledModule;
use move_core_types::account_address::AccountAddress;
use move_core_types::language_storage::ModuleId;
use move_core_types::u256::U256;
use move_vm_runtime::loader::Function;
use move_vm_types::loaded_data::runtime_types::Type;
use move_vm_types::values;
use move_vm_types::values::{Container, ContainerRef, Value, ValueImpl};
use crate::generic_vm::vm_executor::GenericVM;
use crate::input::VMInputT;
use crate::r#move::input::{CloneableValue, FunctionDefaultable, MoveFunctionInput, StructAbilities};
use crate::r#move::movevm;
use crate::r#move::types::{MoveInfantStateState, MoveFuzzState, MoveStagedVMState};
use crate::r#move::vm_state::MoveVMState;
use crate::state::HasCaller;
use crate::state_input::StagedVMState;


pub enum MoveInputStatus {
    Complete(Value),
    DependentOnStructs(Value, Vec<Type>),
}

pub struct MoveCorpusInitializer<'a> {
    pub state: &'a mut MoveFuzzState,
    pub executor: &'a mut movevm::MoveVM<MoveFunctionInput, MoveFuzzState>,
    pub scheduler: &'a dyn Scheduler<MoveFunctionInput, MoveFuzzState>,
    pub infant_scheduler: &'a dyn Scheduler<MoveStagedVMState, MoveInfantStateState>,
    pub default_state: MoveStagedVMState,
}

impl<'a> MoveCorpusInitializer<'a>
{

    pub fn new(
        state: &'a mut MoveFuzzState,
        executor: &'a mut movevm::MoveVM<MoveFunctionInput, MoveFuzzState>,
        scheduler: &'a dyn Scheduler<MoveFunctionInput, MoveFuzzState>,
        infant_scheduler: &'a dyn Scheduler<MoveStagedVMState, MoveInfantStateState>,
    ) -> Self {
        Self {
            state,
            executor,
            scheduler,
            infant_scheduler,
            default_state: MoveStagedVMState::new_with_state(
                MoveVMState::new()
            ),
        }
    }

    pub fn setup(&mut self, targets: Vec<String>) {
        self.basic_setup();
        self.initialize_glob(targets);
    }

    pub fn basic_setup(&mut self) {
        // setup callers
        self.state.add_caller(&AccountAddress::random());
        self.state.add_caller(&AccountAddress::random());
        self.state.add_caller(&AccountAddress::random());

        // add metadata
        self.state.metadata_mut().insert(StructAbilities::new());

        // setup infant scheduler & corpus
        self.default_state = StagedVMState::new_with_state(
            MoveVMState::new()
        );
        let mut tc = Testcase::new(self.default_state.clone());
        tc.set_exec_time(Duration::from_secs(0));
        let idx = self
            .state
            .infant_states_state
            .corpus_mut()
            .add(tc)
            .expect("failed to add");
        self.infant_scheduler
            .on_add(&mut self.state.infant_states_state, idx)
            .expect("failed to call infant scheduler on_add");
    }


    pub fn initialize_glob(&mut self, dirs: Vec<String>) {
        let mut modules = vec![];
        for directory in dirs {
            // find all directory named "bytecode_modules" in the current directory
            let paths = glob::glob(&format!("{}/*/bytecode_modules/*.mv", directory)).unwrap();
            for path in paths {
                // read the file into a vector of bytes
                let module = std::fs::read(path.unwrap()).unwrap();
                // deserialize the vector of bytes into a CompiledModule
                let module = CompiledModule::deserialize(&module).unwrap();
                println!("deploying module: {:?}", module.self_id());
                // add the module to the corpus
                modules.push(module);
            }
        }
        self.add_module(modules);

    }

    pub fn initialize_bytecode(&mut self, modules: Vec<Vec<u8>>) {
        let cmods = modules.iter().map(|v| {
            CompiledModule::deserialize(&v).unwrap()
        }).collect_vec();
        self.add_module(cmods);
    }

    fn add_module(&mut self, modules: Vec<CompiledModule>) {
        macro_rules! wrap_input {
            ($input: expr) => {{
                let mut tc = Testcase::new($input);
                tc.set_exec_time(Duration::from_secs(0));
                tc
            }};
        }
        for module in modules {
            let module_id = module.self_id();
            self.executor.deploy(module, None, AccountAddress::random(), &mut self.state)
                .expect("failed to deploy module");
        }

        for (module_id, funcs) in self.executor.functions.clone() {
            for (_, func) in funcs {
                let input = self.build_input(&module_id, func.clone());
                match input {
                    Some(input) => {

                        let idx = self.state.add_tx_to_corpus(
                            wrap_input!(input)
                        ).expect("failed to add input to corpus");
                        self.scheduler.on_add(self.state, idx).expect("failed to call scheduler on_add");
                    }
                    None => {
                        // dependent on structs
                        todo!()
                    }
                }
            }
        }
    }

    // if struct is found, return None because we cannot instantiate a struct
    fn gen_default_value(state: &mut MoveFuzzState, ty: Box<Type>) -> MoveInputStatus {
        match *ty {
            Type::Bool => {
                MoveInputStatus::Complete(Value::bool(false))
            }
            Type::U8 => {
                MoveInputStatus::Complete(Value::u8(0))
            }
            Type::U64 => {
                MoveInputStatus::Complete(Value::u64(0))
            }
            Type::U128 => {
                MoveInputStatus::Complete(Value::u128(0))
            }
            Type::Address => {
                MoveInputStatus::Complete(Value::address(state.get_rand_address()))
            }
            Type::Signer => {
                MoveInputStatus::Complete(Value::signer(state.get_rand_address()))
            }
            Type::Vector(v) => {
                macro_rules! wrap {
                    ($v: ident, $default: expr) => {
                        MoveInputStatus::Complete(
                            Value(ValueImpl::Container(
                                Container::$v(Rc::new(RefCell::new($default)))
                            ))
                        )
                    };
                }
                match *v.clone() {
                    Type::Vector(_) =>
                        todo!("vector of vector"),
                    Type::Bool => { wrap!(VecBool, vec![false]) }
                    Type::U8 => { wrap!(VecU8, vec![0]) }
                    Type::U64 => { wrap!(VecU64, vec![0]) }
                    Type::U128 => { wrap!(VecU128, vec![0]) }
                    Type::U16 => { wrap!(VecU16, vec![0]) }
                    Type::U32 => { wrap!(VecU32, vec![0]) }
                    Type::U256 => { wrap!(VecU256, vec![U256::zero()]) }
                    Type::Address => { wrap!(VecAddress, vec![state.get_rand_address()]) }
                    Type::Signer => { unreachable!("cannot initialize signer vector") }
                    Type::Reference(_) | Type::MutableReference(_) | Type::Vector(_) | Type::Struct(_) => {
                        let default_inner = Self::gen_default_value(state, v);
                        if let MoveInputStatus::Complete(Value(inner)) = default_inner {
                            wrap!(Vec, vec![inner])
                        } else if let MoveInputStatus::DependentOnStructs(Value(inner), deps) = default_inner {
                            MoveInputStatus::DependentOnStructs(
                                Value(ValueImpl::Container(
                                    Container::Vec(Rc::new(RefCell::new(vec![inner])))
                                )),
                                deps
                            )
                        } else {
                            unreachable!()
                        }
                    }
                    _ => unreachable!()
                }
            }


            Type::Struct(_) => {
                MoveInputStatus::DependentOnStructs(
                    Value(ValueImpl::Container(
                        Container::Struct(Rc::new(RefCell::new(vec![])))
                    )),
                    vec![*ty]
                )
            }
            Type::Reference(ty) | Type::MutableReference(ty)  => {
                todo!("reference")
            }
            _ => unreachable!()
        }
    }

    fn find_struct_deps(&mut self, ty: Box<Type>) -> Vec<Type> {
        match *ty {
            Type::Vector(v) => {
                self.find_struct_deps(v)
            }

            Type::Struct(v) => {
                vec![Type::Struct(v)]
            }
            Type::Reference(ty) | Type::MutableReference(ty)  => {
                self.find_struct_deps(ty)
            }
            _ => vec![]
        }
    }

    fn build_input(&mut self, module_id: &ModuleId, function: Arc<Function>) -> Option<MoveFunctionInput> {
        todo!("build input");
        // let mut values = vec![];
        //
        // for parameter_type in &function.parameter_types {
        //     let default_val = Self::gen_default_value(self.state, Box::new(parameter_type.clone()));
        //     if default_val.is_none() {
        //         return None;
        //     }
        //     values.push(CloneableValue::from(default_val.unwrap()));
        // }
        // let input = MoveFunctionInput {
        //     module: module_id.clone(),
        //     function: function.name.clone(),
        //     function_info: Arc::new(FunctionDefaultable {
        //         function: Some(function),
        //     }),
        //     args: values,
        //     ty_args: vec![],
        //     caller: self.state.get_rand_caller(),
        //     vm_state: StagedVMState::new_uninitialized(),
        //     vm_state_idx: 0,
        //     _deps: vec![],
        //     _deps_amount: vec![],
        // };
        // return Some(input);
    }
}