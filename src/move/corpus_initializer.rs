use std::{cell::RefCell, collections::HashMap, rc::Rc, sync::Arc, time::Duration};

use itertools::Itertools;
use libafl::{
    corpus::{Corpus, Testcase},
    schedulers::Scheduler,
    state::{HasCorpus, HasMetadata},
};
use move_binary_format::{access::ModuleAccess, file_format::Bytecode, CompiledModule};
use move_core_types::{
    account_address::AccountAddress,
    language_storage::{ModuleId, StructTag},
    u256::U256,
};
use move_vm_runtime::loader::Function;
use move_vm_types::{
    loaded_data::runtime_types::Type,
    values::{Container, ContainerRef, IndexedRef, Value, ValueImpl},
};
use revm_primitives::HashSet;
use sui_types::base_types::{TX_CONTEXT_MODULE_NAME, TX_CONTEXT_STRUCT_NAME};
use tracing::{debug, info};

use crate::{
    generic_vm::vm_executor::GenericVM,
    mutation_utils::ConstantPoolMetadata,
    r#move::{
        input::{CloneableValue, FunctionDefaultable, MoveFunctionInput, StructAbilities},
        movevm,
        movevm::TypeTagInfoMeta,
        scheduler::MoveSchedulerMeta,
        types::{MoveFuzzState, MoveInfantStateState, MoveStagedVMState},
        vm_state::MoveVMState,
    },
    state::HasCaller,
    state_input::StagedVMState,
};

pub enum MoveInputStatus {
    Complete(Value),
    DependentOnStructs(Value, Vec<Type>),
}

pub struct MoveCorpusInitializer<'a, SC, ISC>
where
    SC: Scheduler<State = MoveFuzzState>,
    ISC: Scheduler<State = MoveInfantStateState>,
{
    pub state: &'a mut MoveFuzzState,
    pub executor: &'a mut movevm::MoveVM<MoveFunctionInput, MoveFuzzState>,
    pub scheduler: SC,
    pub infant_scheduler: ISC,
    pub default_state: MoveStagedVMState,
}

pub fn is_tx_context(struct_tag: &StructTag) -> bool {
    struct_tag.address ==
        AccountAddress::new(
            hex::decode("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap()
                .try_into()
                .unwrap(),
        ) &&
        struct_tag.module == TX_CONTEXT_MODULE_NAME.into() &&
        struct_tag.name == TX_CONTEXT_STRUCT_NAME.into()
}

pub fn create_tx_context(caller: AccountAddress, ty: Type) -> Value {
    match ty {
        Type::MutableReference(ty) | Type::Reference(ty) => {
            if let Type::Struct(_struct_tag) = *ty {
                // struct TxContext has drop {
                //     /// The address of the user that signed the current transaction
                //     sender: address,
                //     /// Hash of the current transaction
                //     tx_hash: vector<u8>,
                //     /// The current epoch number
                //     epoch: u64,
                //     /// Timestamp that the epoch started at
                //     epoch_timestamp_ms: u64,
                //     /// Counter recording the number of fresh id's created while executing
                //     /// this transaction. Always 0 at the start of a transaction
                //     ids_created: u64
                // }
                let inner = Container::Struct(Rc::new(RefCell::new(vec![
                    ValueImpl::Address(caller),
                    ValueImpl::Container(Container::VecU8(Rc::new(RefCell::new(vec![6; 32])))),
                    ValueImpl::U64(123213),
                    ValueImpl::U64(2130127412),
                    ValueImpl::U64(0),
                ])));

                return Value(ValueImpl::ContainerRef(ContainerRef::Local(inner)));
            }
        }
        _ => unreachable!("tx context type mismatch"),
    }
    unreachable!()
}

impl<'a, SC, ISC> MoveCorpusInitializer<'a, SC, ISC>
where
    SC: Scheduler<State = MoveFuzzState>,
    ISC: Scheduler<State = MoveInfantStateState>,
{
    pub fn new(
        state: &'a mut MoveFuzzState,
        executor: &'a mut movevm::MoveVM<MoveFunctionInput, MoveFuzzState>,
        scheduler: SC,
        infant_scheduler: ISC,
    ) -> Self {
        Self {
            state,
            executor,
            scheduler,
            infant_scheduler,
            default_state: MoveStagedVMState::new_with_state(MoveVMState::new()),
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
        self.state.metadata_map_mut().insert(StructAbilities::new());
        self.state.metadata_map_mut().insert(ConstantPoolMetadata::new());
        self.state
            .infant_states_state
            .metadata_map_mut()
            .insert(MoveSchedulerMeta::new());

        // setup infant scheduler & corpus
        self.default_state = StagedVMState::new_with_state(MoveVMState::new());
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
        let mut modules_dependencies = vec![];
        for directory in dirs {
            let deps = glob::glob(&format!("{}/*/bytecode_modules/dependencies/*/*.mv", directory)).unwrap();

            for path in deps {
                let module = std::fs::read(path.unwrap()).unwrap();
                let module = CompiledModule::deserialize_no_check_bounds(&module).unwrap();
                modules_dependencies.push(module);
            }

            // find all directory named "bytecode_modules" in the current directory
            let paths = glob::glob(&format!("{}/*/bytecode_modules/*.mv", directory)).unwrap();
            for path in paths {
                // read the file into a vector of bytes
                let module = std::fs::read(path.unwrap()).unwrap();
                // deserialize the vector of bytes into a CompiledModule
                let module = CompiledModule::deserialize_no_check_bounds(&module).unwrap();
                // add the module to the corpus
                modules.push(module);
            }
        }
        self.add_module(modules, modules_dependencies);
    }

    fn extract_constants(&mut self, module: &CompiledModule) {
        let constant_pool = self
            .state
            .metadata_map_mut()
            .get_mut::<ConstantPoolMetadata>()
            .expect("failed to get constant pool metadata");

        module.constant_pool.iter().for_each(|constant| {
            constant_pool.add_constant(constant.data.clone());
        });

        module.function_defs.iter().for_each(|defs| {
            if let Some(ref code) = defs.code {
                code.code.iter().for_each(|instr| match instr {
                    Bytecode::LdU16(x) => {
                        constant_pool.add_constant((*x).to_le_bytes().to_vec());
                    }
                    Bytecode::LdU64(x) => {
                        constant_pool.add_constant((*x).to_le_bytes().to_vec());
                    }
                    Bytecode::LdU8(x) => {
                        constant_pool.add_constant((*x).to_le_bytes().to_vec());
                    }
                    Bytecode::LdU32(x) => {
                        constant_pool.add_constant((*x).to_le_bytes().to_vec());
                    }
                    Bytecode::LdU128(x) => {
                        constant_pool.add_constant((*x).to_le_bytes().to_vec());
                    }
                    Bytecode::LdU256(x) => {
                        constant_pool.add_constant((*x).to_le_bytes().to_vec());
                    }
                    _ => {}
                })
            }
        });
    }

    fn deployer(
        &mut self,
        to_deploy: Vec<ModuleId>,
        deployed: &mut HashSet<ModuleId>,
        module_id_to_module: &HashMap<ModuleId, CompiledModule>,
    ) {
        for mod_id in to_deploy {
            if deployed.contains(&mod_id) {
                continue;
            }

            let module = module_id_to_module.get(&mod_id).unwrap().clone();

            // push constants of module to mutator's constant hinting pool
            self.extract_constants(&module);

            let deps = module.immediate_dependencies();
            self.deployer(deps, deployed, module_id_to_module);
            self.executor.deploy(module, None, AccountAddress::random(), self.state);
            deployed.insert(mod_id);
        }
    }

    fn add_module(&mut self, modules: Vec<CompiledModule>, modules_dependencies: Vec<CompiledModule>) {
        macro_rules! wrap_input {
            ($input: expr) => {{
                let mut tc = Testcase::new($input);
                tc.set_exec_time(Duration::from_secs(0));
                tc
            }};
        }
        let mut module_id_to_module = HashMap::new();
        for module in modules.iter().chain(modules_dependencies.iter()) {
            module_id_to_module.insert(module.self_id(), module.clone());
        }
        self.deployer(
            modules.iter().map(|m| m.self_id()).collect_vec(),
            &mut HashSet::new(),
            &module_id_to_module,
        );

        let module_id_to_fuzz = modules.iter().map(|m| m.self_id()).collect::<HashSet<_>>();

        for (module_id, funcs) in self.executor.functions.clone() {
            if !module_id_to_fuzz.contains(&module_id) {
                continue;
            }

            for (name, func) in funcs {
                debug!("fuzzing: {:?}::{:?}", module_id, name);
                let input = self.build_input(&module_id, func.clone());
                match input {
                    Some(input) => {
                        let idx = self
                            .state
                            .add_tx_to_corpus(wrap_input!(input))
                            .expect("failed to add input to corpus");
                        self.scheduler
                            .on_add(self.state, idx)
                            .expect("failed to call scheduler on_add");
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
    #[allow(clippy::boxed_local)]
    fn gen_default_value(state: &mut MoveFuzzState, ty: Box<Type>) -> MoveInputStatus {
        match *ty {
            Type::Bool => MoveInputStatus::Complete(Value::bool(false)),
            Type::U8 => MoveInputStatus::Complete(Value::u8(0)),
            Type::U16 => MoveInputStatus::Complete(Value::u16(0)),
            Type::U32 => MoveInputStatus::Complete(Value::u32(0)),
            Type::U64 => MoveInputStatus::Complete(Value::u64(0)),
            Type::U128 => MoveInputStatus::Complete(Value::u128(0)),
            Type::U256 => MoveInputStatus::Complete(Value::u256(U256::zero())),
            Type::Address => MoveInputStatus::Complete(Value::address(state.get_rand_address())),
            Type::Signer => MoveInputStatus::Complete(Value::signer(state.get_rand_address())),
            Type::Vector(v) => {
                macro_rules! wrap {
                    ($v: ident, $default: expr) => {
                        MoveInputStatus::Complete(Value(ValueImpl::Container(Container::$v(Rc::new(
                            RefCell::new($default),
                        )))))
                    };
                }
                match *v.clone() {
                    Type::Vector(_) => todo!("vector of vector"),
                    Type::Bool => {
                        wrap!(VecBool, vec![false])
                    }
                    Type::U8 => {
                        wrap!(VecU8, vec![0])
                    }
                    Type::U64 => {
                        wrap!(VecU64, vec![0])
                    }
                    Type::U128 => {
                        wrap!(VecU128, vec![0])
                    }
                    Type::U16 => {
                        wrap!(VecU16, vec![0])
                    }
                    Type::U32 => {
                        wrap!(VecU32, vec![0])
                    }
                    Type::U256 => {
                        wrap!(VecU256, vec![U256::zero()])
                    }
                    Type::Address => {
                        wrap!(VecAddress, vec![state.get_rand_address()])
                    }
                    Type::Signer => {
                        unreachable!("cannot initialize signer vector")
                    }
                    Type::Reference(_) |
                    Type::MutableReference(_) |
                    Type::Struct(_) |
                    Type::StructInstantiation(_, _) => {
                        let default_inner = Self::gen_default_value(state, v);
                        if let MoveInputStatus::Complete(Value(inner)) = default_inner {
                            wrap!(Vec, vec![inner])
                        } else if let MoveInputStatus::DependentOnStructs(Value(inner), deps) = default_inner {
                            MoveInputStatus::DependentOnStructs(
                                Value(ValueImpl::Container(Container::Vec(Rc::new(RefCell::new(vec![inner]))))),
                                deps,
                            )
                        } else {
                            unreachable!()
                        }
                    }
                    _ => unreachable!(),
                }
            }
            Type::Struct(_) | Type::StructInstantiation(_, _) => MoveInputStatus::DependentOnStructs(
                Value(ValueImpl::Container(Container::Struct(Rc::new(RefCell::new(vec![]))))),
                vec![*ty],
            ),
            Type::Reference(ty) | Type::MutableReference(ty) => {
                let default_inner = Self::gen_default_value(state, ty);
                if let MoveInputStatus::Complete(Value(inner)) = default_inner {
                    if let ValueImpl::Container(inner_v) = inner {
                        MoveInputStatus::Complete(Value(ValueImpl::ContainerRef(ContainerRef::Local(inner_v))))
                    } else {
                        MoveInputStatus::Complete(Value(ValueImpl::IndexedRef(IndexedRef {
                            idx: 0,
                            container_ref: ContainerRef::Local(Container::Locals(Rc::new(RefCell::new(vec![inner])))),
                        })))
                    }
                } else if let MoveInputStatus::DependentOnStructs(Value(ValueImpl::Container(cont)), deps) =
                    default_inner
                {
                    MoveInputStatus::DependentOnStructs(Value(ValueImpl::ContainerRef(ContainerRef::Local(cont))), deps)
                } else {
                    unreachable!()
                }
            }
            ty => todo!("gen_default_value failed: {:?}", ty),
        }
    }

    pub fn gen_tx_context(&mut self, ty: Type) -> Value {
        create_tx_context(self.state.get_rand_caller(), ty)
    }

    fn build_input(&mut self, module_id: &ModuleId, function: Arc<Function>) -> Option<MoveFunctionInput> {
        let mut values = vec![];
        let mut resolved = true;
        let mut deps = HashMap::new();
        let type_tag_info = self
            .state
            .metadata_map()
            .get::<TypeTagInfoMeta>()
            .expect("type tag info not found")
            .clone();
        for parameter_type in &function.parameter_types {
            let tag = type_tag_info.get_type_tag(parameter_type);
            let default_val = if let Some(tag) = tag &&
                is_tx_context(tag)
            {
                MoveInputStatus::Complete(self.gen_tx_context(parameter_type.clone()))
            } else {
                Self::gen_default_value(self.state, Box::new(parameter_type.clone()))
            };

            match default_val {
                MoveInputStatus::Complete(v) => {
                    values.push(CloneableValue::from(v));
                }
                MoveInputStatus::DependentOnStructs(vals, tys) => {
                    values.push(CloneableValue::from(vals));
                    tys.iter().for_each(|ty| {
                        *deps.entry(ty.clone()).or_insert(0) += 1;
                    });
                    resolved = false;
                }
            }
        }

        let input = MoveFunctionInput {
            module: module_id.clone(),
            function: function.name.clone(),
            function_info: Arc::new(FunctionDefaultable {
                function: Some(function),
            }),
            args: values,
            ty_args: vec![],
            caller: self.state.get_rand_caller(),
            vm_state: StagedVMState::new_uninitialized(),
            vm_state_idx: 0,
            _deps: deps,
            _resolved: resolved,
        };

        // debug!("input: {:?}", input);
        Some(input)
    }
}
