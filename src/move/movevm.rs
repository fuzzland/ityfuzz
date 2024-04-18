use std::{
    any::Any,
    collections::{BTreeMap, HashMap, VecDeque},
    fmt::Debug,
    sync::Arc,
};

use libafl::state::HasMetadata;
use libafl_bolts::impl_serdeany;
use move_binary_format::{access::ModuleAccess, file_format::Bytecode, CompiledModule};
use move_core_types::{
    account_address::AccountAddress,
    identifier::Identifier,
    language_storage::{ModuleId, StructTag, TypeTag},
};
use move_vm_runtime::{
    interpreter::{CallStack, ExitCode, Frame, Interpreter, ItyFuzzTracer, Stack},
    loader::{BinaryType::Module, Function, Loader, Resolver, StructTagType},
    native_extensions::NativeContextExtensions,
    native_functions::{NativeContext, NativeFunctions},
};
use move_vm_types::{
    data_store::DataStore,
    gas::{GasMeter, UnmeteredGasMeter},
    loaded_data::runtime_types::Type,
    natives::function::NativeResult,
    values::{Container, Locals, Reference, StructRef, VMValueCast, Value, ValueImpl},
};
use revm_primitives::HashSet;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sui_move_natives_latest::{object_runtime::ObjectRuntime, NativesCostTable};
use sui_protocol_config::ProtocolConfig;
use sui_types::{
    base_types::{ObjectID, SequenceNumber},
    error::SuiResult,
    metrics::LimitsMetrics,
    object::{Object, Owner},
    storage::ChildObjectResolver,
};
use tracing::debug;

use super::types::MoveFuzzState;
use crate::{
    generic_vm::{
        vm_executor::{ExecutionResult, GenericVM, MAP_SIZE},
        vm_state::VMStateT,
    },
    input::VMInputT,
    r#move::{
        corpus_initializer::{create_tx_context, is_tx_context, MoveCorpusInitializer},
        input::{ConciseMoveInput, FunctionDefaultable, MoveFunctionInput, MoveFunctionInputT},
        types::{MoveAddress, MoveOutput},
        vm_state::{Gate, GatedValue, MoveVMState},
    },
    state::HasCaller,
    state_input::StagedVMState,
};

pub static mut MOVE_COV_MAP: [u8; MAP_SIZE] = [0u8; MAP_SIZE];
pub static mut MOVE_CMP_MAP: [u128; MAP_SIZE] = [0; MAP_SIZE];
pub static mut MOVE_READ_MAP: [bool; MAP_SIZE] = [false; MAP_SIZE];
pub static mut MOVE_WRITE_MAP: [u8; MAP_SIZE] = [0u8; MAP_SIZE];
pub static mut MOVE_STATE_CHANGED: bool = false;
pub struct MoveVM<I, S> {
    // for comm with move_vm
    pub functions: HashMap<ModuleId, HashMap<Identifier, Arc<Function>>>,
    pub loader: Loader,
    pub protocol_config: ProtocolConfig,
    pub native_context: NativeContextExtensions<'static>,
    _phantom: std::marker::PhantomData<(I, S)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeTagInfoMeta {
    pub type_to_type_tag: HashMap<Type, StructTag>,
    pub tx_context: HashSet<Type>,
}

impl_serdeany!(TypeTagInfoMeta);

impl Default for TypeTagInfoMeta {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeTagInfoMeta {
    pub fn new() -> Self {
        Self {
            type_to_type_tag: HashMap::new(),
            tx_context: HashSet::new(),
        }
    }
    pub fn register_type_tag(&mut self, ty: Type, loader: &Loader) {
        let tag = self.find_type(&ty, loader);
        if let TypeTag::Struct(struct_tag) = tag {
            if is_tx_context(&struct_tag) {
                self.tx_context.insert(ty.clone());
            }
            self.type_to_type_tag.insert(ty, *struct_tag);
        }
    }
    pub fn is_tx_context(&self, ty: &Type) -> bool {
        self.tx_context.contains(ty)
    }
    pub fn get_type_tag(&self, ty: &Type) -> Option<&StructTag> {
        self.type_to_type_tag.get(ty)
    }
    #[allow(clippy::only_used_in_recursion)]
    pub fn find_type(&mut self, ty: &Type, loader: &Loader) -> TypeTag {
        match ty {
            Type::Bool => TypeTag::Bool,
            Type::U8 => TypeTag::U8,
            Type::U16 => TypeTag::U16,
            Type::U32 => TypeTag::U32,
            Type::U64 => TypeTag::U64,
            Type::U128 => TypeTag::U128,
            Type::U256 => TypeTag::U256,
            Type::Address => TypeTag::Address,
            Type::Signer => TypeTag::Signer,
            Type::Vector(ty) => TypeTag::Vector(Box::new(self.find_type(ty, loader))),
            Type::Struct(gidx) => TypeTag::Struct(Box::new(
                loader
                    .struct_gidx_to_type_tag(*gidx, &[], StructTagType::Defining)
                    .expect("struct tag"),
            )),
            Type::StructInstantiation(gidx, ty_args) => {
                match loader.struct_gidx_to_type_tag(*gidx, ty_args.as_slice(), StructTagType::Defining) {
                    Ok(v) => TypeTag::Struct(Box::new(v)),
                    Err(_) => TypeTag::Bool,
                }
            }
            Type::Reference(v) | Type::MutableReference(v) => self.find_type(v, loader),
            _ => TypeTag::Bool,
        }
    }
}

impl<I, S> Default for MoveVM<I, S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I, S> MoveVM<I, S> {
    pub fn new() -> Self {
        let functions = HashMap::new();
        Self {
            functions,
            loader: Loader::new(Self::get_natives(), Default::default()),
            protocol_config: Self::get_protocol_config(),
            native_context: Self::get_extension(),
            _phantom: Default::default(),
        }
    }

    pub fn get_natives() -> NativeFunctions {
        NativeFunctions::new(sui_move_natives_latest::all_natives(true)).expect("native functions")
    }

    pub fn get_protocol_config() -> ProtocolConfig {
        ProtocolConfig::get_for_max_version_UNSAFE()
    }

    pub fn get_extension<'a>() -> NativeContextExtensions<'a> {
        let mut extensions = NativeContextExtensions::default();
        extensions.add(ObjectRuntime::new(
            &DummyChildObjectResolver {},
            BTreeMap::new(),
            false,
            &Self::get_protocol_config(),
            Arc::new(LimitsMetrics::new(&Default::default())),
        ));
        extensions.add(NativesCostTable::from_protocol_config(&Self::get_protocol_config()));
        extensions
    }

    pub fn clear_context(&mut self) {
        let state = &mut self.native_context.get_mut::<ObjectRuntime>().state;
        state.events.clear();
        state.deleted_ids.clear();
        state.new_ids.clear();
        state.input_objects.clear();
        state.transfers.clear();
        state.total_events_size = 0;
    }

    pub fn call_native(
        func: Arc<Function>,
        ty_args: Vec<Type>,
        interp: &mut Interpreter,
        state: &mut dyn DataStore,
        resolver: &Resolver,
        gas_meter: &mut impl GasMeter,
        extension: &mut NativeContextExtensions<'_>,
    ) -> bool {
        let mut args = VecDeque::new();
        let expected_args = func.parameters.len();
        for _ in 0..expected_args {
            args.push_front(interp.operand_stack.pop().expect("operand stack underflow"));
        }

        let mut native_context = NativeContext::new(interp, state, resolver, extension, gas_meter.remaining_gas());

        let native_function = func.get_native().expect("native function not found");
        let result: NativeResult = native_function(&mut native_context, ty_args, args).unwrap();
        let return_values = match result.result {
            Ok(values) => values,
            _ => {
                return false;
            }
        };
        for value in return_values {
            let _ = interp.operand_stack.push(value);
        }
        // debug!("ext: {:?}", ext.get::<ObjectRuntime>().state.events);
        true
    }
}

pub struct MoveVMTracer;

impl ItyFuzzTracer for MoveVMTracer {
    fn on_step(&mut self, interpreter: &Interpreter, _frame: &Frame, pc: u16, instruction: &Bytecode) {
        macro_rules! fast_peek_back {
            ($interp: expr) => {
                &$interp.operand_stack.value[$interp.operand_stack.value.len() - 1]
            };
            ($interp: expr, $kth: expr) => {
                &$interp.operand_stack.value[$interp.operand_stack.value.len() - $kth]
            };
        }
        macro_rules! distance {
            ($cond:expr, $l:expr, $v:expr) => {
                if !($cond) {
                    if *$l > *$v {
                        (*$l - *$v) as u128
                    } else {
                        (*$v - *$l) as u128
                    }
                } else {
                    0u128
                }
            };
        }

        match instruction {
            // COV MAP
            Bytecode::BrTrue(offset) => {
                if let Value(ValueImpl::Bool(b)) = fast_peek_back!(interpreter) {
                    let next_pc = if *b { *offset } else { pc + 1 };
                    let map_offset = next_pc as usize % MAP_SIZE;
                    unsafe {
                        MOVE_COV_MAP[map_offset] = (MOVE_COV_MAP[map_offset] + 1) % 255;
                    }
                } else {
                    unreachable!("brtrue with non-bool value")
                }
            }
            Bytecode::BrFalse(offset) => {
                if let Value(ValueImpl::Bool(b)) = fast_peek_back!(interpreter) {
                    let next_pc = if !*b { *offset } else { pc + 1 };
                    let map_offset = next_pc as usize % MAP_SIZE;
                    unsafe {
                        MOVE_COV_MAP[map_offset] = (MOVE_COV_MAP[map_offset] + 1) % 255;
                    }
                } else {
                    unreachable!("brfalse with non-bool value")
                }
            }

            // CMP MAP
            Bytecode::Eq => {
                let distance = match (fast_peek_back!(interpreter), fast_peek_back!(interpreter, 2)) {
                    (Value(ValueImpl::U8(l)), Value(ValueImpl::U8(r))) => distance!(*l == *r, l, r),
                    (Value(ValueImpl::U16(l)), Value(ValueImpl::U16(r))) => distance!(*l == *r, l, r),
                    (Value(ValueImpl::U32(l)), Value(ValueImpl::U32(r))) => distance!(*l == *r, l, r),
                    (Value(ValueImpl::U64(l)), Value(ValueImpl::U64(r))) => distance!(*l == *r, l, r),
                    (Value(ValueImpl::U128(l)), Value(ValueImpl::U128(r))) => distance!(*l == *r, l, r),
                    (Value(ValueImpl::U256(l)), Value(ValueImpl::U256(r))) => {
                        distance!(*l == *r, &l.unchecked_as_u128(), &r.unchecked_as_u128())
                    }
                    (Value(ValueImpl::Bool(l)), Value(ValueImpl::Bool(r))) => {
                        if l == r {
                            0
                        } else {
                            1
                        }
                    }
                    _ => u128::MAX,
                };

                let map_offset = pc as usize % MAP_SIZE;
                if unsafe { MOVE_CMP_MAP[map_offset] > distance } {
                    unsafe {
                        MOVE_CMP_MAP[map_offset] = distance;
                    }
                }
            }
            Bytecode::Neq => {}
            Bytecode::Lt | Bytecode::Le => {
                let distance = match (fast_peek_back!(interpreter), fast_peek_back!(interpreter, 2)) {
                    (Value(ValueImpl::U8(l)), Value(ValueImpl::U8(r))) => distance!(*l <= *r, l, r),
                    (Value(ValueImpl::U16(l)), Value(ValueImpl::U16(r))) => distance!(*l <= *r, l, r),
                    (Value(ValueImpl::U32(l)), Value(ValueImpl::U32(r))) => distance!(*l <= *r, l, r),
                    (Value(ValueImpl::U64(l)), Value(ValueImpl::U64(r))) => distance!(*l <= *r, l, r),
                    (Value(ValueImpl::U128(l)), Value(ValueImpl::U128(r))) => distance!(*l <= *r, l, r),
                    (Value(ValueImpl::U256(l)), Value(ValueImpl::U256(r))) => {
                        distance!(*l <= *r, &l.unchecked_as_u128(), &r.unchecked_as_u128())
                    }
                    _ => u128::MAX,
                };

                let map_offset = pc as usize % MAP_SIZE;
                if unsafe { MOVE_CMP_MAP[map_offset] > distance } {
                    unsafe {
                        MOVE_CMP_MAP[map_offset] = distance;
                    }
                }
            }
            Bytecode::Gt | Bytecode::Ge => {
                let distance = match (fast_peek_back!(interpreter), fast_peek_back!(interpreter, 2)) {
                    (Value(ValueImpl::U8(l)), Value(ValueImpl::U8(r))) => distance!(*l >= *r, l, r),
                    (Value(ValueImpl::U16(l)), Value(ValueImpl::U16(r))) => distance!(*l >= *r, l, r),
                    (Value(ValueImpl::U32(l)), Value(ValueImpl::U32(r))) => distance!(*l >= *r, l, r),
                    (Value(ValueImpl::U64(l)), Value(ValueImpl::U64(r))) => distance!(*l >= *r, l, r),
                    (Value(ValueImpl::U128(l)), Value(ValueImpl::U128(r))) => distance!(*l >= *r, l, r),
                    (Value(ValueImpl::U256(l)), Value(ValueImpl::U256(r))) => {
                        distance!(*l >= *r, &l.unchecked_as_u128(), &r.unchecked_as_u128())
                    }
                    _ => u128::MAX,
                };

                let map_offset = pc as usize % MAP_SIZE;
                if unsafe { MOVE_CMP_MAP[map_offset] > distance } {
                    unsafe {
                        MOVE_CMP_MAP[map_offset] = distance;
                    }
                }
            }

            // RW MAP & Onchain stuffs
            Bytecode::MutBorrowGlobal(sd_idx) |
            Bytecode::ImmBorrowGlobal(sd_idx) |
            Bytecode::Exists(sd_idx) |
            Bytecode::MoveFrom(sd_idx) => unsafe {
                let addr_off = if let Value(ValueImpl::Address(addr)) = fast_peek_back!(interpreter) {
                    u128::from_le_bytes(
                        addr.as_slice()[addr.len() - 16..]
                            .try_into()
                            .expect("slice with incorrect length"),
                    )
                } else {
                    unreachable!("borrow_global with non-address value")
                };
                let offset = sd_idx.0;
                let map_offset = (addr_off.unchecked_add(offset as u128) % (MAP_SIZE as u128)) as usize;
                if !MOVE_READ_MAP[map_offset] {
                    MOVE_READ_MAP[map_offset] = true;
                }
            },
            Bytecode::MutBorrowGlobalGeneric(sd_idx) |
            Bytecode::ImmBorrowGlobalGeneric(sd_idx) |
            Bytecode::ExistsGeneric(sd_idx) |
            Bytecode::MoveFromGeneric(sd_idx) => unsafe {
                let addr_off = if let Value(ValueImpl::Address(addr)) = fast_peek_back!(interpreter) {
                    u128::from_le_bytes(
                        addr.as_slice()[addr.len() - 16..]
                            .try_into()
                            .expect("slice with incorrect length"),
                    )
                } else {
                    unreachable!("borrow_global with non-address value")
                };
                let offset = sd_idx.0;
                let map_offset = (addr_off.unchecked_add(offset as u128) % (MAP_SIZE as u128)) as usize;
                if !MOVE_READ_MAP[map_offset] {
                    MOVE_READ_MAP[map_offset] = true;
                }
            },
            Bytecode::MoveTo(sd_idx) => unsafe {
                MOVE_STATE_CHANGED = true;
                let addr_struct: StructRef = fast_peek_back!(interpreter, 2).clone().cast().unwrap();
                let addr = addr_struct
                    .borrow_field(0)
                    .unwrap()
                    .value_as::<Reference>()
                    .unwrap()
                    .read_ref()
                    .unwrap()
                    .value_as::<AccountAddress>()
                    .unwrap();

                let addr_off = u128::from_le_bytes(
                    addr.as_slice()[addr.len() - 16..]
                        .try_into()
                        .expect("slice with incorrect length"),
                );
                let offset = sd_idx.0;
                let map_offset = (addr_off.unchecked_add(offset as u128) % (MAP_SIZE as u128)) as usize;
                if MOVE_WRITE_MAP[map_offset] == 0 {
                    MOVE_WRITE_MAP[map_offset] = 1;
                }
            },
            Bytecode::MoveToGeneric(sd_idx) => unsafe {
                MOVE_STATE_CHANGED = true;
                let addr_struct: StructRef = fast_peek_back!(interpreter, 2).clone().cast().unwrap();
                let addr = addr_struct
                    .borrow_field(0)
                    .unwrap()
                    .value_as::<Reference>()
                    .unwrap()
                    .read_ref()
                    .unwrap()
                    .value_as::<AccountAddress>()
                    .unwrap();

                let addr_off = u128::from_le_bytes(
                    addr.as_slice()[addr.len() - 16..]
                        .try_into()
                        .expect("slice with incorrect length"),
                );
                let offset = sd_idx.0;
                let map_offset = (addr_off.unchecked_add(offset as u128) % (MAP_SIZE as u128)) as usize;
                if MOVE_WRITE_MAP[map_offset] == 0 {
                    MOVE_WRITE_MAP[map_offset] = 1;
                }
            },

            // Onchain stuffs
            Bytecode::Call(_) => {}
            Bytecode::CallGeneric(_) => {}
            _ => {}
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
        u128,
        MoveOutput,
        I,
        S,
        ConciseMoveInput,
    > for MoveVM<I, S>
where
    I: VMInputT<MoveVMState, ModuleId, AccountAddress, ConciseMoveInput> + MoveFunctionInputT + 'static,
    S: HasMetadata + HasCaller<MoveAddress> + 'static,
{
    fn deploy(
        &mut self,
        module: CompiledModule,
        _constructor_args: Option<MoveFunctionInput>,
        _deployed_address: AccountAddress,
        state: &mut S,
    ) -> Option<AccountAddress> {
        // debug!("deploying module dep: {:?}", module.self_id());

        if !state.metadata_map_mut().contains::<TypeTagInfoMeta>() {
            state.metadata_map_mut().insert(TypeTagInfoMeta::new());
        }

        let func_off = self.loader.module_cache.read().functions.len();
        let _module_name = module.name().to_owned();
        let deployed_module_idx = module.self_id();
        self.loader
            .module_cache
            .write()
            .insert(
                &Self::get_natives(),
                &MoveVMState::default(),
                deployed_module_idx.clone(),
                &module,
            )
            .expect("internal deploy error");

        for f in &self.loader.module_cache.read().functions[func_off..] {
            // debug!("deployed function: {:?}@{}({:?}) returns {:?}", deployed_module_idx,
            // f.name.as_str(), f.parameter_types, f.return_types());
            self.functions
                .entry(deployed_module_idx.clone())
                .or_default()
                .insert(f.name.to_owned(), f.clone());
            let meta = state.metadata_map_mut().get_mut::<TypeTagInfoMeta>().unwrap();
            for ty in &f.parameter_types {
                meta.register_type_tag(ty.clone(), &self.loader);
            }
        }

        let init_func = self.loader.module_cache.read().functions[func_off..]
            .iter()
            .filter(|f| f.name.as_str() == "init")
            .map(|f| f.clone())
            .next();
        if let Some(init_func) = init_func {
            let otw = &init_func.parameters;
            debug!(
                "init function found {:?} {_module_name} {:?}",
                otw, init_func.parameter_types
            );
            let mut args = vec![];
            if otw.len() == 1 {
                args.push(create_tx_context(
                    state.get_rand_caller(),
                    init_func.parameter_types[0].clone(),
                ));
            }

            let move_input = MoveFunctionInput {
                module: deployed_module_idx.clone(),
                function: init_func.name.clone(),
                function_info: Arc::new(FunctionDefaultable::new(init_func.clone())),
                args: vec![],
                ty_args: vec![],
                caller: AccountAddress::ZERO,
                vm_state: StagedVMState::new_with_state(MoveVMState::default()),
                vm_state_idx: 0,
                _deps: Default::default(),
                _resolved: true,
            };
            let res = self.execute(&move_input.as_any().downcast_ref::<I>().unwrap(), state);
            println!("init function found {:?}", res);
        }

        Some(*deployed_module_idx.address())
    }

    fn fast_static_call(
        &mut self,
        _data: &[(AccountAddress, MoveFunctionInput)],
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

    fn fast_call(
        &mut self,
        _data: &[(AccountAddress, AccountAddress, MoveFunctionInput)],
        _vm_state: &MoveVMState,
        _state: &mut S,
    ) -> (Vec<(MoveOutput, bool)>, MoveVMState)
    where
        MoveVMState: VMStateT,
        AccountAddress: Serialize + DeserializeOwned + Debug,
        ModuleId: Serialize + DeserializeOwned + Debug,
        MoveOutput: Default,
    {
        todo!()
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn execute(
        &mut self,
        input: &I,
        state: &mut S,
    ) -> ExecutionResult<ModuleId, AccountAddress, MoveVMState, MoveOutput, ConciseMoveInput>
    where
        MoveVMState: VMStateT,
    {
        let initial_function = self
            .functions
            .get(input.module_id())
            .unwrap()
            .get(input.function_name())
            .unwrap();

        // debug!("running input: {:?}", input.function_name());

        // debug!("running {:?} {:?}", initial_function.name.as_str(),
        // initial_function.scope);

        // setup interpreter
        let mut interp = Interpreter {
            operand_stack: Stack::new(),
            call_stack: CallStack::new(),
            paranoid_type_checks: false,
            runtime_limits_config: Default::default(),
        };

        let mut vm_state = input.get_state().clone();
        unsafe {
            MOVE_STATE_CHANGED = false;
        }

        // set up initial frame
        let mut current_frame = {
            let mut locals = Locals::new(initial_function.local_count());
            for (i, value) in input.args().iter().enumerate() {
                locals.store_loc(i, value.clone().value, false).unwrap();
            }
            Frame {
                pc: 0,
                locals,
                function: initial_function.clone(),
                ty_args: vec![],
                local_tys: vec![],
            }
        };

        let mut call_stack = vec![];
        let mut reverted = false;
        let mut native_called = false;
        let mut gas_meter = UnmeteredGasMeter {};

        // debug!("running {:?} with args {:?}", initial_function.name.as_str(),
        // input.args());

        loop {
            let resolver = current_frame.resolver(vm_state.link_context(), &self.loader);
            let ret = current_frame.execute_code(
                &resolver,
                &mut interp,
                &mut vm_state,
                &mut gas_meter,
                &mut MoveVMTracer {},
            );
            // debug!("{:?}", ret);

            if ret.is_err() {
                debug!("reverted {:?}", ret);
                reverted = true;
                break;
            }

            match ret.unwrap() {
                ExitCode::Return => match call_stack.pop() {
                    Some(frame) => {
                        current_frame = frame;
                        current_frame.pc += 1;
                    }
                    None => {
                        break;
                    }
                },
                ExitCode::Call(fh_idx) => {
                    // todo: handle native here
                    let func = resolver.function_from_handle(fh_idx);

                    if func.is_native() {
                        // debug!("calling native function: {:?}", func.name.as_str());
                        native_called = true;
                        if !Self::call_native(
                            func,
                            vec![],
                            &mut interp,
                            &mut vm_state,
                            &resolver,
                            &mut gas_meter,
                            &mut self.native_context,
                        ) {
                            reverted = true;
                            break;
                        } else {
                            current_frame.pc += 1;
                        }
                        continue;
                    }
                    let argc = func.parameters.len();
                    let mut locals = Locals::new(func.local_count());
                    // debug!("function: {:?} with {} args ({})", func.name, func.local_count(),
                    // func.parameters.len());
                    for i in 0..argc {
                        locals
                            .store_loc(argc - i - 1, interp.operand_stack.pop().unwrap(), false)
                            .unwrap();
                    }
                    // debug!("locals: {:?}", locals);
                    call_stack.push(current_frame);
                    current_frame = Frame {
                        pc: 0,
                        locals,
                        function: func.clone(),
                        ty_args: vec![],
                        local_tys: vec![],
                    };
                }
                ExitCode::CallGeneric(fh_idx) => {
                    let ty_args = resolver
                        .instantiate_generic_function(fh_idx, &current_frame.ty_args)
                        .unwrap();
                    let func = resolver.function_from_instantiation(fh_idx);

                    // todo: handle native here
                    if func.is_native() {
                        native_called = true;
                        if !Self::call_native(
                            func,
                            ty_args,
                            &mut interp,
                            &mut vm_state,
                            &resolver,
                            &mut gas_meter,
                            &mut self.native_context,
                        ) {
                            reverted = true;
                            break;
                        } else {
                            current_frame.pc += 1;
                        }
                        continue;
                    }

                    let argc = func.parameters.len();
                    let mut locals = Locals::new(func.local_count());
                    for i in 0..argc {
                        locals
                            .store_loc(argc - i - 1, interp.operand_stack.pop().unwrap(), false)
                            .unwrap();
                    }
                    call_stack.push(current_frame);
                    current_frame = Frame {
                        pc: 0,
                        locals,
                        function: func.clone(),
                        ty_args,
                        local_tys: vec![],
                    };
                }
            }
        }

        let resolver = current_frame.resolver(vm_state.link_context(), &self.loader);

        let mut out: MoveOutput = MoveOutput { vars: vec![] };

        // debug!("{:?}", interp.operand_stack.value);

        macro_rules! add_value {
            ($v: expr, $t: expr, $gate: expr) => {{
                let res = vm_state.add_new_value(
                    GatedValue {
                        v: $v.clone(),
                        gate: $gate,
                    },
                    $t,
                    &resolver,
                    state,
                );

                if res {
                    unsafe {
                        MOVE_STATE_CHANGED = true;
                    }
                }
            }};
        }
        for (v, t) in interp
            .operand_stack
            .value
            .iter()
            .zip(initial_function.return_types().iter())
        {
            add_value!(v, t, Gate::Own);
            // debug!("adding as own: {:?}", v);
            out.vars.push((t.clone(), v.clone()));
            // debug!("val: {:?} {:?}", v, resolver.loader.type_to_type_tag(t));
        }

        if native_called {
            for (_uid, (owner, ty, value)) in &self.native_context.get::<ObjectRuntime>().state.transfers {
                let gate = match owner {
                    Owner::AddressOwner(addr) => {
                        if state.has_caller(&MoveAddress::new(addr.to_vec().try_into().unwrap())) {
                            Gate::MutRef
                        } else {
                            continue;
                        }
                    }
                    Owner::ObjectOwner(_addr) => {
                        continue;
                    }
                    Owner::Shared { .. } => Gate::MutRef,
                    Owner::Immutable => Gate::Ref,
                };

                // debug!("adding as {:?}: {:?}", gate, value);

                add_value!(value, ty, gate);
                // debug!("transfer: {:?}", t);
            }

            for (_t, st, v) in &self.native_context.get::<ObjectRuntime>().state.events {
                // debug!("st.name.as_str(): {:?}, v: {:?}", st.name.as_str(), v);
                if st.name.as_str() == "AAAA__fuzzland_move_bug" {
                    if let Value(ValueImpl::Container(Container::Struct(data))) = v {
                        let data = (**data).borrow();
                        let item = data.first().expect("invalid event data");
                        if let ValueImpl::U64(data) = item {
                            vm_state.typed_bug.push(format!("bug{}", *data));
                        } else {
                            panic!("invalid event data");
                        }
                    } else {
                        panic!("invalid event data");
                    }
                }
            }
            self.clear_context();
        }

        ExecutionResult {
            new_state: StagedVMState::new_with_state(vm_state),
            output: out,
            reverted,
            additional_info: None,
        }
    }

    fn get_jmp(&self) -> &'static mut [u8; MAP_SIZE] {
        unsafe { &mut MOVE_COV_MAP }
    }

    fn get_read(&self) -> &'static mut [bool; MAP_SIZE] {
        unsafe { &mut MOVE_READ_MAP }
    }

    fn get_write(&self) -> &'static mut [u8; MAP_SIZE] {
        unsafe { &mut MOVE_WRITE_MAP }
    }

    fn get_cmp(&self) -> &'static mut [u128; MAP_SIZE] {
        unsafe { &mut MOVE_CMP_MAP }
    }

    fn state_changed(&self) -> bool {
        unsafe { MOVE_STATE_CHANGED }
    }
}

pub struct DummyChildObjectResolver;

impl ChildObjectResolver for DummyChildObjectResolver {
    fn read_child_object(
        &self,
        _parent: &ObjectID,
        _child: &ObjectID,
        _child_version_upper_bound: SequenceNumber,
    ) -> SuiResult<Option<Object>> {
        todo!()
    }
}

pub fn dummy_loader(state: &mut MoveFuzzState) -> Loader {
    // module 0x3::TestMod {
    //     resource struct TestStruct {
    //         data: u64
    //     }
    //     public fun test1(data: u64) : TestStruct {
    //         TestStruct { data };
    //     }
    // }
    let bytecode = "a11ceb0b0500000008010002020204030605050b0607111e082f200a4f050c540b000000010200000200010001030108000007546573744d6f640a546573745374727563740574657374310464617461000000000000000000000000000000000000000000000000000000000000000300020103030001000002030b0012000200";

    let module_bytecode = hex::decode(bytecode).unwrap();
    let module = CompiledModule::deserialize_no_check_bounds(&module_bytecode).unwrap();

    let mut vm = MoveVM::<MoveFunctionInput, MoveFuzzState>::new();
    let deployed_address = AccountAddress::ZERO;
    let _ = vm.deploy(module, None, deployed_address, state);

    vm.loader
}

pub fn dummy_resolver(loader: &Loader) -> Resolver {
    let compiled = loader
        .module_cache
        .read()
        .compiled_modules
        .binaries
        .first()
        .unwrap()
        .clone();
    let loaded = loader
        .module_cache
        .read()
        .loaded_modules
        .binaries
        .first()
        .unwrap()
        .clone();
    let binary = Module { compiled, loaded };

    Resolver { loader, binary }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Borrow, cell::RefCell, rc::Rc};

    use move_vm_types::{
        loaded_data::runtime_types::{CachedStructIndex, Type::Struct},
        values::{self, ContainerRef, Value, ValueImpl},
    };
    use tracing::debug;

    use super::*;
    use crate::{
        r#move::input::{CloneableValue, ConciseMoveInput},
        state::FuzzState,
    };

    fn _run(
        bytecode: &str,
        args: Vec<CloneableValue>,
        func: &str,
    ) -> ExecutionResult<ModuleId, AccountAddress, MoveVMState, MoveOutput, ConciseMoveInput> {
        let module_bytecode = hex::decode(bytecode).unwrap();
        let module = CompiledModule::deserialize_no_check_bounds(&module_bytecode).unwrap();
        let _module_idx = module.self_id();
        let mut mv = MoveVM::<
            MoveFunctionInput,
            FuzzState<MoveFunctionInput, MoveVMState, ModuleId, AccountAddress, MoveOutput, ConciseMoveInput>,
        >::new();
        let _loc = mv
            .deploy(module, None, AccountAddress::new([0; 32]), &mut FuzzState::new(0))
            .unwrap();

        assert_eq!(mv.functions.len(), 1);

        let input = MoveFunctionInput {
            // take the first module
            module: mv
                .loader
                .module_cache
                .read()
                .compiled_modules
                .id_map
                .iter()
                .next()
                .unwrap()
                .0
                .clone(),
            function: Identifier::new(func).unwrap(),
            function_info: Default::default(),
            args,
            ty_args: vec![],
            caller: AccountAddress::new([1; 32]),
            vm_state: StagedVMState {
                state: MoveVMState {
                    resources: Default::default(),
                    _gv_slot: Default::default(),
                    _hot_potato: 0,
                    values: Default::default(),
                    typed_bug: vec![],
                    ref_in_use: vec![],
                },
                stage: vec![],
                initialized: false,
                trace: Default::default(),
            },
            vm_state_idx: 0,
            _deps: Default::default(),
            _resolved: true,
        };
        mv.execute(&input.clone(), &mut FuzzState::new(0))
    }

    #[test]
    fn test_move_vm_simple() {
        // module 0x3::TestMod {
        //         public fun test1(data: u64) : u64 {
        //         data * 2
        //     }
        // }

        let module_hex = "a11ceb0b0500000006010002030205050703070a0e0818200c38130000000100000001030007546573744d6f6405746573743100000000000000000000000000000000000000000000000000000000000000030001000001040b00060200000000000000180200";
        _run(module_hex, vec![CloneableValue::from(Value::u64(20))], "test1");
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
        _run(module_hex, vec![CloneableValue::from(Value::u64(20))], "test1");
    }

    #[test]
    fn test_args() {
        let module_hex = "a11ceb0b060000000901000202020403060a05100a071a290843200a63070c6a270d91010200020000020000040001000003020300000108000106080001030b50726f66696c65496e666f046e616d650770726f66696c650574657374310574657374320375726c0000000000000000000000000000000000000000000000000000000000000000000202010305030001000000040601000000000000000602000000000000001200020101000000040b0010001402000000";
        let res = _run(module_hex, vec![], "test2");

        debug!("{:?}", res);
        let (ty, struct_obj) = res.output.vars[0].clone();
        assert_eq!(ty, Struct(CachedStructIndex(0)));

        if let ValueImpl::Container(borrowed) = struct_obj.0.borrow() {
            debug!("borrowed: {:?} from {:?}", borrowed, struct_obj);
            let reference = Value(ValueImpl::ContainerRef(ContainerRef::Local(borrowed.copy_by_ref())));

            debug!("reference: {:?} from {:?}", reference, struct_obj);

            let res2 = _run(module_hex, vec![CloneableValue::from(reference)], "test1");

            debug!("{:?}", res2);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn test_use_stdlib() {
        let module_hex = "a11ceb0b060000000801000202020403060a0510080718290841200a61070c68240002000002000004000100000301020001070200010301020b50726f66696c65496e666f046e616d650770726f66696c650574657374310574657374320375726c00000000000000000000000000000000000000000000000000000000000000000002020103050300010000010431030b00150201010000030631020c000d001100060c000000000000000200";
        let _res = _run(
            module_hex,
            vec![CloneableValue::from(Value(ValueImpl::IndexedRef(values::IndexedRef {
                idx: 0,
                container_ref: ContainerRef::Local(values::Container::Locals(Rc::new(RefCell::new(vec![
                    ValueImpl::U8(2),
                ])))),
            })))],
            "test2",
        );
    }
}
