use core::panic;
use std::{
    cell::RefCell,
    collections::{hash_map::DefaultHasher, HashMap, HashSet, VecDeque},
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
    io::Write,
    ops::Deref,
    rc::Rc,
    str::FromStr,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_dyn_abi::DynSolType;
use alloy_sol_types::SolValue;
use bytes::Bytes;
use itertools::Itertools;
use libafl::prelude::{HasMetadata, Scheduler};
use revm::precompile::{Precompile, Precompiles};
use revm_interpreter::{
    analysis::to_analysed,
    return_ok,
    BytecodeLocked,
    CallContext,
    CallInputs,
    CallScheme,
    Contract,
    CreateInputs,
    Gas,
    Host,
    InstructionResult,
    InstructionResult::{Continue, ControlLeak, Revert},
    Interpreter,
    SelfDestructResult,
};
use revm_primitives::{
    BerlinSpec,
    Bytecode,
    ByzantiumSpec,
    CancunSpec,
    Env,
    FrontierSpec,
    HomesteadSpec,
    IstanbulSpec,
    LatestSpec,
    LondonSpec,
    MergeSpec,
    PetersburgSpec,
    ShanghaiSpec,
    SpecId,
    SpuriousDragonSpec,
    TangerineSpec,
    B256,
};
use tracing::debug;

use super::{
    middlewares::cheatcode::{
        ExpectedCallData,
        ExpectedCallTracker,
        ExpectedCallType,
        ExpectedEmit,
        ExpectedRevert,
        Prank,
        ERROR_PREFIX,
        REVERT_PREFIX,
    },
    types::EVMFuzzState,
    vm::{IS_FAST_CALL, MEM_LIMIT, SETCODE_ONLY},
};
use crate::{
    evm::{
        abi::{get_abi_type_boxed, register_abi_instance},
        contract_utils::extract_sig_from_contract,
        corpus_initializer::ABIMap,
        input::{EVMInput, EVMInputTy},
        middlewares::middleware::{add_corpus, CallMiddlewareReturn, Middleware, MiddlewareType},
        mutator::AccessPattern,
        onchain::{
            abi_decompiler::fetch_abi_evmole,
            flashloan::{register_borrow_txn, Flashloan},
        },
        types::{as_u64, generate_random_address, is_zero, EVMAddress, EVMU256},
        vm::{is_reverted_or_control_leak, EVMState, SinglePostExecution, IN_DEPLOY, IS_FAST_CALL_STATIC},
    },
    generic_vm::vm_executor::MAP_SIZE,
    handle_contract_insertion,
    invoke_middlewares,
    state::{HasCaller, HasHashToAddress},
    state_input::StagedVMState,
};

pub static mut JMP_MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];

// dataflow
pub static mut READ_MAP: [bool; MAP_SIZE] = [false; MAP_SIZE];
pub static mut WRITE_MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];

// cmp
pub static mut CMP_MAP: [EVMU256; MAP_SIZE] = [EVMU256::MAX; MAP_SIZE];

pub static mut ABI_MAX_SIZE: [usize; MAP_SIZE] = [0; MAP_SIZE];
pub static mut STATE_CHANGE: bool = false;

pub const RW_SKIPPER_PERCT_IDX: usize = 100;
pub const RW_SKIPPER_AMT: usize = MAP_SIZE - RW_SKIPPER_PERCT_IDX;

// How mant iterations the coverage is the same
pub static mut COVERAGE_NOT_CHANGED: u32 = 0;
pub static mut RET_SIZE: usize = 0;
pub static mut RET_OFFSET: usize = 0;

pub static mut PANIC_ON_BUG: bool = false;
// for debugging purpose, return ControlLeak when the calls amount exceeds this
// value
pub static mut CALL_UNTIL: u32 = u32::MAX;

/// Shall we dump the contract calls
pub static mut WRITE_RELATIONSHIPS: bool = false;

/// Branch status of the current execution
pub static mut BRANCH_STATUS: [Option<(EVMAddress, usize, bool)>; MAP_SIZE] = [None; MAP_SIZE];
pub static mut BRANCH_STATUS_IDX: usize = 0;

pub fn clear_branch_status() {
    unsafe {
        for i in BRANCH_STATUS.iter_mut().take(BRANCH_STATUS_IDX + 1) {
            *i = None;
        }

        BRANCH_STATUS_IDX = 0;
    }
}

pub fn add_branch(branch: (EVMAddress, usize, bool)) {
    unsafe {
        if BRANCH_STATUS_IDX >= MAP_SIZE {
            return;
        }
        BRANCH_STATUS[BRANCH_STATUS_IDX] = Some(branch);
        BRANCH_STATUS_IDX += 1;
    }
}

const SCRIBBLE_EVENT_HEX: [u8; 32] = [
    0xb4, 0x26, 0x04, 0xcb, 0x10, 0x5a, 0x16, 0xc8, 0xf6, 0xdb, 0x8a, 0x41, 0xe6, 0xb0, 0x0c, 0x0c, 0x1b, 0x48, 0x26,
    0x46, 0x5e, 0x8b, 0xc5, 0x04, 0xb3, 0xeb, 0x3e, 0x88, 0xb3, 0xe6, 0xa4, 0xa0,
];

/// Check if address is precompile by having assumption
/// that precompiles are in range of 1 to N.
#[inline(always)]
pub fn is_precompile(address: EVMAddress, num_of_precompiles: usize) -> bool {
    if !address[..18].iter().all(|i| *i == 0) {
        return false;
    }
    let num = u16::from_be_bytes([address[18], address[19]]);
    num.wrapping_sub(1) < num_of_precompiles as u16
}

#[allow(clippy::type_complexity)]
pub struct FuzzHost<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    pub evmstate: EVMState,
    /// [EIP-1153[(https://eips.ethereum.org/EIPS/eip-1153) transient storage that is discarded after every transactions
    pub transient_storage: HashMap<(EVMAddress, EVMU256), EVMU256>,
    // these are internal to the host
    pub env: Env,
    pub code: HashMap<EVMAddress, Arc<BytecodeLocked>>,
    pub hash_to_address: HashMap<[u8; 4], HashSet<EVMAddress>>,
    pub address_to_hash: HashMap<EVMAddress, Vec<[u8; 4]>>,
    pub _pc: usize,
    pub pc_to_addresses: HashMap<(EVMAddress, usize), HashSet<EVMAddress>>,
    pub pc_to_create: HashMap<(EVMAddress, usize), usize>,
    pub pc_to_call_hash: HashMap<(EVMAddress, usize, usize), HashSet<Vec<u8>>>,
    pub middlewares_enabled: bool,
    // If you use RefCell, modifying middlewares during execution will cause a panic
    // because the executor borrows middlewares over its entire lifetime.
    pub middlewares: RwLock<Vec<Rc<RefCell<dyn Middleware<SC>>>>>,

    pub coverage_changed: bool,

    pub flashloan_middleware: Option<Rc<RefCell<Flashloan>>>,

    pub middlewares_latent_call_actions: Vec<CallMiddlewareReturn>,

    pub scheduler: SC,

    // controlled by onchain module, if sload cant find the slot, use this value
    pub next_slot: EVMU256,

    pub access_pattern: Rc<RefCell<AccessPattern>>,

    pub bug_hit: bool,
    pub current_typed_bug: Vec<(String, (EVMAddress, usize))>,
    pub call_count: u32,

    #[cfg(feature = "print_logs")]
    pub logs: HashSet<u64>,
    // set_code data
    pub setcode_data: HashMap<EVMAddress, Bytecode>,
    // selftdestruct
    pub current_self_destructs: Vec<(EVMAddress, usize)>,
    // arbitrary calls
    pub current_arbitrary_calls: Vec<(EVMAddress, EVMAddress, usize)>,
    // integer_overflow
    pub current_integer_overflow: HashSet<(EVMAddress, usize, &'static str)>,
    // relations file handle
    relations_file: std::fs::File,
    // Filter duplicate relations
    relations_hash: HashSet<u64>,
    /// Randomness from inputs
    pub randomness: Vec<u8>,
    /// workdir
    pub work_dir: String,
    /// custom SpecId
    pub spec_id: SpecId,
    /// Precompiles
    pub precompiles: Precompiles,

    /// All SSTORE PCs that are for mapping (i.e., writing to multiple storage
    /// slots)
    pub mapping_sstore_pcs: HashSet<(EVMAddress, usize)>,
    pub mapping_sstore_pcs_to_slot: HashMap<(EVMAddress, usize), HashSet<EVMU256>>,

    /// For future continue executing when control leak happens
    pub leak_ctx: Vec<SinglePostExecution>,

    pub jumpi_trace: usize,

    /// Depth of call stack
    pub call_depth: u64,
    /// Prank information
    pub prank: Option<Prank>,
    /// Expected revert information
    pub expected_revert: Option<ExpectedRevert>,
    /// Expected emits
    pub expected_emits: VecDeque<ExpectedEmit>,
    /// Expected calls
    pub expected_calls: ExpectedCallTracker,
    /// Assert failed message for the cheatcode
    pub assert_msg: Option<String>,
}

impl<SC> Debug for FuzzHost<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuzzHost")
            .field("data", &self.evmstate)
            .field("env", &self.env)
            .field("hash_to_address", &self.hash_to_address)
            .field("address_to_hash", &self.address_to_hash)
            .field("_pc", &self._pc)
            .field("pc_to_addresses", &self.pc_to_addresses)
            .field("pc_to_call_hash", &self.pc_to_call_hash)
            .field("middlewares_enabled", &self.middlewares_enabled)
            .field("middlewares", &self.middlewares)
            .field("middlewares_latent_call_actions", &self.middlewares_latent_call_actions)
            .finish()
    }
}

// all clones would not include middlewares and states
impl<SC> Clone for FuzzHost<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            evmstate: self.evmstate.clone(),
            transient_storage: self.transient_storage.clone(),
            env: self.env.clone(),
            code: self.code.clone(),
            hash_to_address: self.hash_to_address.clone(),
            address_to_hash: self.address_to_hash.clone(),
            _pc: self._pc,
            pc_to_addresses: self.pc_to_addresses.clone(),
            pc_to_create: self.pc_to_create.clone(),
            pc_to_call_hash: self.pc_to_call_hash.clone(),
            middlewares_enabled: false,
            middlewares: RwLock::new(Default::default()),
            coverage_changed: false,
            flashloan_middleware: self.flashloan_middleware.clone(),
            middlewares_latent_call_actions: vec![],
            scheduler: self.scheduler.clone(),
            next_slot: Default::default(),
            access_pattern: self.access_pattern.clone(),
            bug_hit: false,
            call_count: 0,
            #[cfg(feature = "print_logs")]
            logs: Default::default(),
            setcode_data: self.setcode_data.clone(),
            current_self_destructs: self.current_self_destructs.clone(),
            current_arbitrary_calls: self.current_arbitrary_calls.clone(),
            current_integer_overflow: self.current_integer_overflow.clone(),
            relations_file: self.relations_file.try_clone().unwrap(),
            relations_hash: self.relations_hash.clone(),
            current_typed_bug: self.current_typed_bug.clone(),
            randomness: vec![],
            work_dir: self.work_dir.clone(),
            spec_id: self.spec_id,
            precompiles: Precompiles::default(),
            leak_ctx: self.leak_ctx.clone(),
            mapping_sstore_pcs: self.mapping_sstore_pcs.clone(),
            mapping_sstore_pcs_to_slot: self.mapping_sstore_pcs_to_slot.clone(),
            jumpi_trace: self.jumpi_trace,
            call_depth: self.call_depth,
            prank: self.prank.clone(),
            expected_emits: self.expected_emits.clone(),
            expected_revert: self.expected_revert.clone(),
            expected_calls: self.expected_calls.clone(),
            assert_msg: self.assert_msg.clone(),
        }
    }
}

// hack: I don't want to change evm internal to add a new type of return
// this return type is never used as we disabled gas
pub static mut ACTIVE_MATCH_EXT_CALL: bool = false;
const UNBOUND_CALL_THRESHOLD: usize = 50;

// if a PC transfers control to >10 addresses, we consider call at this PC to be
// unbounded
const CONTROL_LEAK_THRESHOLD: usize = 50;

impl<SC> FuzzHost<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    pub fn new(scheduler: SC, workdir: String) -> Self {
        Self {
            evmstate: EVMState::new(),
            transient_storage: HashMap::new(),
            env: Env::default(),
            code: HashMap::new(),
            hash_to_address: HashMap::new(),
            address_to_hash: HashMap::new(),
            _pc: 0,
            pc_to_addresses: HashMap::new(),
            pc_to_create: HashMap::new(),
            pc_to_call_hash: HashMap::new(),
            middlewares_enabled: false,
            middlewares: RwLock::new(Default::default()),
            coverage_changed: false,
            flashloan_middleware: None,
            middlewares_latent_call_actions: vec![],
            scheduler,
            next_slot: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            bug_hit: false,
            call_count: 0,
            #[cfg(feature = "print_logs")]
            logs: Default::default(),
            setcode_data: HashMap::new(),
            current_self_destructs: Default::default(),
            current_arbitrary_calls: Default::default(),
            current_integer_overflow: Default::default(),
            relations_file: std::fs::File::create(format!("{}/relations.log", workdir)).unwrap(),
            relations_hash: HashSet::new(),
            current_typed_bug: Default::default(),
            randomness: vec![],
            work_dir: workdir,
            spec_id: SpecId::LATEST,
            precompiles: Default::default(),
            leak_ctx: vec![],
            mapping_sstore_pcs: Default::default(),
            mapping_sstore_pcs_to_slot: Default::default(),
            jumpi_trace: 37,
            call_depth: 0,
            prank: None,
            expected_revert: None,
            expected_emits: VecDeque::new(),
            expected_calls: ExpectedCallTracker::new(),
            assert_msg: None,
        }
    }

    pub fn set_spec_id(&mut self, spec_id: String) {
        self.spec_id = SpecId::from(spec_id.as_str());
    }

    /// custom spec id run_inspect
    pub fn run_inspect(&mut self, interp: &mut Interpreter, state: &mut EVMFuzzState) -> InstructionResult {
        match self.spec_id {
            SpecId::LATEST => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, LatestSpec>(self, state),
            SpecId::FRONTIER => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, FrontierSpec>(self, state),
            SpecId::HOMESTEAD => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, HomesteadSpec>(self, state),
            SpecId::TANGERINE => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, TangerineSpec>(self, state),
            SpecId::SPURIOUS_DRAGON => {
                interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, SpuriousDragonSpec>(self, state)
            }
            SpecId::BYZANTIUM => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, ByzantiumSpec>(self, state),
            SpecId::CONSTANTINOPLE | SpecId::PETERSBURG => {
                interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, PetersburgSpec>(self, state)
            }
            SpecId::ISTANBUL => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, IstanbulSpec>(self, state),
            SpecId::MUIR_GLACIER | SpecId::BERLIN => {
                interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, BerlinSpec>(self, state)
            }
            SpecId::LONDON => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, LondonSpec>(self, state),
            SpecId::MERGE => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, MergeSpec>(self, state),
            SpecId::SHANGHAI => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, ShanghaiSpec>(self, state),
            SpecId::CANCUN => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, CancunSpec>(self, state),
            _ => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, LatestSpec>(self, state),
        }
    }

    pub fn remove_all_middlewares(&mut self) {
        self.middlewares_enabled = false;
        self.middlewares = RwLock::new(Default::default());
    }

    pub fn add_middlewares(&mut self, middleware: Rc<RefCell<dyn Middleware<SC>>>) {
        self.middlewares_enabled = true;
        self.middlewares.write().unwrap().push(middleware);
    }

    pub fn remove_middlewares(&mut self, middlewares: Rc<RefCell<dyn Middleware<SC>>>) {
        let ty = middlewares.deref().borrow().get_type();

        self.middlewares
            .write()
            .unwrap()
            .retain(|x| x.deref().borrow().get_type() != ty);
    }

    pub fn remove_middlewares_by_ty(&mut self, ty: &MiddlewareType) {
        self.middlewares
            .write()
            .unwrap()
            .retain(|x| x.deref().borrow().get_type() != *ty);
    }

    pub fn add_flashloan_middleware(&mut self, middlware: Flashloan) {
        self.flashloan_middleware = Some(Rc::new(RefCell::new(middlware)));
    }

    pub fn initialize(&mut self, state: &EVMFuzzState) {
        self.hash_to_address = state.get_hash_to_address().clone();
        for key in self.hash_to_address.keys() {
            let addresses = self.hash_to_address.get(key).unwrap();
            for addr in addresses {
                match self.address_to_hash.get_mut(addr) {
                    Some(s) => {
                        s.push(*key);
                    }
                    None => {
                        self.address_to_hash.insert(*addr, vec![*key]);
                    }
                }
            }
        }
    }

    pub fn add_hashes(&mut self, address: EVMAddress, hashes: Vec<[u8; 4]>) {
        self.address_to_hash.insert(address, hashes.clone());

        for hash in hashes {
            // insert if exists or create new
            match self.hash_to_address.get_mut(&hash) {
                Some(s) => {
                    s.insert(address);
                }
                None => {
                    self.hash_to_address.insert(hash, HashSet::from([address]));
                }
            }
        }
    }

    pub fn add_one_hashes(&mut self, address: EVMAddress, hash: [u8; 4]) {
        match self.address_to_hash.get_mut(&address) {
            Some(s) => {
                s.push(hash);
            }
            None => {
                self.address_to_hash.insert(address, vec![hash]);
            }
        }

        match self.hash_to_address.get_mut(&hash) {
            Some(s) => {
                s.insert(address);
            }
            None => {
                self.hash_to_address.insert(hash, HashSet::from([address]));
            }
        }
    }

    pub fn set_codedata(&mut self, address: EVMAddress, code: Bytecode) {
        self.setcode_data.insert(address, code);
    }

    pub fn clear_codedata(&mut self) {
        self.setcode_data.clear();
    }

    pub fn set_code(&mut self, address: EVMAddress, mut code: Bytecode, state: &mut EVMFuzzState) {
        unsafe {
            invoke_middlewares!(self, None, state, on_insert, &mut code, address);
        }
        self.code
            .insert(address, Arc::new(BytecodeLocked::try_from(to_analysed(code)).unwrap()));
    }

    pub fn find_static_call_read_slot(
        &self,
        _address: EVMAddress,
        _data: Bytes,
        _state: &mut EVMFuzzState,
    ) -> Vec<EVMU256> {
        vec![]
        // let call = Contract::new_with_context_not_cloned::<LatestSpec>(
        //     data,
        //     self.code.get(&address).expect("no code").clone(),
        //     &CallContext {
        //         address,
        //         caller: Default::default(),
        //         code_address: address,
        //         apparent_value: Default::default(),
        //         scheme: CallScheme::StaticCall,
        //     },
        // );
        // let mut interp = Interpreter::new::<LatestSpec>(call, 1e10 as u64);
        // let (ret, slots) =
        //     interp.locate_slot::<FuzzHost<VS, I, S>, LatestSpec, S>(&mut
        // self.clone(), state); if ret != Return::Revert {
        //     slots
        // } else {
        //     vec![]
        // }
    }
    pub fn write_relations(&mut self, caller: EVMAddress, target: EVMAddress, funtion_hash: Bytes) {
        if funtion_hash.len() < 0x4 {
            return;
        }
        let cur_write_str = format!(
            "{{caller:0x{} --> target:0x{} function(0x{})}}\n",
            hex::encode(caller),
            hex::encode(target),
            hex::encode(&funtion_hash[..4])
        );
        let mut hasher = DefaultHasher::new();
        cur_write_str.hash(&mut hasher);
        let cur_wirte_hash = hasher.finish();
        if self.relations_hash.contains(&cur_wirte_hash) {
            return;
        }
        if self.relations_hash.is_empty() {
            let write_head = "[ityfuzz relations] caller, traget, function hash\n".to_string();
            self.relations_file.write_all(write_head.as_bytes()).unwrap();
        }

        self.relations_hash.insert(cur_wirte_hash);
        self.relations_file.write_all(cur_write_str.as_bytes()).unwrap();
    }

    fn call_allow_control_leak(
        &mut self,
        input: &mut CallInputs,
        interp: &mut Interpreter,
        (out_offset, out_len): (usize, usize),
        state: &mut EVMFuzzState,
    ) -> (InstructionResult, Gas, Bytes) {
        macro_rules! push_interp {
            () => {{
                self.leak_ctx = vec![SinglePostExecution::from_interp(interp, (out_offset, out_len))];
            }};
        }
        self.call_count += 1;
        if self.call_count >= unsafe { CALL_UNTIL } {
            push_interp!();
            return (ControlLeak, Gas::new(0), Bytes::new());
        }

        if unsafe { WRITE_RELATIONSHIPS } {
            self.write_relations(input.transfer.source, input.contract, input.input.clone());
        }

        let mut hash = input.input.to_vec();
        hash.resize(4, 0);

        macro_rules! record_func_hash {
            () => {
                unsafe {
                    let mut s = DefaultHasher::new();
                    hash.hash(&mut s);
                    let _hash = s.finish();
                    ABI_MAX_SIZE[(_hash as usize) % MAP_SIZE] = RET_SIZE;
                }
            };
        }

        // middlewares
        let mut middleware_result: Option<(InstructionResult, Gas, Bytes)> = None;
        for action in &self.middlewares_latent_call_actions {
            match action {
                CallMiddlewareReturn::Continue => {}
                CallMiddlewareReturn::ReturnRevert => {
                    middleware_result = Some((Revert, Gas::new(0), Bytes::new()));
                }
                CallMiddlewareReturn::ReturnSuccess(b) => {
                    middleware_result = Some((Continue, Gas::new(0), b.clone()));
                }
            }
            if middleware_result.is_some() {
                break;
            }
        }
        self.middlewares_latent_call_actions.clear();

        if let Some(m) = middleware_result {
            return m;
        }

        let input_seq = input.input.to_vec();

        let is_target_address_unbounded = {
            assert_ne!(self._pc, 0);
            self.pc_to_addresses
                .entry((input.context.caller, self._pc))
                .or_default();
            let addresses_at_pc = self.pc_to_addresses.get_mut(&(input.context.caller, self._pc)).unwrap();
            addresses_at_pc.insert(input.contract);
            addresses_at_pc.len() > CONTROL_LEAK_THRESHOLD
        };

        if input.context.scheme == CallScheme::StaticCall &&
            (state.has_caller(&input.contract) || is_target_address_unbounded)
        {
            record_func_hash!();
            push_interp!();
            // println!(
            //     "staticcall self {:?} -> {:?} with {:?}",
            //     input.context.caller,
            //     input.contract,
            //     hex::encode(input.input.clone())
            // );
            return (InstructionResult::AddressUnboundedStaticCall, Gas::new(0), Bytes::new());
        }

        if input.context.scheme == CallScheme::Call {
            // if calling sender, then definitely control leak
            if state.has_caller(&input.contract) || is_target_address_unbounded {
                record_func_hash!();
                push_interp!();
                // println!(
                //     "call self {:?} -> {:?} with {:?}",
                //     input.context.caller,
                //     input.contract,
                //     hex::encode(input.input.clone())
                // );
                return (ControlLeak, Gas::new(0), Bytes::new());
            }
            // check whether the whole CALLDATAVALUE can be arbitrary
            self.pc_to_call_hash
                .entry((input.context.caller, self._pc, self.jumpi_trace))
                .or_default();
            self.pc_to_call_hash
                .get_mut(&(input.context.caller, self._pc, self.jumpi_trace))
                .unwrap()
                .insert(hash.to_vec());
            if self
                .pc_to_call_hash
                .get(&(input.context.caller, self._pc, self.jumpi_trace))
                .unwrap()
                .len() >
                UNBOUND_CALL_THRESHOLD &&
                input_seq.len() >= 4
            {
                self.current_arbitrary_calls.push((
                    input.context.caller,
                    input.context.address,
                    interp.program_counter(),
                ));
                // println!(
                //     "ub leak {:?} -> {:?} with {:?} {}",
                //     input.context.caller,
                //     input.contract,
                //     hex::encode(input.input.clone()),
                //     self.jumpi_trace
                // );
                push_interp!();
                return (
                    InstructionResult::ArbitraryExternalCallAddressBounded(
                        input.context.caller,
                        input.context.address,
                        input.transfer.value,
                    ),
                    Gas::new(0),
                    Bytes::new(),
                );
            }
        }

        let input_bytes = Bytes::from(input_seq);

        // find contracts that have this function hash
        let contract_loc_option = self.hash_to_address.get(hash.as_slice());
        if unsafe { ACTIVE_MATCH_EXT_CALL } {
            if let Some(loc) = contract_loc_option {
                // if there is such a location known, then we can use exact call
                if !loc.contains(&input.contract) {
                    // todo(@shou): resolve multi locs
                    if loc.len() != 1 {
                        panic!("more than one contract found for the same hash");
                    }
                    let mut interp = Interpreter::new_with_memory_limit(
                        Contract::new_with_context_analyzed(
                            input_bytes,
                            self.code.get(loc.iter().next().unwrap()).unwrap().clone(),
                            &input.context,
                        ),
                        1e10 as u64,
                        false,
                        MEM_LIMIT,
                    );

                    let ret = self.run_inspect(&mut interp, state);
                    return (ret, Gas::new(0), interp.return_value());
                }
            }
        }

        // if there is code, then call the code
        let res = self.call_forbid_control_leak(input, state);
        match res.0 {
            ControlLeak |
            InstructionResult::ArbitraryExternalCallAddressBounded(_, _, _) |
            InstructionResult::AddressUnboundedStaticCall => {
                self.leak_ctx
                    .push(SinglePostExecution::from_interp(interp, (out_offset, out_len)));
            }
            _ => {}
        }
        res
    }

    fn call_forbid_control_leak(
        &mut self,
        input: &mut CallInputs,
        state: &mut EVMFuzzState,
    ) -> (InstructionResult, Gas, Bytes) {
        let mut hash = input.input.to_vec();
        hash.resize(4, 0);
        // if there is code, then call the code
        if let Some(code) = self.code.get(&input.context.code_address) {
            let mut interp = Interpreter::new_with_memory_limit(
                Contract::new_with_context_analyzed(Bytes::from(input.input.to_vec()), code.clone(), &input.context),
                1e10 as u64,
                false,
                MEM_LIMIT,
            );

            let ret = self.run_inspect(&mut interp, state);
            return (ret, Gas::new(0), interp.return_value());
        }

        // transfer txn and fallback provided
        if hash == [0x00, 0x00, 0x00, 0x00] {
            return (Continue, Gas::new(0), Bytes::new());
        }
        (Revert, Gas::new(0), Bytes::new())
    }

    fn call_precompile(
        &mut self,
        input: &mut CallInputs,
        _state: &mut EVMFuzzState,
    ) -> (InstructionResult, Gas, Bytes) {
        let precompile = self
            .precompiles
            .get(&input.contract)
            .expect("Check for precompile should be already done");
        let out = match precompile {
            Precompile::Standard(fun) => fun(input.input.to_vec().as_slice(), u64::MAX),
            Precompile::Custom(fun) => fun(input.input.to_vec().as_slice(), u64::MAX),
        };
        match out {
            Ok((_, data)) => (InstructionResult::Return, Gas::new(0), Bytes::from(data)),
            Err(_) => (InstructionResult::PrecompileError, Gas::new(0), Bytes::new()),
        }
    }

    /// Apply the prank
    pub fn apply_prank(&mut self, contract_caller: &EVMAddress, input: &mut CallInputs) {
        if let Some(prank) = &self.prank {
            if self.call_depth >= prank.depth && contract_caller == &prank.old_caller {
                // At the target depth we set `msg.sender`
                if self.call_depth == prank.depth {
                    input.context.caller = prank.new_caller;
                    input.transfer.source = prank.new_caller;
                }

                // At the target depth, or deeper, we set `tx.origin`
                if let Some(new_origin) = prank.new_origin {
                    self.env.tx.caller = new_origin;
                }
            }
        }
    }

    /// Clean up the prank
    pub fn clean_prank(&mut self) {
        if let Some(prank) = &self.prank {
            if self.call_depth != prank.depth {
                return;
            }
            if let Some(old_origin) = prank.old_origin {
                self.env.tx.caller = old_origin;
            }
            if prank.single_call {
                let _ = self.prank.take();
            }
        }
    }

    /// Check expected
    pub fn check_expected(
        &mut self,
        call: &CallInputs,
        res: (InstructionResult, Gas, Bytes),
    ) -> (InstructionResult, Gas, Bytes) {
        // Check assert result
        if let Some(res) = self.check_assert_result() {
            return res;
        }

        // Check expected reverts
        let res = self.check_expected_revert(res);
        if res.0 == Revert {
            return res;
        }
        // Check expected emits
        let res = self.check_expected_emits(call, res);
        if res.0 == Revert {
            return res;
        }
        // Check expected calls
        self.check_expected_calls(res)
    }

    pub fn check_assert_result(&mut self) -> Option<(InstructionResult, Gas, Bytes)> {
        if let Some(ref msg) = self.assert_msg {
            return Some((InstructionResult::Revert, Gas::new(0), msg.abi_encode().into()));
        }

        None
    }

    /// Check expected reverts
    fn check_expected_revert(&mut self, res: (InstructionResult, Gas, Bytes)) -> (InstructionResult, Gas, Bytes) {
        // Check if we should check for reverts
        if self.expected_revert.is_none() {
            return res;
        }
        let expected_revert = self.expected_revert.as_ref().unwrap();
        if self.call_depth > expected_revert.depth {
            return res;
        }
        let (result, gas, retdata) = res;
        let mut expected_revert = self.expected_revert.take().unwrap();

        // Check result
        if matches!(result, return_ok!()) {
            return (
                InstructionResult::Revert,
                gas,
                "Call did not revert as expected".abi_encode().into(),
            );
        }

        // Check revert reason
        if expected_revert.reason.is_none() {
            return (InstructionResult::Return, gas, retdata);
        }
        let expected_reason = expected_revert.reason.take().unwrap();
        let mut actual_reason = retdata.clone();
        if actual_reason.len() >= 4 && matches!(actual_reason[..4].try_into(), Ok(ERROR_PREFIX | REVERT_PREFIX)) {
            if let Ok(parsed_bytes) = DynSolType::Bytes.abi_decode(&actual_reason[4..]) {
                if let Some(bytes) = parsed_bytes.as_bytes().map(|b| b.to_vec()) {
                    actual_reason = bytes.into();
                }
            }
        }
        if actual_reason != expected_reason {
            return (
                InstructionResult::Revert,
                gas,
                "Revert reason mismatch".abi_encode().into(),
            );
        }

        (InstructionResult::Return, gas, retdata)
    }

    /// Check expected emits
    fn check_expected_emits(
        &mut self,
        call: &CallInputs,
        res: (InstructionResult, Gas, Bytes),
    ) -> (InstructionResult, Gas, Bytes) {
        let should_check_emits = self
            .expected_emits
            .iter()
            .any(|expected| expected.depth == self.call_depth) &&
            // Ignore staticcalls
            !call.is_static;
        if !should_check_emits {
            return res;
        }

        let (result, gas, retdata) = res;
        // Not all emits were matched.
        if self.expected_emits.iter().any(|expected| !expected.found) {
            return (
                InstructionResult::Revert,
                gas,
                "log != expected log".abi_encode().into(),
            );
        }

        self.expected_emits.clear();
        (result, gas, retdata)
    }

    /// Check expected calls
    fn check_expected_calls(&mut self, res: (InstructionResult, Gas, Bytes)) -> (InstructionResult, Gas, Bytes) {
        // Only check expected calls at the root call
        if self.call_depth > 0 {
            return res;
        }

        let (result, gas, retdata) = res;
        let expected_calls = std::mem::take(&mut self.expected_calls);
        for (_, calldatas) in expected_calls {
            // Loop over each address, and for each address, loop over each calldata it
            // expects.
            for (_, (expected, actual_count)) in calldatas {
                // Grab the values we expect to see
                let ExpectedCallData { count, call_type, .. } = expected;

                let failed = match call_type {
                    ExpectedCallType::Count => count != actual_count,
                    ExpectedCallType::NonCount => count > actual_count,
                };
                if failed {
                    let msg = "expected call count mismatch";
                    return (InstructionResult::Revert, gas, msg.abi_encode().into());
                }
            }
        }

        (result, gas, retdata)
    }
}

macro_rules! process_rw_key {
    ($key:ident) => {
        if $key > EVMU256::from(RW_SKIPPER_PERCT_IDX) {
            // $key >>= 4;
            $key %= EVMU256::from(RW_SKIPPER_AMT);
            $key += EVMU256::from(RW_SKIPPER_PERCT_IDX);
            as_u64($key) as usize % MAP_SIZE
        } else {
            as_u64($key) as usize % MAP_SIZE
        }
    };
}

macro_rules! u256_to_u8 {
    ($key:ident) => {
        (as_u64($key >> 4) % 254) as u8
    };
}

#[macro_export]
macro_rules! invoke_middlewares {
    ($host:expr, $interp:expr, $state:expr, $invoke:ident $(, $arg:expr)*) => {
        if $host.middlewares_enabled {
            if let Some(m) = $host.flashloan_middleware.clone() {
                let mut middleware = m.deref().borrow_mut();
                middleware.$invoke($interp, $host, $state $(, $arg)*);
            }

            if !$host.setcode_data.is_empty() {
                $host.clear_codedata();
            }

            let mut middlewares = $host.middlewares.read().unwrap().clone();
            for middleware in middlewares.iter_mut() {
                middleware.deref().borrow_mut().$invoke($interp, $host, $state $(, $arg)*);
            }

            if !$host.setcode_data.is_empty() {
                for (address, code) in &$host.setcode_data.clone() {
                    $host.set_code(address.clone(), code.clone(), $state);
                }
            }
        }
    };
}

impl<SC> Host<EVMFuzzState> for FuzzHost<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    fn step(&mut self, interp: &mut Interpreter, state: &mut EVMFuzzState) -> InstructionResult {
        unsafe {
            // debug!("pc: {}", interp.program_counter());
            // debug!("{:?}", *interp.instruction_pointer);
            invoke_middlewares!(self, interp, state, on_step);
            if IS_FAST_CALL_STATIC {
                return Continue;
            }

            macro_rules! fast_peek {
                ($idx:expr) => {
                    interp.stack.data()[interp.stack.len() - 1 - $idx]
                };
            }
            match *interp.instruction_pointer {
                // 0xfd => {
                //     println!("fd {} @ {:?}", interp.program_counter(), interp.contract.address);
                // }
                // 0x3b => {
                //     println!(
                //         "3b {} @ {:?} {:?}",
                //         interp.program_counter(),
                //         interp.contract.address,
                //         fast_peek!(0)
                //     );
                // }
                // 0x31 | 0x47 => {
                //     debug!("host setp balance");
                //     std::thread::sleep(std::time::Duration::from_secs(3));
                // }
                0x57 => {
                    // JUMPI counter cond
                    let br = fast_peek!(1);
                    let jump_dest = if is_zero(br) { 1 } else { as_u64(fast_peek!(0)) };
                    let _pc = interp.program_counter();

                    let (shash, _) = self.jumpi_trace.overflowing_mul(54059);
                    self.jumpi_trace = (shash) ^ (_pc * 76963);
                    let idx = (_pc * (jump_dest as usize)) % MAP_SIZE;
                    if JMP_MAP[idx] == 0 {
                        self.coverage_changed = true;
                    }
                    JMP_MAP[idx] = JMP_MAP[idx].saturating_add(1);

                    #[cfg(feature = "cmp")]
                    {
                        let idx = (interp.program_counter()) % MAP_SIZE;
                        CMP_MAP[idx] = br;
                    }

                    add_branch((interp.contract.address, interp.program_counter(), jump_dest != 1));
                }

                #[cfg(any(feature = "dataflow", feature = "cmp"))]
                0x55 => {
                    // SSTORE
                    let pc = interp.program_counter();
                    if !self.mapping_sstore_pcs.contains(&(interp.contract.address, pc)) {
                        let mut key = fast_peek!(0);
                        let slots = self
                            .mapping_sstore_pcs_to_slot
                            .entry((interp.contract.address, pc))
                            .or_default();
                        slots.insert(key);
                        if slots.len() > 10 {
                            self.mapping_sstore_pcs.insert((interp.contract.address, pc));
                        }

                        let value = fast_peek!(1);
                        let compressed_value = u256_to_u8!(value) + 1;
                        WRITE_MAP[process_rw_key!(key)] = compressed_value;

                        let res =
                            <FuzzHost<SC> as Host<EVMFuzzState>>::sload(self, interp.contract.address, fast_peek!(0));
                        let value_changed = res.expect("sload failed").0 != value;

                        let idx = interp.program_counter() % MAP_SIZE;
                        JMP_MAP[idx] = if value_changed { 1 } else { 0 };

                        STATE_CHANGE |= value_changed;
                    }
                }

                #[cfg(feature = "dataflow")]
                0x54 => {
                    // SLOAD
                    let mut key = fast_peek!(0);
                    READ_MAP[process_rw_key!(key)] = true;
                }

                // todo(shou): support signed checking
                #[cfg(feature = "cmp")]
                0x10 | 0x12 => {
                    // LT, SLT
                    let v1 = fast_peek!(0);
                    let v2 = fast_peek!(1);
                    let abs_diff = if v1 >= v2 {
                        if v1 - v2 != EVMU256::ZERO {
                            v1 - v2
                        } else {
                            EVMU256::from(1)
                        }
                    } else {
                        EVMU256::ZERO
                    };
                    let idx = interp.program_counter() % MAP_SIZE;
                    if abs_diff < CMP_MAP[idx] {
                        CMP_MAP[idx] = abs_diff;
                    }
                }

                #[cfg(feature = "cmp")]
                0x11 | 0x13 => {
                    // GT, SGT
                    let v1 = fast_peek!(0);
                    let v2 = fast_peek!(1);
                    let abs_diff = if v1 <= v2 {
                        if v2 - v1 != EVMU256::ZERO {
                            v2 - v1
                        } else {
                            EVMU256::from(1)
                        }
                    } else {
                        EVMU256::ZERO
                    };
                    let idx = interp.program_counter() % MAP_SIZE;
                    if abs_diff < CMP_MAP[idx] {
                        CMP_MAP[idx] = abs_diff;
                    }
                }

                #[cfg(feature = "cmp")]
                0x14 => {
                    // EQ
                    let v1 = fast_peek!(0);
                    let v2 = fast_peek!(1);
                    let abs_diff = if v1 < v2 {
                        (v2 - v1) % (EVMU256::MAX - EVMU256::from(1)) + EVMU256::from(1)
                    } else {
                        (v1 - v2) % (EVMU256::MAX - EVMU256::from(1)) + EVMU256::from(1)
                    };
                    let idx = interp.program_counter() % MAP_SIZE;
                    if abs_diff < CMP_MAP[idx] {
                        CMP_MAP[idx] = abs_diff;
                    }
                }

                0xf1 | 0xf2 | 0xf4 | 0xfa => {
                    let offset_of_ret_size: usize = match *interp.instruction_pointer {
                        0xf1 | 0xf2 => 6,
                        0xf4 | 0xfa => 5,
                        _ => unreachable!(),
                    };
                    {
                        RET_OFFSET = as_u64(fast_peek!(offset_of_ret_size - 1)) as usize;
                        // debug!("RET_OFFSET: {}", RET_OFFSET);
                        RET_SIZE = as_u64(fast_peek!(offset_of_ret_size)) as usize;
                    }
                    self._pc = interp.program_counter();
                }
                0xf0 | 0xf5 | 0xa0..=0xa4 | 0xff => {
                    // CREATE, CREATE2
                    self._pc = interp.program_counter();
                }
                _ => {}
            }

            self.access_pattern.deref().borrow_mut().decode_instruction(interp);
        }
        Continue
    }

    fn step_end(
        &mut self,
        _interp: &mut Interpreter,
        _ret: InstructionResult,
        _: &mut EVMFuzzState,
    ) -> InstructionResult {
        Continue
    }

    fn env(&mut self) -> &mut Env {
        &mut self.env
    }

    fn load_account(&mut self, _address: EVMAddress) -> Option<(bool, bool)> {
        Some((
            true, true, // self.data.contains_key(&address) || self.code.contains_key(&address),
        ))
    }

    fn block_hash(&mut self, _number: EVMU256) -> Option<B256> {
        Some(B256::zero())
    }

    fn balance(&mut self, address: EVMAddress) -> Option<(EVMU256, bool)> {
        #[cfg(feature = "real_balance")]
        {
            if let Some(balance) = self.evmstate.get_balance(&address) {
                return Some((*balance, true));
            }
            self.evmstate.set_balance(address, self.next_slot);
            Some((self.next_slot, true))
        }
        #[cfg(not(feature = "real_balance"))]
        {
            Some((EVMU256::MAX, true))
        }
    }

    fn code(&mut self, address: EVMAddress) -> Option<(Arc<BytecodeLocked>, bool)> {
        // debug!("code");
        match self.code.get(&address) {
            Some(code) => Some((code.clone(), true)),
            None => Some((Arc::new(BytecodeLocked::default()), true)),
        }
    }

    fn code_hash(&mut self, address: EVMAddress) -> Option<(B256, bool)> {
        match self.code.get(&address) {
            Some(code) => Some((code.hash(), true)),
            None => Some((B256::zero(), true)),
        }
    }

    fn sload(&mut self, address: EVMAddress, index: EVMU256) -> Option<(EVMU256, bool)> {
        if let Some(account) = self.evmstate.get_mut(&address) {
            if let Some(slot) = account.get(&index) {
                // println!("sload: {:?} -> {:?} = {:?}", address, index, slot);
                return Some((*slot, true));
            } else {
                account.insert(index, self.next_slot);
            }
        } else {
            let mut account = HashMap::new();
            account.insert(index, self.next_slot);
            self.evmstate.insert(address, account);
        }
        // println!("sload(c): {:?} -> {:?} = {:?}", address, index, self.next_slot);
        Some((self.next_slot, true))
    }

    fn sstore(
        &mut self,
        address: EVMAddress,
        index: EVMU256,
        value: EVMU256,
    ) -> Option<(EVMU256, EVMU256, EVMU256, bool)> {
        match self.evmstate.get_mut(&address) {
            Some(account) => {
                account.insert(index, value);
            }
            None => {
                let mut account = HashMap::new();
                account.insert(index, value);
                self.evmstate.insert(address, account);
            }
        };

        Some((EVMU256::from(0), EVMU256::from(0), EVMU256::from(0), true))
    }

    fn tload(&mut self, address: EVMAddress, index: EVMU256) -> EVMU256 {
        if let Some(slot) = self.transient_storage.get(&(address, index)) {
            *slot
        } else {
            self.transient_storage.insert((address, index), self.next_slot);
            self.next_slot
        }
    }

    fn tstore(&mut self, address: EVMAddress, index: EVMU256, value: EVMU256) {
        self.transient_storage.insert((address, index), value);
    }

    fn log(&mut self, _address: EVMAddress, _topics: Vec<B256>, _data: Bytes) {
        // flag check
        if _topics.len() == 1 {
            let current_flag = _topics.last().unwrap().0;
            // hex is "fuzzland"
            if current_flag[0] == 0x66 &&
                current_flag[1] == 0x75 &&
                current_flag[2] == 0x7a &&
                current_flag[3] == 0x7a &&
                current_flag[4] == 0x6c &&
                current_flag[5] == 0x61 &&
                current_flag[6] == 0x6e &&
                current_flag[7] == 0x64 &&
                current_flag[8] == 0x00 &&
                current_flag[9] == 0x00 ||
                current_flag == SCRIBBLE_EVENT_HEX
            {
                let data_string = String::from_utf8(_data[64..].to_vec()).unwrap();
                if unsafe { PANIC_ON_BUG } {
                    panic!("target bug found: {}", data_string);
                }
                self.current_typed_bug
                    .push((data_string.trim_end_matches('\u{0}').to_string(), (_address, self._pc)));
            }
        }

        #[cfg(feature = "print_logs")]
        {
            let mut hasher = DefaultHasher::new();
            _data.to_vec().hash(&mut hasher);
            let h = hasher.finish();
            if self.logs.contains(&h) {
                return;
            }
            self.logs.insert(h);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards");
            let timestamp = now.as_nanos();
            debug!("log@{} {:?}", timestamp, hex::encode(_data));
        }
    }

    fn selfdestruct(&mut self, _address: EVMAddress, _target: EVMAddress) -> Option<SelfDestructResult> {
        self.current_self_destructs.push((_address, self._pc));
        Some(SelfDestructResult::default())
    }

    fn create(
        &mut self,
        inputs: &mut CreateInputs,
        state: &mut EVMFuzzState,
    ) -> (InstructionResult, Option<EVMAddress>, Gas, Bytes) {
        if unsafe { IN_DEPLOY } {
            // todo: use nonce + hash instead
            let r_addr = generate_random_address(state);

            // update local balance
            // for create we don't check sender balance
            // todo: only disable checking in setUp
            let value = EVMU256::from(inputs.value);
            if cfg!(feature = "real_balance") && value != EVMU256::ZERO {
                let receiver = r_addr;
                if let Some(balance) = self.evmstate.get_balance(&receiver) {
                    self.evmstate.set_balance(receiver, *balance + value);
                } else {
                    self.evmstate.set_balance(receiver, self.next_slot + value);
                };
            }

            let mut interp = Interpreter::new_with_memory_limit(
                Contract::new_with_context(
                    Bytes::new(),
                    Bytecode::new_raw(inputs.init_code.clone()),
                    &CallContext {
                        address: r_addr,
                        caller: inputs.caller,
                        code_address: r_addr,
                        apparent_value: inputs.value,
                        scheme: CallScheme::Call,
                    },
                ),
                1e10 as u64,
                false,
                MEM_LIMIT,
            );
            let ret = self.run_inspect(&mut interp, state);
            debug!("create: {:?} -> {:?} = {:?}", inputs.caller, r_addr, ret);
            if !is_reverted_or_control_leak(&ret) {
                let runtime_code: Bytes = interp.return_value();
                self.set_code(r_addr, Bytecode::new_raw(runtime_code.clone()), state);
                if !unsafe { SETCODE_ONLY } {
                    // now we build & insert abi
                    let contract_code_str = hex::encode(&runtime_code);
                    let sigs = extract_sig_from_contract(&contract_code_str);
                    let mut unknown_sigs: usize = 0;
                    let mut parsed_abi = vec![];
                    for sig in &sigs {
                        if let Some(abi) = state.metadata_map().get::<ABIMap>().unwrap().get(sig) {
                            parsed_abi.push(abi.clone());
                        } else {
                            unknown_sigs += 1;
                        }
                    }

                    if unknown_sigs >= sigs.len() / 30 {
                        debug!("Too many unknown function signature for newly created contract, we are going to decompile this contract using EVMole");
                        let abis = fetch_abi_evmole(&runtime_code)
                            .iter()
                            .map(|abi| {
                                if let Some(known_abi) =
                                    state.metadata_map().get::<ABIMap>().unwrap().get(&abi.function)
                                {
                                    known_abi
                                } else {
                                    abi
                                }
                            })
                            .cloned()
                            .collect_vec();
                        parsed_abi = abis;
                    }
                    // notify flashloan and blacklisting flashloan addresses
                    handle_contract_insertion!(state, self, r_addr, r_addr, parsed_abi);

                    parsed_abi.iter().filter(|v| !v.is_constructor).for_each(|abi| {
                        #[cfg(not(feature = "fuzz_static"))]
                        if abi.is_static {
                            return;
                        }

                        let mut abi_instance = get_abi_type_boxed(&abi.abi);
                        abi_instance.set_func_with_signature(abi.function, &abi.function_name, &abi.abi);
                        register_abi_instance(r_addr, abi_instance.clone(), state);

                        let input = EVMInput {
                            caller: state.get_rand_caller(),
                            contract: r_addr,
                            data: Some(abi_instance),
                            sstate: StagedVMState::new_uninitialized(),
                            sstate_idx: 0,
                            txn_value: if abi.is_payable { Some(EVMU256::ZERO) } else { None },
                            step: false,
                            env: Default::default(),
                            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                            liquidation_percent: 0,
                            input_type: EVMInputTy::ABI,
                            direct_data: Default::default(),
                            randomness: vec![0],
                            repeat: 1,
                            swap_data: HashMap::new(),
                        };
                        add_corpus(self, state, &input);
                    });
                }
                (Continue, Some(r_addr), Gas::new(0), runtime_code)
            } else {
                (ret, Some(r_addr), Gas::new(0), Bytes::new())
            }
        } else {
            (InstructionResult::Revert, None, Gas::new(0), Bytes::new())
        }
    }

    fn call(
        &mut self,
        input: &mut CallInputs,
        interp: &mut Interpreter,
        output_info: (usize, usize),
        state: &mut EVMFuzzState,
    ) -> (InstructionResult, Gas, Bytes) {
        self.apply_prank(&interp.contract().caller, input);
        self.call_depth += 1;

        let value = EVMU256::from(input.transfer.value);
        if cfg!(feature = "real_balance") && value != EVMU256::ZERO {
            let sender = input.transfer.source;
            debug!("call sender: {:?}", sender);
            let current = if let Some(balance) = self.evmstate.get_balance(&sender) {
                *balance
            } else {
                self.evmstate.set_balance(sender, self.next_slot);
                self.next_slot
            };
            // debug!("call sender balance: {}", current);
            if current < value {
                return (Revert, Gas::new(0), Bytes::new());
            }
            self.evmstate.set_balance(sender, current - value);

            let receiver = input.transfer.target;
            if let Some(balance) = self.evmstate.get_balance(&receiver) {
                self.evmstate.set_balance(receiver, *balance + value);
            } else {
                self.evmstate.set_balance(receiver, self.next_slot + value);
            };
        }

        let mut res = if is_precompile(input.contract, self.precompiles.len()) {
            self.call_precompile(input, state)
        } else if unsafe { IS_FAST_CALL_STATIC || IS_FAST_CALL } {
            self.call_forbid_control_leak(input, state)
        } else {
            self.call_allow_control_leak(input, interp, output_info, state)
        };

        let ret_buffer = res.2.clone();

        self.call_depth -= 1;
        res = self.check_expected(input, res);
        self.clean_prank();

        unsafe {
            if self.middlewares_enabled {
                let mut middlewares = self.middlewares.read().unwrap().clone();
                for middleware in middlewares.iter_mut() {
                    middleware
                        .deref()
                        .borrow_mut()
                        .on_return(interp, self, state, &ret_buffer);
                }
            }
        }
        res
    }
}
