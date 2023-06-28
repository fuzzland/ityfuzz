use crate::evm::bytecode_analyzer;
use crate::evm::input::{EVMInput, EVMInputT, EVMInputTy};
use crate::evm::middlewares::middleware::{CallMiddlewareReturn, Middleware, MiddlewareType};
use crate::evm::mutator::AccessPattern;
use crate::evm::onchain::flashloan::{Flashloan, FlashloanData};
use bytes::Bytes;
use itertools::Itertools;
use libafl::prelude::{HasCorpus, Scheduler, HasRand};
use libafl::state::State;
use primitive_types::H256;
use revm::db::BenchmarkDB;
use revm_interpreter::InstructionResult::{Continue, Return, Revert};


use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::fs::OpenOptions;
use std::hash::Hash;
use std::hash::Hasher;
use std::io::Write;
use std::ops::Deref;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use hex::FromHex;
use revm_interpreter::{BytecodeLocked, CallContext, CallInputs, CallScheme, Contract, CreateInputs, Gas, Host, InstructionResult, Interpreter, SelfDestructResult};
use revm_interpreter::analysis::to_analysed;
use revm_primitives::{B256, Bytecode, Env, LatestSpec, Spec};
use crate::evm::types::{as_u64, bytes_to_u64, EVMAddress, EVMU256, generate_random_address, is_zero};

use crate::evm::uniswap::{generate_uniswap_router_call, TokenContext};
use crate::evm::vm::EVMState;
use crate::generic_vm::vm_executor::{ExecutionResult, GenericVM, MAP_SIZE};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;

use crate::state::{HasCaller, HasCurrentInputIdx, HasHashToAddress, HasItyState};

use super::concolic::concolic_exe_host::ConcolicEVMExecutor;

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
pub static mut GLOBAL_CALL_CONTEXT: Option<CallContext> = None;
pub static mut GLOBAL_CALL_DATA: Option<CallContext> = None;

pub static mut PANIC_ON_BUG: bool = false;
pub static mut PANIC_ON_TYPEDBUG: bool = false;
// for debugging purpose, return ControlLeak when the calls amount exceeds this value
pub static mut CALL_UNTIL: u32 = u32::MAX;

/// Shall we dump the contract calls
pub static mut WRITE_RELATIONSHIPS: bool = false;


pub struct FuzzHost<VS, I, S>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress> + EVMInputT,
    VS: VMStateT,
{
    pub evmstate: EVMState,
    // these are internal to the host
    pub env: Env,
    pub code: HashMap<EVMAddress, Arc<BytecodeLocked>>,
    pub hash_to_address: HashMap<[u8; 4], HashSet<EVMAddress>>,
    pub address_to_hash: HashMap<EVMAddress, Vec<[u8; 4]>>,
    pub _pc: usize,
    pub pc_to_addresses: HashMap<usize, HashSet<EVMAddress>>,
    pub pc_to_call_hash: HashMap<usize, HashSet<Vec<u8>>>,
    pub concolic_enabled: bool,
    pub middlewares_enabled: bool,
    pub middlewares: Rc<RefCell<HashMap<MiddlewareType, Rc<RefCell<dyn Middleware<VS, I, S>>>>>>,

    pub coverage_changed: bool,

    pub flashloan_middleware: Option<Rc<RefCell<Flashloan<VS, I, S>>>>,

    pub middlewares_latent_call_actions: Vec<CallMiddlewareReturn>,

    pub origin: EVMAddress,

    pub scheduler: Arc<dyn Scheduler<EVMInput, S>>,

    // controlled by onchain module, if sload cant find the slot, use this value
    pub next_slot: EVMU256,

    pub access_pattern: Rc<RefCell<AccessPattern>>,

    pub bug_hit: bool,
    pub current_typed_bug: Vec<u64>,
    pub call_count: u32,

    #[cfg(feature = "print_logs")]
    pub logs: HashSet<u64>,
    // set_code data
    pub setcode_data: HashMap<EVMAddress, Bytecode>,
    // selftdestruct
    pub selfdestruct_hit:bool,
    // relations file handle
    relations_file: std::fs::File,
    // Filter duplicate relations
    relations_hash: HashSet<u64>,
    /// Known typed bugs, used for filtering in duplicate bugs
    known_typed_bugs: HashSet<u64>,
}

impl<VS, I, S> Debug for FuzzHost<VS, I, S>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress> + EVMInputT,
    VS: VMStateT,
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
            .field("concolic_enabled", &self.concolic_enabled)
            .field("middlewares_enabled", &self.middlewares_enabled)
            .field("middlewares", &self.middlewares)
            .field(
                "middlewares_latent_call_actions",
                &self.middlewares_latent_call_actions,
            )
            .field("origin", &self.origin)
            .finish()
    }
}

// all clones would not include middlewares and states
impl<VS, I, S> Clone for FuzzHost<VS, I, S>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress> + EVMInputT,
    VS: VMStateT,
{
    fn clone(&self) -> Self {
        Self {
            evmstate: self.evmstate.clone(),
            env: self.env.clone(),
            code: self.code.clone(),
            hash_to_address: self.hash_to_address.clone(),
            address_to_hash: self.address_to_hash.clone(),
            _pc: self._pc,
            pc_to_addresses: self.pc_to_addresses.clone(),
            pc_to_call_hash: self.pc_to_call_hash.clone(),
            concolic_enabled: false,
            middlewares_enabled: false,
            middlewares: Rc::new(RefCell::new(HashMap::new())),
            coverage_changed: false,
            flashloan_middleware: None,
            middlewares_latent_call_actions: vec![],
            origin: self.origin.clone(),
            scheduler: self.scheduler.clone(),
            next_slot: Default::default(),
            access_pattern: self.access_pattern.clone(),
            bug_hit: false,
            call_count: 0,
            #[cfg(feature = "print_logs")]
            logs: Default::default(),
            setcode_data:self.setcode_data.clone(),
            selfdestruct_hit:self.selfdestruct_hit,
            relations_file: self.relations_file.try_clone().unwrap(),
            relations_hash: self.relations_hash.clone(),
            current_typed_bug: self.current_typed_bug.clone(),
            known_typed_bugs: self.known_typed_bugs.clone(),
        }
    }
}

// hack: I don't want to change evm internal to add a new type of return
// this return type is never used as we disabled gas
pub(crate) const ControlLeak: InstructionResult = InstructionResult::FatalExternalError;
pub static mut ACTIVE_MATCH_EXT_CALL: bool = false;
const CONTROL_LEAK_DETECTION: bool = true;
const UNBOUND_CALL_THRESHOLD: usize = 3;

// if a PC transfers control to >2 addresses, we consider call at this PC to be unbounded
const CONTROL_LEAK_THRESHOLD: usize = 2;


impl<VS, I, S> FuzzHost<VS, I, S>
where
    S: State + HasCaller<EVMAddress> + Clone + Debug + HasCorpus<I> + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress> + EVMInputT,
    VS: VMStateT,
{
    pub fn new(scheduler: Arc<dyn Scheduler<EVMInput, S>>, workdir: String) -> Self {
        let ret = Self {
            evmstate: EVMState::new(),
            env: Env::default(),
            code: HashMap::new(),
            hash_to_address: HashMap::new(),
            address_to_hash: HashMap::new(),
            _pc: 0,
            pc_to_addresses: HashMap::new(),
            pc_to_call_hash: HashMap::new(),
            concolic_enabled: false,
            middlewares_enabled: false,
            middlewares: Rc::new(RefCell::new(HashMap::new())),
            coverage_changed: false,
            flashloan_middleware: None,
            middlewares_latent_call_actions: vec![],
            origin: Default::default(),
            scheduler,
            next_slot: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            bug_hit: false,
            call_count: 0,
            #[cfg(feature = "print_logs")]
            logs: Default::default(),
            setcode_data:HashMap::new(),
            selfdestruct_hit:false,
            relations_file: std::fs::File::create(format!("{}/relations.log", workdir)).unwrap(),
            relations_hash: HashSet::new(),
            current_typed_bug: Default::default(),
            known_typed_bugs: HashSet::new(),
        };
        // ret.env.block.timestamp = EVMU256::max_value();
        ret
    }

    pub fn remove_all_middlewares(&mut self) {
        self.middlewares_enabled = false;
        self.middlewares.deref().borrow_mut().clear();
    }

    pub fn add_middlewares(&mut self, middlewares: Rc<RefCell<dyn Middleware<VS, I, S>>>) {
        self.middlewares_enabled = true;
        let ty = middlewares.deref().borrow().get_type();
        self.middlewares
            .deref()
            .borrow_mut()
            .insert(ty, middlewares);
    }

    pub fn add_flashloan_middleware(&mut self, middlware: Flashloan<VS, I, S>) {
        self.flashloan_middleware = Some(Rc::new(RefCell::new(middlware)));
    }

    pub fn set_concolic_enabled(&mut self, enabled: bool) {
        self.concolic_enabled = enabled;
    }

    pub fn initialize(&mut self, state: &S)
    where
        S: HasHashToAddress,
    {
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

    pub fn set_codedata(&mut self, address: EVMAddress, mut code: Bytecode) {
        self.setcode_data.insert(address, code);
    }

    pub fn clear_codedata(&mut self) {
        self.setcode_data.clear();
    }

    pub fn set_code(&mut self, address: EVMAddress, mut code: Bytecode, state: &mut S) {
        unsafe {
            if self.middlewares_enabled {
                match self.flashloan_middleware.clone() {
                    Some(m) => {
                        let mut middleware = m.deref().borrow_mut();
                        middleware.on_insert(&mut code, address, self, state);
                    }
                    _ => {}
                }
                for (_, middleware) in &mut self.middlewares.clone().deref().borrow_mut().iter_mut()
                {
                    middleware
                        .deref()
                        .deref()
                        .borrow_mut()
                        .on_insert(&mut code, address, self, state);
                }
            }
        }
        assert!(self
            .code
            .insert(
                address,
                Arc::new(BytecodeLocked::try_from(to_analysed(code)).unwrap())
            )
            .is_none());
    }

    pub fn find_static_call_read_slot(
        &self,
        address: EVMAddress,
        data: Bytes,
        state: &mut S,
    ) -> Vec<EVMU256> {
        return vec![];
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
        //     interp.locate_slot::<FuzzHost<VS, I, S>, LatestSpec, S>(&mut self.clone(), state);
        // if ret != Return::Revert {
        //     slots
        // } else {
        //     vec![]
        // }
    }
    pub fn write_relations(&mut self, caller: EVMAddress, target: EVMAddress, funtion_hash: Bytes) {
        if funtion_hash.len() < 0x4 {
            return;
        }
        let cur_write_str = format!("{{caller:0x{} --> traget:0x{} function(0x{})}}\n", hex::encode(caller), hex::encode(target), hex::encode(&funtion_hash[..4]));
        let mut hasher = DefaultHasher::new();
        cur_write_str.hash(&mut hasher);
        let cur_wirte_hash = hasher.finish();
        if self.relations_hash.contains(&cur_wirte_hash) {
            return;
        }
        if self.relations_hash.len() == 0{
            let write_head = format!("[ityfuzz relations] caller, traget, function hash\n");
            self.relations_file
                .write_all(write_head.as_bytes())
                .unwrap();
        }

        self.relations_hash.insert(cur_wirte_hash);
        self.relations_file
            .write_all(cur_write_str.as_bytes())
            .unwrap();
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

pub static mut ARBITRARY_CALL: bool = false;

impl<VS, I, S> Host<S> for FuzzHost<VS, I, S>
where
    S: State +HasRand + HasCaller<EVMAddress> + Debug + Clone + HasCorpus<I> +  'static,
    I: VMInputT<VS, EVMAddress, EVMAddress> + EVMInputT,
    VS: VMStateT,
{
    fn step(&mut self, interp: &mut Interpreter, state: &mut S) -> InstructionResult {
        unsafe {
            if self.middlewares_enabled {
                match self.flashloan_middleware.clone() {
                    Some(m) => {
                        let mut middleware = m.deref().borrow_mut();
                        middleware.on_step(interp, self, state);
                    }
                    _ => {}
                }
                self.clear_codedata();
                for (_, middleware) in &mut self.middlewares.clone().deref().borrow_mut().iter_mut()
                {
                    middleware
                        .deref()
                        .deref()
                        .borrow_mut()
                        .on_step(interp, self, state);
                }

                for (address, code) in &self.setcode_data.clone() {
                    self.set_code(address.clone(), code.clone(), state);
                }
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
                0x57 => {
                    // JUMPI counter cond
                    let br = fast_peek!(1);
                    let jump_dest = if is_zero(br) {
                        1
                    } else {
                        as_u64(fast_peek!(0))
                    };
                    let idx = (interp.program_counter() * (jump_dest as usize)) % MAP_SIZE;
                    if JMP_MAP[idx] == 0 {
                        self.coverage_changed = true;
                    }
                    if JMP_MAP[idx] < 255 {
                        JMP_MAP[idx] += 1;
                    }

                    #[cfg(feature = "cmp")]
                    {
                        let idx = (interp.program_counter()) % MAP_SIZE;
                        CMP_MAP[idx] = br;
                    }
                }

                #[cfg(any(feature = "dataflow", feature = "cmp"))]
                0x55 => {
                    // SSTORE
                    #[cfg(feature = "dataflow")]
                    let value = fast_peek!(1);
                    {
                        let mut key = fast_peek!(0);
                        let v = u256_to_u8!(value) + 1;
                        WRITE_MAP[process_rw_key!(key)] = v;
                    }
                    let res = <FuzzHost<VS, I, S> as Host<S>>::sload(
                        self,
                        interp.contract.address,
                        fast_peek!(0),
                    );
                    let value_changed = res.expect("sload failed").0 != value;

                    let idx = interp.program_counter() % MAP_SIZE;
                    JMP_MAP[idx] = if value_changed { 1 } else { 0 };

                    STATE_CHANGE |= value_changed;
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
                    unsafe {
                        RET_OFFSET = as_u64(fast_peek!(offset_of_ret_size - 1)) as usize;
                        // println!("RET_OFFSET: {}", RET_OFFSET);
                        RET_SIZE = as_u64(fast_peek!(offset_of_ret_size)) as usize;
                    }
                    self._pc = interp.program_counter();
                }
                _ => {}
            }

            self.access_pattern
                .deref()
                .borrow_mut()
                .decode_instruction(interp);
        }
        return Continue;
    }

    fn step_end(&mut self, _interp: &mut Interpreter, _ret: InstructionResult, _: &mut S) -> InstructionResult {
        return Continue;
    }

    fn env(&mut self) -> &mut Env {
        return &mut self.env;
    }

    fn load_account(&mut self, _address: EVMAddress) -> Option<(bool, bool)> {
        Some((
            true,
            true, // self.data.contains_key(&address) || self.code.contains_key(&address),
        ))
    }

    fn block_hash(&mut self, _number: EVMU256) -> Option<B256> {
        Some(
            B256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        )
    }

    fn balance(&mut self, _address: EVMAddress) -> Option<(EVMU256, bool)> {
        // println!("balance");

        Some((EVMU256::MAX, true))
    }

    fn code(&mut self, address: EVMAddress) -> Option<(Arc<BytecodeLocked>, bool)> {
        // println!("code");
        match self.code.get(&address) {
            Some(code) => Some((code.clone(), true)),
            None => Some((Arc::new(
                BytecodeLocked::default()
            ), true)),
        }
    }

    fn code_hash(&mut self, _address: EVMAddress) -> Option<(B256, bool)> {
        Some((
            B256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            true,
        ))
    }

    fn sload(&mut self, address: EVMAddress, index: EVMU256) -> Option<(EVMU256, bool)> {
        if let Some(account) = self.evmstate.get(&address) {
            if let Some(slot) = account.get(&index) {
                return Some((slot.clone(), true));
            }
        }
        Some((self.next_slot, true))
        // match self.data.get(&address) {
        //     Some(account) => Some((account.get(&index).unwrap_or(&EVMU256::zero()).clone(), true)),
        //     None => Some((EVMU256::zero(), true)),
        // }
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

    fn log(&mut self, _address: EVMAddress, _topics: Vec<B256>, _data: Bytes) {
        if _topics.len() == 1 && (*_topics.last().unwrap()).0[31] == 0x37 {
            if unsafe {PANIC_ON_BUG} {
                panic!("target hit");
            }
            self.bug_hit = true;
        } else if _topics.len() == 1 && (*_topics.last().unwrap()).0[31] == 0x78{
            if unsafe {PANIC_ON_TYPEDBUG} {
                panic!("target typed_bug hit");
            }
            let current_type = bytes_to_u64(&(*_topics.last().unwrap()).0[23..31]);
            if !self.known_typed_bugs.contains(&current_type) {
                self.current_typed_bug.push(current_type);
                self.known_typed_bugs.insert(current_type);
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
            println!("log@{} {:?}", timestamp, hex::encode(_data));
        }
    }

    fn selfdestruct(&mut self, _address: EVMAddress, _target: EVMAddress) -> Option<SelfDestructResult> {
        return Some(SelfDestructResult::default());
    }

    fn create(
        &mut self,
        inputs: &mut CreateInputs,
        state: &mut S,
    ) -> (InstructionResult, Option<EVMAddress>, Gas, Bytes) {
        unsafe {
            // todo: use nonce + hash instead
            let r_addr = generate_random_address(state);
            let mut interp = Interpreter::new(
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
                false
            );
            let ret = interp.run_inspect::<S, FuzzHost<VS, I, S>, LatestSpec>(self, state);
            if ret == InstructionResult::Continue {
                self.set_code(
                    r_addr,
                    Bytecode::new_raw(interp.return_value()),
                    state
                );
                (
                    Continue,
                    Some(r_addr),
                    Gas::new(0),
                    interp.return_value(),
                )
            } else {
                (
                    ret,
                    Some(r_addr),
                    Gas::new(0),
                    Bytes::new(),
                )
            }
        }
    }

    fn call(&mut self, input: &mut CallInputs, state: &mut S) -> (InstructionResult, Gas, Bytes) {
        self.call_count += 1;
        if self.call_count >= unsafe {CALL_UNTIL} {
            return (ControlLeak, Gas::new(0), Bytes::new());
        }

        if unsafe { WRITE_RELATIONSHIPS } {
            self.write_relations(
                input.transfer.source.clone(),
                input.contract.clone(),
                input.input.clone(),
            );
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

        if middleware_result.is_some() {
            return middleware_result.unwrap();
        }

        // if calling sender, then definitely control leak
        if self.origin == input.contract {
            record_func_hash!();
            // println!("call self {:?} -> {:?} with {:?}", input.context.caller, input.contract, hex::encode(input.input.clone()));
            return (ControlLeak, Gas::new(0), Bytes::new());
        }

        let mut input_seq = input.input.to_vec();

        // check whether the whole CALLDATAVALUE can be arbitrary
        if !self.pc_to_call_hash.contains_key(&self._pc) {
            self.pc_to_call_hash.insert(self._pc, HashSet::new());
        }
        self.pc_to_call_hash
            .get_mut(&self._pc)
            .unwrap()
            .insert(hash.to_vec());
        if self.pc_to_call_hash.get(&self._pc).unwrap().len() > UNBOUND_CALL_THRESHOLD
            && input_seq.len() >= 4
        {
            unsafe {
                ARBITRARY_CALL = true;
            }
            // random sample a key from hash_to_address
            // println!("unbound call {:?} -> {:?} with {:?}", input.context.caller, input.contract, hex::encode(input.input.clone()));
            match self.address_to_hash.get_mut(&input.context.code_address) {
                None => {}
                Some(hashes) => {
                    let selected_key =
                        hashes[hash.iter().map(|x| (*x) as usize).sum::<usize>() % hashes.len()];
                    for i in 0..4 {
                        input_seq[i] = selected_key[i];
                    }
                }
            }
        }

        // control leak check
        assert_ne!(self._pc, 0);
        if !self.pc_to_addresses.contains_key(&self._pc) {
            self.pc_to_addresses.insert(self._pc, HashSet::new());
        }
        let addresses_at_pc = self.pc_to_addresses.get_mut(&self._pc).unwrap();
        addresses_at_pc.insert(input.contract);

        // if control leak is enabled, return controlleak if it is unbounded call
        if CONTROL_LEAK_DETECTION == true {
            if addresses_at_pc.len() > CONTROL_LEAK_THRESHOLD {
                record_func_hash!();
                return (ControlLeak, Gas::new(0), Bytes::new());
            }
        }

        let mut old_call_context = None;
        unsafe {
            old_call_context = GLOBAL_CALL_CONTEXT.clone();
            GLOBAL_CALL_CONTEXT = Some(input.context.clone());
        }

        macro_rules! ret_back_ctx {
            () => {
                unsafe {
                    GLOBAL_CALL_CONTEXT = old_call_context;
                }
            };
        }

        let input_bytes = Bytes::from(input_seq);

        // find contracts that have this function hash
        let contract_loc_option = self.hash_to_address.get(hash.as_slice());
        if unsafe { ACTIVE_MATCH_EXT_CALL } && contract_loc_option.is_some() {
            let loc = contract_loc_option.unwrap();
            // if there is such a location known, then we can use exact call
            if !loc.contains(&input.contract) {
                // todo(@shou): resolve multi locs
                if loc.len() != 1 {
                    panic!("more than one contract found for the same hash");
                }
                let mut interp = Interpreter::new(
                    Contract::new_with_context_analyzed(
                        input_bytes,
                        self.code.get(loc.iter().nth(0).unwrap()).unwrap().clone(),
                        &input.context,
                    ),
                    1e10 as u64,
                    false
                );

                let ret = interp.run_inspect::<S, FuzzHost<VS, I, S>, LatestSpec>(self, state);
                ret_back_ctx!();
                return (ret, Gas::new(0), interp.return_value());
            }
        }

        // if there is code, then call the code
        if let Some(code) = self.code.get(&input.context.code_address) {
            let mut interp = Interpreter::new(
                Contract::new_with_context_analyzed(
                    input_bytes.clone(),
                    code.clone(),
                    &input.context,
                ),
                1e10 as u64,
                false
            );
            let ret = interp.run_inspect::<S, FuzzHost<VS, I, S>, LatestSpec>(self, state);
            ret_back_ctx!();
            return (ret, Gas::new(0), interp.return_value());
        }

        // transfer txn and fallback provided
        if hash == [0x00, 0x00, 0x00, 0x00] {
            ret_back_ctx!();
            return (Continue, Gas::new(0), Bytes::new());
        }

        ret_back_ctx!();
        return (Revert, Gas::new(0), Bytes::new());
    }
}
