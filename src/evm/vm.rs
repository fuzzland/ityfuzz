use itertools::Itertools;
use std::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::cmp::{max, min};
use std::collections::{HashMap, HashSet};

use std::collections::hash_map::DefaultHasher;
use std::fs::OpenOptions;
use std::hash::{Hash, Hasher};
use std::i64::MAX;
use std::io::Write;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::process::exit;
use std::rc::Rc;
use std::str::FromStr;

use crate::evm::concolic::concolic_host::ConcolicHost;
use crate::input::VMInputT;
use crate::rand_utils;
use crate::state_input::StagedVMState;
use bytes::Bytes;
use libafl::impl_serdeany;
use libafl::prelude::powersched::PowerSchedule;
use libafl::prelude::{HasMetadata, ObserversTuple, SerdeAnyMap};
use libafl::state::{HasCorpus, State};
use nix::libc::stat;
use primitive_types::{H160, H256, U256, U512};
use rand::random;
use revm::db::BenchmarkDB;
use revm::Return::{Continue, Revert};
use revm::{
    Bytecode, CallContext, CallInputs, CallScheme, Contract, CreateInputs, Env, Gas, Host,
    Interpreter, LatestSpec, Return, SelfDestructResult, Spec,
};
use serde::__private::de::Borrowed;
use serde::{Deserialize, Serialize};
use serde_traitobject::Any;

pub static mut jmp_map: [u8; MAP_SIZE] = [0; MAP_SIZE];

// dataflow
pub static mut read_map: [bool; MAP_SIZE] = [false; MAP_SIZE];
pub static mut write_map: [u8; MAP_SIZE] = [0; MAP_SIZE];

// cmp
pub static mut cmp_map: [U256; MAP_SIZE] = [U256::max_value(); MAP_SIZE];
pub static mut abi_max_size: [usize; MAP_SIZE] = [0; MAP_SIZE];
pub static mut state_change: bool = false;

pub const RW_SKIPPER_PERCT_IDX: usize = 100;
pub const RW_SKIPPER_AMT: usize = MAP_SIZE - RW_SKIPPER_PERCT_IDX;

pub static mut ret_size: usize = 0;
pub static mut ret_offset: usize = 0;
pub static mut global_call_context: Option<CallContext> = None;
pub static mut global_call_data: Option<CallContext> = None;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PostExecutionCtx {
    pub stack: Vec<U256>,
    pub pc: usize,
    pub output_offset: usize,
    pub output_len: usize,

    pub call_data: Bytes,

    pub address: H160,
    pub caller: H160,
    pub code_address: H160,
    pub apparent_value: U256,

    pub memory: Vec<u8>,
}

impl PostExecutionCtx {
    fn get_call_ctx(&self) -> CallContext {
        CallContext {
            address: self.address,
            caller: self.caller,
            apparent_value: self.apparent_value,
            code_address: self.code_address,
            scheme: CallScheme::Call,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EVMState {
    pub state: HashMap<H160, HashMap<U256, U256>>,
    // If control leak happens, we add state with incomplete execution to the corpus
    // More than one when the control is leaked again with the call based on the incomplete state
    pub post_execution: Vec<PostExecutionCtx>,
    pub leaked_func_hash: Option<u64>,
    pub flashloan_data: FlashloanData,
}

impl Default for EVMState {
    fn default() -> Self {
        Self {
            state: HashMap::new(),
            post_execution: Vec::new(),
            leaked_func_hash: None,
            flashloan_data: FlashloanData::new(),
        }
    }
}

impl VMStateT for EVMState {
    fn get_hash(&self) -> u64 {
        let mut s = DefaultHasher::new();
        for i in self.post_execution.iter() {
            i.pc.hash(&mut s);
            i.stack.hash(&mut s);
        }
        for i in self.state.iter().sorted_by_key(|k| k.0) {
            i.0 .0.hash(&mut s);
            for j in i.1.iter() {
                j.0.hash(&mut s);
                j.1.hash(&mut s);
            }
        }
        s.finish()
    }
    fn has_post_execution(&self) -> bool {
        self.post_execution.len() > 0
    }

    fn get_post_execution_needed_len(&self) -> usize {
        self.post_execution.last().unwrap().output_len
    }

    fn get_post_execution_pc(&self) -> usize {
        match self.post_execution.last() {
            Some(i) => i.pc,
            None => 0,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl EVMState {
    pub(crate) fn new() -> Self {
        Self {
            state: HashMap::new(),
            post_execution: vec![],
            leaked_func_hash: None,
            flashloan_data: FlashloanData::new(),
        }
    }

    pub fn get(&self, address: &H160) -> Option<&HashMap<U256, U256>> {
        self.state.get(address)
    }

    pub fn get_mut(&mut self, address: &H160) -> Option<&mut HashMap<U256, U256>> {
        self.state.get_mut(address)
    }

    pub fn insert(&mut self, address: H160, storage: HashMap<U256, U256>) {
        self.state.insert(address, storage);
    }
}

use crate::evm::input::EVMInputT;
use crate::evm::middleware::{
    CallMiddlewareReturn, CanHandleDeferredActions, ExecutionStage, Middleware, MiddlewareOp,
    MiddlewareType,
};
use crate::evm::onchain::flashloan::{Flashloan, FlashloanData};
use crate::evm::onchain::onchain::OnChain;
use crate::generic_vm::vm_executor::{ExecutionResult, GenericVM, MAP_SIZE};
use crate::generic_vm::vm_state::VMStateT;
#[cfg(feature = "record_instruction_coverage")]
use crate::r#const::DEBUG_PRINT_PERCENT;
use crate::state::{FuzzState, HasCaller, HasHashToAddress, HasItyState};
use crate::types::float_scale_to_u512;
pub use cmp_map as CMP_MAP;
pub use jmp_map as JMP_MAP;
pub use read_map as READ_MAP;
pub use write_map as WRITE_MAP;

#[derive(Debug)]
pub struct FuzzHost {
    pub data: EVMState,
    // these are internal to the host
    env: Env,
    code: HashMap<H160, Bytecode>,
    hash_to_address: HashMap<[u8; 4], HashSet<H160>>,
    _pc: usize,
    pc_to_addresses: HashMap<usize, HashSet<H160>>,
    pc_to_call_hash: HashMap<usize, HashSet<Vec<u8>>>,
    concolic_prob: f32,
    middlewares_enabled: bool,
    middlewares: Rc<RefCell<HashMap<MiddlewareType, Box<dyn Middleware>>>>,
    pub middlewares_deferred_actions: HashMap<MiddlewareType, Vec<MiddlewareOp>>,
    pub middlewares_latent_call_actions: Vec<CallMiddlewareReturn>,
    #[cfg(feature = "record_instruction_coverage")]
    pub pc_coverage: HashMap<H160, HashSet<usize>>,
    #[cfg(feature = "record_instruction_coverage")]
    pub total_instr: HashMap<H160, usize>,
    #[cfg(feature = "record_instruction_coverage")]
    pub total_instr_set: HashMap<H160, HashSet<usize>>,
    pub origin: H160,
}

// all clones would not include middlewares and states
impl Clone for FuzzHost {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            env: self.env.clone(),
            code: self.code.clone(),
            hash_to_address: self.hash_to_address.clone(),
            _pc: self._pc,
            pc_to_addresses: self.pc_to_addresses.clone(),
            pc_to_call_hash: self.pc_to_call_hash.clone(),
            concolic_prob: self.concolic_prob,
            middlewares_enabled: false,
            middlewares: Rc::new(RefCell::new(HashMap::new())),
            middlewares_deferred_actions: Default::default(),
            #[cfg(feature = "record_instruction_coverage")]
            pc_coverage: self.pc_coverage.clone(),
            #[cfg(feature = "record_instruction_coverage")]
            total_instr: self.total_instr.clone(),
            middlewares_latent_call_actions: vec![],
            origin: self.origin.clone(),
            total_instr_set: Default::default()
        }
    }
}

// hack: I don't want to change evm internal to add a new type of return
// this return type is never used as we disabled gas
const ControlLeak: Return = Return::FatalExternalError;
const ACTIVE_MATCH_EXT_CALL: bool = false;
const CONTROL_LEAK_DETECTION: bool = false;
const UNBOUND_CALL_THRESHOLD: usize = 10;

// if a PC transfers control to >2 addresses, we consider call at this PC to be unbounded
const CONTROL_LEAK_THRESHOLD: usize = 2;

pub fn instructions_pc(bytecode: &Bytecode) -> HashSet<usize> {
    let mut i = 0;
    let bytes = bytecode.bytes();
    let mut complete_bytes = vec![];

    while i < bytes.len() {
        let op = *bytes.get(i).unwrap();
        complete_bytes.push(i);
        i += 1;
        if op >= 0x60 && op <= 0x7f {
            i += op as usize - 0x5f;
        }
    }
    complete_bytes.into_iter().collect()
}

impl FuzzHost {
    pub fn new() -> Self {
        let mut ret = Self {
            data: EVMState::new(),
            env: Env::default(),
            code: HashMap::new(),
            hash_to_address: HashMap::new(),
            _pc: 0,
            pc_to_addresses: HashMap::new(),
            pc_to_call_hash: HashMap::new(),
            concolic_prob: 0.0,
            middlewares_enabled: false,
            middlewares: Rc::new(RefCell::new(HashMap::new())),
            middlewares_deferred_actions: Default::default(),
            #[cfg(feature = "record_instruction_coverage")]
            pc_coverage: Default::default(),
            #[cfg(feature = "record_instruction_coverage")]
            total_instr: Default::default(),
            middlewares_latent_call_actions: vec![],
            origin: Default::default(),
            total_instr_set: Default::default()
        };
        ret.env.block.timestamp = U256::max_value();
        ret
    }

    pub fn add_middlewares(&mut self, middlewares: Box<dyn Middleware>) {
        self.middlewares_enabled = true;
        let ty = middlewares.get_type();
        self.middlewares_deferred_actions.insert(ty, vec![]);
        self.middlewares
            .deref()
            .borrow_mut()
            .insert(ty, middlewares);
    }

    pub fn set_concolic_prob(&mut self, prob: f32) {
        if prob > 1.0 || prob < 0.0 {
            panic!("concolic prob should be in [0, 1]");
        } else if prob != 0.0 {
            self.concolic_prob = prob;
            self.middlewares_enabled = true;
        }
    }

    pub fn initialize<S>(&mut self, state: &S)
    where
        S: HasHashToAddress,
    {
        self.hash_to_address = state.get_hash_to_address().clone();
    }

    pub fn set_code(&mut self, address: H160, code: Bytecode) {
        #[cfg(any(feature = "evaluation", feature = "record_instruction_coverage"))]
        {
            let pcs = instructions_pc(&code.clone());
            self.total_instr.insert(
                address,
                pcs.len(),
            );
            self.total_instr_set.insert(address, pcs);
        }
        self.code.insert(address, code.to_analysed::<LatestSpec>());

    }

    #[cfg(feature = "record_instruction_coverage")]
    fn record_instruction_coverage(&mut self) {
        let mut data = format!(
            "coverage: {:?}",
            self.total_instr
                .keys()
                .map(|k| (
                    k,
                    self.pc_coverage.get(k).unwrap_or(&Default::default()).len(),
                    self.total_instr.get(k).unwrap()
                ))
                .collect::<Vec<_>>()
        );

        let mut not_covered: HashMap<H160, HashSet<usize>> = HashMap::new();
        for (addr, covs) in &self.total_instr_set {
            for cov in covs {
                match self.pc_coverage.get_mut(addr) {
                    Some(covs) => {
                        if !covs.contains(cov) {
                            not_covered.entry(*addr).or_insert(HashSet::new()).insert(*cov);
                        }
                    }
                    None => {
                        not_covered.entry(*addr).or_insert(HashSet::new()).insert(*cov);
                    }
                }
            }
        }

        data.push_str("\n\n\nnot covered: ");
        not_covered
            .iter()
            .for_each(
                |(addr, pcs)| {
                    data.push_str(&format!("{:?}: {:?}\n\n", addr, pcs.into_iter().sorted().collect::<Vec<_>>()));
                });


        let mut file = OpenOptions::new()
            .write(true)
            .append(false)
            .create(true)
            .open("cov.txt")
            .unwrap();
        file.write_all(data.as_bytes()).unwrap();
    }
}

macro_rules! process_rw_key {
    ($key:ident) => {
        if $key > U256::from(RW_SKIPPER_PERCT_IDX) {
            // $key >>= 4;
            $key %= U256::from(RW_SKIPPER_AMT);
            $key += U256::from(RW_SKIPPER_PERCT_IDX);
            $key.as_usize() % MAP_SIZE
        } else {
            $key.as_usize() % MAP_SIZE
        }
    };
}

macro_rules! u256_to_u8 {
    ($key:ident) => {
        (($key >> 4) % 254).as_u64() as u8
    };
}
impl Host for FuzzHost {
    const INSPECT: bool = true;
    type DB = BenchmarkDB;
    fn step(&mut self, interp: &mut Interpreter, _is_static: bool) -> Return {
        #[cfg(feature = "record_instruction_coverage")]
        {
            let address = interp.contract.address;
            let pc = interp.program_counter().clone();
            self.pc_coverage.entry(address).or_default().insert(pc);
        }

        unsafe {
            if self.middlewares_enabled {
                for (_, middleware) in &mut self.middlewares.clone().deref().borrow_mut().iter_mut()
                {
                    for op in middleware.on_step(interp) {
                        op.execute(self);
                    }
                }
            }

            macro_rules! fast_peek {
                ($idx:expr) => {
                    interp.stack.data()[interp.stack.len() - 1 - $idx]
                };
            }
            match *interp.instruction_pointer {
                // 0xfd => {
                //     // println!("fd {}", interp.program_counter());
                // }
                0x57 => {
                    // JUMPI
                    let jump_dest = if fast_peek!(0).is_zero() {
                        fast_peek!(1).as_u64()
                    } else {
                        1
                    };
                    let idx = (interp.program_counter() * (jump_dest as usize)) % MAP_SIZE;
                    if jmp_map[idx] < 255 {
                        jmp_map[idx] += 1;
                    }

                    #[cfg(feature = "cmp")]
                    {
                        let idx = (interp.program_counter()) % MAP_SIZE;
                        if jump_dest != 1 {
                            CMP_MAP[idx] = U256::zero();
                        } else {
                            CMP_MAP[idx] = U256::one();
                        }
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
                    let res = self.sload(interp.contract.address, fast_peek!(0));
                    state_change = res.expect("sload failed").0 != value;
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
                        if v1 - v2 != U256::zero() {
                            (v1 - v2)
                        } else {
                            U256::from(1)
                        }
                    } else {
                        U256::zero()
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
                        if v2 - v1 != U256::zero() {
                            (v2 - v1)
                        } else {
                            U256::from(1)
                        }
                    } else {
                        U256::zero()
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
                        (v2 - v1) % (U256::max_value() - 1) + 1
                    } else {
                        (v1 - v2) % (U256::max_value() - 1) + 1
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
                        ret_offset = fast_peek!(offset_of_ret_size - 1).as_usize();
                        // println!("ret_offset: {}", ret_offset);
                        ret_size = fast_peek!(offset_of_ret_size).as_usize();
                    }
                    self._pc = interp.program_counter();
                }
                _ => {}
            }
        }
        return Continue;
    }

    fn step_end(&mut self, _interp: &mut Interpreter, _is_static: bool, _ret: Return) -> Return {
        return Continue;
    }

    fn env(&mut self) -> &mut Env {
        return &mut self.env;
    }

    fn load_account(&mut self, _address: H160) -> Option<(bool, bool)> {
        Some((
            true,
            true, // self.data.contains_key(&address) || self.code.contains_key(&address),
        ))
    }

    fn block_hash(&mut self, number: U256) -> Option<H256> {
        println!("blockhash {}", number);

        Some(
            H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        )
    }

    fn balance(&mut self, _address: H160) -> Option<(U256, bool)> {
        // println!("balance");

        Some((U256::max_value(), true))
    }

    fn code(&mut self, address: H160) -> Option<(Bytecode, bool)> {
        // println!("code");
        match self.code.get(&address) {
            Some(code) => Some((code.clone(), true)),
            None => Some((Bytecode::new(), true)),
        }
    }

    fn code_hash(&mut self, _address: H160) -> Option<(H256, bool)> {
        Some((
            H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            true,
        ))
    }

    fn sload(&mut self, address: H160, index: U256) -> Option<(U256, bool)> {
        match self.data.get(&address) {
            Some(account) => Some((account.get(&index).unwrap_or(&U256::zero()).clone(), true)),
            None => Some((U256::zero(), true)),
        }
    }

    fn sstore(
        &mut self,
        address: H160,
        index: U256,
        value: U256,
    ) -> Option<(U256, U256, U256, bool)> {
        match self.data.get_mut(&address) {
            Some(account) => {
                account.insert(index, value);
            }
            None => {
                let mut account = HashMap::new();
                account.insert(index, value);
                self.data.insert(address, account);
            }
        };
        Some((U256::from(0), U256::from(0), U256::from(0), true))
    }

    fn log(&mut self, _address: H160, _topics: Vec<H256>, _data: Bytes) {
        if _topics.len() == 1 && (*_topics.last().unwrap()).0[31] == 0x37 {
            #[cfg(feature = "record_instruction_coverage")]
            self.record_instruction_coverage();
            panic!("target hit, {:?} - {:?}", hex::encode(_data), _topics);
        }
    }

    fn selfdestruct(&mut self, _address: H160, _target: H160) -> Option<SelfDestructResult> {
        return Some(SelfDestructResult::default());
    }

    fn create<SPEC: Spec>(
        &mut self,
        _inputs: &mut CreateInputs,
    ) -> (Return, Option<H160>, Gas, Bytes) {
        unsafe {
            println!("create");
        }
        return (
            Continue,
            Some(H160::from_str("0x0000000000000000000000000000000000000000").unwrap()),
            Gas::new(0),
            Bytes::new(),
        );
    }

    fn call<SPEC: Spec>(&mut self, input: &mut CallInputs) -> (Return, Gas, Bytes) {
        let mut hash = input.input.to_vec();
        hash.resize(4, 0);

        macro_rules! record_func_hash {
            () => {
                unsafe {
                    let mut s = DefaultHasher::new();
                    hash.hash(&mut s);
                    let _hash = s.finish();
                    abi_max_size[(_hash as usize) % MAP_SIZE] = ret_size;
                    self.data.leaked_func_hash = Some(_hash);
                }
            };
        }

        self.data.leaked_func_hash = None;

        let mut middleware_result: Option<(Return, Gas, Bytes)> = None;
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
            // random sample a key from hash_to_address
            let mut keys: Vec<&[u8; 4]> = self.hash_to_address.keys().collect();
            let selected_key = keys[hash.iter().map(|x| (*x) as usize).sum::<usize>() % keys.len()];
            hash = selected_key.to_vec();
            for i in 0..4 {
                input_seq[i] = hash[i];
            }
        }

        let input_bytes = Bytes::from(input_seq);

        // find the contract wrt the hash
        let contract_loc_option = self.hash_to_address.get(hash.as_slice());

        // if the contract is not found or control leak is enabled, return controlleak if it is unbounded call
        if CONTROL_LEAK_DETECTION || contract_loc_option.is_none() {
            assert_ne!(self._pc, 0);
            if !self.pc_to_addresses.contains_key(&self._pc) {
                self.pc_to_addresses.insert(self._pc, HashSet::new());
            }

            if self.pc_to_addresses.get(&self._pc).unwrap().len() > CONTROL_LEAK_THRESHOLD {
                // println!("control leak");
                record_func_hash!();
                return (ControlLeak, Gas::new(0), Bytes::new());
            }
            self.pc_to_addresses
                .get_mut(&self._pc)
                .unwrap()
                .insert(input.contract);
        }

        unsafe {
            global_call_context = Some(input.context.clone());
        }

        // find contracts that have this function hash
        if ACTIVE_MATCH_EXT_CALL == true && contract_loc_option.is_some() {
            let loc = contract_loc_option.unwrap();
            // if there is such a location known, then we can use exact call
            if !loc.contains(&input.contract) {
                // todo(@shou): resolve multi locs
                if loc.len() != 1 {
                    panic!("more than one contract found for the same hash");
                }
                let mut interp = Interpreter::new::<LatestSpec>(
                    Contract::new_with_context::<LatestSpec>(
                        input_bytes,
                        self.code.get(loc.iter().nth(0).unwrap()).unwrap().clone(),
                        &input.context,
                    ),
                    1e10 as u64,
                );

                let ret = interp.run::<FuzzHost, LatestSpec>(self);
                return (ret, Gas::new(0), interp.return_value());
            }
        }

        // transfer txn
        if hash == [0x00, 0x00, 0x00, 0x00] {
            return (Continue, Gas::new(0), Bytes::new());
        }

        // default behavior
        match self.code.get(&input.contract) {
            Some(code) => {
                let mut interp = Interpreter::new::<LatestSpec>(
                    Contract::new_with_context::<LatestSpec>(
                        input_bytes,
                        code.clone(),
                        &input.context,
                    ),
                    1e10 as u64,
                );
                let ret = interp.run::<FuzzHost, LatestSpec>(self);
                return (ret, Gas::new(0), interp.return_value());
            }
            None => {
                return (Revert, Gas::new(0), Bytes::new());
            }
        }

        return (Continue, Gas::new(0), Bytes::new());
    }
}

#[derive(Debug, Clone)]
pub struct EVMExecutor<I, S, VS> {
    pub host: FuzzHost,
    deployer: H160,
    phandom: PhantomData<(I, S, VS)>,
}

#[derive(Clone, Debug)]
pub struct IntermediateExecutionResult {
    pub output: Bytes,
    pub new_state: EVMState,
    pub pc: usize,
    pub ret: Return,
    pub stack: Vec<U256>,
    pub memory: Vec<u8>,
}

impl<VS, I, S> EVMExecutor<I, S, VS>
where
    I: VMInputT<VS, H160, H160> + 'static,
    S: State + HasCorpus<I> + HasItyState<H160, H160, VS> + HasMetadata + HasCaller<H160> + 'static,
    VS: Default + VMStateT + 'static,
{
    pub fn new(fuzz_host: FuzzHost, deployer: H160) -> Self {
        Self {
            host: fuzz_host,
            deployer,
            phandom: PhantomData,
        }
    }

    pub fn set_code(&mut self, address: H160, code: Vec<u8>) {
        let bytecode = Bytecode::new_raw(Bytes::from(code)).to_analysed::<LatestSpec>();
        self.host.set_code(address, bytecode.clone());
    }

    pub fn execute_from_pc(
        &mut self,
        call_ctx: &CallContext,
        vm_state: &EVMState,
        data: Bytes,
        input: &I,
        post_exec: Option<PostExecutionCtx>,
        mut state: Option<&mut S>,
    ) -> IntermediateExecutionResult {
        self.host.data = vm_state.clone();
        // although some of the concolic inputs are concrete
        // see EVMInputConstraint
        let input_len_concolic = data.len() * 8;

        unsafe {
            global_call_context = Some(call_ctx.clone());
        }

        let mut bytecode = self
            .host
            .code
            .get(&call_ctx.code_address)
            .expect("no code")
            .clone();

        let mut interp = if let Some(ref post_exec_ctx) = post_exec {
            unsafe {
                let new_pc = post_exec_ctx.pc;
                let call = Contract::new_with_context::<LatestSpec>(
                    post_exec_ctx.call_data.clone(),
                    bytecode,
                    call_ctx,
                );
                let new_ip = call.bytecode.as_ptr().add(new_pc);
                let mut interp = Interpreter::new::<LatestSpec>(call, 1e10 as u64);
                for v in post_exec_ctx.stack.clone() {
                    interp.stack.push(v);
                }
                interp.instruction_pointer = new_ip;
                interp.memory.resize(max(
                    post_exec_ctx.output_offset + post_exec_ctx.output_len,
                    post_exec_ctx.memory.len(),
                ));
                interp.memory.set(0, &post_exec_ctx.memory);

                interp.memory.set(
                    post_exec_ctx.output_offset,
                    &data[4..min(post_exec_ctx.output_len + 4, data.len())],
                );
                interp.return_data_buffer = data;
                interp
            }
        } else {
            let call = Contract::new_with_context::<LatestSpec>(data, bytecode, call_ctx);
            Interpreter::new::<LatestSpec>(call, 1e10 as u64)
        };
        unsafe {
            state_change = false;
        }

        if self.host.middlewares_enabled {
            let rand = rand::random::<f32>();
            if self.host.concolic_prob > rand {
                #[cfg(feature = "evm")]
                self.host.add_middlewares(Box::new(ConcolicHost::new(
                    input_len_concolic.try_into().unwrap(),
                    input.get_data_abi(),
                    input.get_caller(),
                )));
            }
        }

        // cleanup the deferred actions map
        if self.host.middlewares_enabled {
            self.host
                .middlewares_deferred_actions
                .iter_mut()
                .for_each(|(_, v)| {
                    v.clear();
                });
        }
        let r = interp.run::<FuzzHost, LatestSpec>(&mut self.host);

        // For each middleware, execute the deferred actions
        let mut result = IntermediateExecutionResult {
            output: interp.return_value(),
            new_state: self.host.data.clone(),
            pc: interp.program_counter(),
            ret: r,
            stack: interp.stack.data().clone(),
            memory: interp.memory.data().clone(),
        };
        // hack to record txn value
        if let Some(mid) = self
            .host
            .middlewares
            .deref()
            .borrow_mut()
            .get_mut(&MiddlewareType::Flashloan)
        {
            unsafe {
                mid.as_any()
                    .downcast_mut_unchecked::<Flashloan<S>>()
                    .handle_deferred_actions(
                        &MiddlewareOp::Owed(
                            MiddlewareType::Flashloan,
                            U512::from(call_ctx.apparent_value) * float_scale_to_u512(1.0, 5),
                        ),
                        state.as_mut().unwrap(),
                        &mut result,
                    )
            }
        }

        if self.host.middlewares_enabled {
            self.host.middlewares_deferred_actions.iter().for_each(|f| {
                macro_rules! define_deferred_handler {
                    ($t:ty) => {
                        for op in f.1 {
                            self.host
                                .middlewares
                                .deref()
                                .borrow_mut()
                                .get_mut(f.0)
                                .expect("middleware not found")
                                .as_any()
                                .downcast_mut_unchecked::<$t>()
                                .handle_deferred_actions(op, state.as_mut().unwrap(), &mut result);
                        }
                    };
                };
                unsafe {
                    match f.0 {
                        MiddlewareType::OnChain => {
                            define_deferred_handler!(OnChain<VS, I, S>)
                        }
                        MiddlewareType::Flashloan => {
                            define_deferred_handler!(Flashloan<S>)
                        }
                        MiddlewareType::Concolic => {
                            define_deferred_handler!(ConcolicHost)
                        }
                    }
                }
            });
        }

        // remove all concolic hosts
        self.host
            .middlewares
            .deref()
            .borrow_mut()
            .retain(|k, _| *k != MiddlewareType::Concolic);

        result
    }
}

impl<VS, I, S> GenericVM<VS, Bytecode, Bytes, H160, H160, U256, I, S> for EVMExecutor<I, S, VS>
where
    I: VMInputT<VS, H160, H160> + EVMInputT + 'static,
    S: State + HasCorpus<I> + HasItyState<H160, H160, VS> + HasMetadata + HasCaller<H160> + 'static,
    VS: VMStateT + Default + 'static,
{
    fn deploy(
        &mut self,
        code: Bytecode,
        constructor_args: Option<Bytes>,
        deployed_address: H160,
    ) -> Option<H160> {
        let deployer = Contract::new::<LatestSpec>(
            constructor_args.unwrap_or(Bytes::new()),
            code,
            deployed_address,
            self.deployer,
            U256::from(0),
        );
        let middleware_status = self.host.middlewares_enabled;
        // disable middleware for deployment
        self.host.middlewares_enabled = false;
        let mut interp = Interpreter::new::<LatestSpec>(deployer, 1e10 as u64);
        self.host.middlewares_enabled = middleware_status;
        let r = interp.run::<FuzzHost, LatestSpec>(&mut self.host);
        #[cfg(feature = "evaluation")]
        {
            self.host.pc_coverage = Default::default();
        }
        if r != Return::Return {
            println!("deploy failed: {:?}", r);
            return None;
        }
        assert_eq!(r, Return::Return);
        println!("contract = {:?}", hex::encode(interp.return_value()));
        self.set_code(
            deployed_address,
            interp.return_value().to_vec(),
        );
        Some(deployed_address)
    }

    fn execute(&mut self, input: &I, state: Option<&mut S>) -> ExecutionResult<H160, H160, VS> {
        let mut _vm_state = unsafe {
            input
                .get_state()
                .as_any()
                .downcast_ref_unchecked::<EVMState>()
                .clone()
        };
        // todo(@shou): is this correct?
        let is_step = input.is_step();
        let caller = input.get_caller();
        #[cfg(test)]
        let mut data = Bytes::from(input.to_bytes());
        #[cfg(not(test))]
        let data = Bytes::from(input.to_bytes());
        #[cfg(test)]
        if data.len() == 0 {
            data = Bytes::from(input.get_direct_data());
        }

        let value = input.get_txn_value().unwrap_or(0);
        let contract_address = input.get_contract();

        let mut r = if is_step {
            let mut post_exec = _vm_state.post_execution.pop().unwrap().clone();
            self.host.origin = post_exec.caller;
            // we need push the output of CALL instruction
            post_exec.stack.push(U256::one());
            // post_exec.pc += 1;
            self.execute_from_pc(
                &post_exec.get_call_ctx(),
                &_vm_state,
                data,
                input,
                Some(post_exec),
                state,
            )
        } else {
            self.host.origin = caller;
            self.execute_from_pc(
                &CallContext {
                    address: contract_address,
                    caller,
                    code_address: contract_address,
                    apparent_value: U256::from(value),
                    scheme: CallScheme::Call,
                },
                &_vm_state,
                data,
                input,
                None,
                state,
            )
        };
        match r.ret {
            ControlLeak => unsafe {
                let global_ctx = global_call_context
                    .clone()
                    .expect("global call context should be set");
                r.new_state.post_execution.push(PostExecutionCtx {
                    stack: r.stack,
                    pc: r.pc,
                    output_offset: ret_offset,
                    output_len: ret_size,

                    call_data: Default::default(),

                    address: global_ctx.address,
                    caller: global_ctx.caller,
                    code_address: global_ctx.code_address,
                    apparent_value: global_ctx.apparent_value,

                    memory: r.memory,
                });
            },
            _ => {}
        }
        #[cfg(feature = "record_instruction_coverage")]
        if random::<usize>() % DEBUG_PRINT_PERCENT == 0 {
            self.host.record_instruction_coverage();
        }
        return unsafe {
            ExecutionResult {
                output: r.output.to_vec(),
                reverted: r.ret != Return::Return && r.ret != Return::Stop && r.ret != ControlLeak,
                new_state: StagedVMState::new_with_state(
                    VMStateT::as_any(&mut r.new_state)
                        .downcast_ref_unchecked::<VS>()
                        .clone(),
                ),
            }
        };
    }

    fn get_jmp(&self) -> &'static mut [u8; MAP_SIZE] {
        unsafe { &mut JMP_MAP }
    }

    fn get_read(&self) -> &'static mut [bool; MAP_SIZE] {
        unsafe { &mut READ_MAP }
    }

    fn get_write(&self) -> &'static mut [u8; MAP_SIZE] {
        unsafe { &mut WRITE_MAP }
    }

    fn get_cmp(&self) -> &'static mut [U256; MAP_SIZE] {
        unsafe { &mut CMP_MAP }
    }

    fn state_changed(&self) -> bool {
        unsafe { state_change }
    }
}

mod tests {
    use super::*;
    use crate::evm::abi::get_abi_type;
    use crate::evm::input::EVMInput;
    use crate::evm::types::EVMFuzzState;
    use crate::evm::vm::EVMState;
    use crate::evm::vm::{FuzzHost, JMP_MAP};
    use crate::generic_vm::vm_executor::MAP_SIZE;
    use crate::rand_utils::generate_random_address;
    use crate::state::FuzzState;
    use crate::state_input::StagedVMState;
    use bytes::Bytes;
    use libafl::observers::StdMapObserver;
    use libafl::prelude::{tuple_list, HitcountsMapObserver};
    use libafl::state::State;
    use revm::Bytecode;

    #[test]
    fn test_fuzz_executor() {
        let mut evm_executor: EVMExecutor<EVMInput, EVMFuzzState, EVMState> =
            EVMExecutor::new(FuzzHost::new(), generate_random_address());
        let mut observers = tuple_list!();
        let mut vm_state = EVMState::new();

        /*
        contract main {
            function process(uint8 a) public {
                require(a < 2, "2");
            }
        }
        */
        let deployment_bytecode = hex::decode("608060405234801561001057600080fd5b506102ad806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c806390b6e33314610030575b600080fd5b61004a60048036038101906100459190610123565b610060565b60405161005791906101e9565b60405180910390f35b606060028260ff16106100a8576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161009f90610257565b60405180910390fd5b6040518060400160405280600f81526020017f48656c6c6f20436f6e74726163747300000000000000000000000000000000008152509050919050565b600080fd5b600060ff82169050919050565b610100816100ea565b811461010b57600080fd5b50565b60008135905061011d816100f7565b92915050565b600060208284031215610139576101386100e5565b5b60006101478482850161010e565b91505092915050565b600081519050919050565b600082825260208201905092915050565b60005b8381101561018a57808201518184015260208101905061016f565b83811115610199576000848401525b50505050565b6000601f19601f8301169050919050565b60006101bb82610150565b6101c5818561015b565b93506101d581856020860161016c565b6101de8161019f565b840191505092915050565b6000602082019050818103600083015261020381846101b0565b905092915050565b7f3200000000000000000000000000000000000000000000000000000000000000600082015250565b600061024160018361015b565b915061024c8261020b565b602082019050919050565b6000602082019050818103600083015261027081610234565b905091905056fea264697066735822122025c2570c6b62c0201c750ff809bdc45aad0eae99133699dec80912878b9cc33064736f6c634300080f0033").unwrap();

        let deployment_loc = evm_executor
            .deploy(
                Bytecode::new_raw(Bytes::from(deployment_bytecode)),
                None,
                generate_random_address(),
            )
            .unwrap();

        println!("deployed to address: {:?}", deployment_loc);

        let function_hash = hex::decode("90b6e333").unwrap();

        let input_0 = EVMInput {
            caller: generate_random_address(),
            contract: deployment_loc,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(0),
            step: false,
            direct_data: Bytes::from(
                [
                    function_hash.clone(),
                    hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                        .unwrap(),
                ]
                .concat(),
            ),
        };

        // process(0)
        let execution_result_0 = evm_executor.execute(&input_0, None);
        let mut know_map: Vec<u8> = vec![0; MAP_SIZE];

        for i in 0..MAP_SIZE {
            know_map[i] = unsafe { JMP_MAP[i] };
            unsafe { JMP_MAP[i] = 0 };
        }
        assert_eq!(execution_result_0.reverted, false);

        // process(5)

        let input_5 = EVMInput {
            caller: generate_random_address(),
            contract: deployment_loc,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(0),
            step: false,
            direct_data: Bytes::from(
                [
                    function_hash.clone(),
                    hex::decode("0000000000000000000000000000000000000000000000000000000000000005")
                        .unwrap(),
                ]
                .concat(),
            ),
        };

        let execution_result_5 = evm_executor.execute(&input_5, None);

        // checking cmp map about coverage
        let mut cov_changed = false;
        for i in 0..MAP_SIZE {
            let hit = unsafe { JMP_MAP[i] };
            if hit != know_map[i] && hit != 0 {
                println!("jmp_map[{}] = known: {}; new: {}", i, know_map[i], hit);
                unsafe { JMP_MAP[i] = 0 };
                cov_changed = true;
            }
        }
        assert_eq!(cov_changed, true);
        assert_eq!(execution_result_5.reverted, true);
    }
}
