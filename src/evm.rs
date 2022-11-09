use std::collections::{HashMap, HashSet};

use std::i64::MAX;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::str::FromStr;

use crate::input::VMInputT;
use crate::rand_utils;
use crate::state_input::StagedVMState;
use bytes::Bytes;
use libafl::prelude::ObserversTuple;
use primitive_types::{H160, H256, U256};
use rand::random;
use revm::db::BenchmarkDB;
use revm::Return::{Continue, Revert};
use revm::{
    Bytecode, CallInputs, Contract, CreateInputs, Env, Gas, Host, Interpreter, LatestSpec, Return,
    SelfDestructResult, Spec,
};
use serde::{Deserialize, Serialize};

pub const MAP_SIZE: usize = 1024;

pub static mut jmp_map: [u8; MAP_SIZE] = [0; MAP_SIZE];
// dataflow
pub static mut read_map: [bool; MAP_SIZE] = [false; MAP_SIZE];
pub static mut write_map: [u8; MAP_SIZE] = [0; MAP_SIZE];

// cmp
pub static mut cmp_map: [U256; MAP_SIZE] = [U256::max_value(); MAP_SIZE];
pub static mut state_change: bool = false;

pub const RW_SKIPPER_PERCT_IDX: usize = 100;
pub const RW_SKIPPER_AMT: usize = MAP_SIZE - RW_SKIPPER_PERCT_IDX;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VMState {
    pub state: HashMap<H160, HashMap<U256, U256>>,
    // If control leak happens, we add state with incomplete execution to the corpus
    // More than one when the control is leaked again with the call based on the incomplete state
    pub post_execution: Vec<(Vec<U256>, usize)>,
}

impl VMState {
    pub fn get_hash(&self) -> u64 {
        let mut s = DefaultHasher::new();
        for i in self.state.iter() {
            i.0.0.hash(&mut s);
            for j in i.1.iter() {
                j.0.hash(&mut s);
                j.1.hash(&mut s);
            }
        }
        s.finish()
    }
}

impl VMState {
    pub(crate) fn new() -> Self {
        Self {
            state: HashMap::new(),
            post_execution: vec![],
        }
    }

    fn get(&self, address: &H160) -> Option<&HashMap<U256, U256>> {
        self.state.get(address)
    }

    fn get_mut(&mut self, address: &H160) -> Option<&mut HashMap<U256, U256>> {
        self.state.get_mut(address)
    }

    fn insert(&mut self, address: H160, storage: HashMap<U256, U256>) {
        self.state.insert(address, storage);
    }
}

use crate::state::HasHashToAddress;
pub use cmp_map as CMP_MAP;
pub use jmp_map as JMP_MAP;
pub use read_map as READ_MAP;
pub use write_map as WRITE_MAP;

#[derive(Clone, Debug)]
pub struct FuzzHost {
    pub data: VMState,
    // these are internal to the host
    env: Env,
    code: HashMap<H160, Bytecode>,
    hash_to_address: HashMap<[u8; 4], H160>,
    _pc: usize,
    pc_to_addresses: HashMap<usize, HashSet<H160>>,
    pc_to_call_hash: HashMap<usize, HashSet<Vec<u8>>>,
    #[cfg(feature = "record_instruction_coverage")]
    pub pc_coverage: HashMap<H160, HashSet<usize>>,
    #[cfg(feature = "record_instruction_coverage")]
    pub total_instr: HashMap<H160, usize>,
}

// hack: I don't want to change evm internal to add a new type of return
// this return type is never used as we disabled gas
const ControlLeak: Return = Return::FatalExternalError;
const ACTIVE_MATCH_EXT_CALL: bool = true;
const CONTROL_LEAK_DETECTION: bool = false;
const UNBOUND_CALL_THRESHOLD: usize = 10;

// if a PC transfers control to >1 addresses, we consider call at this PC to be unbounded
const CONTROL_LEAK_THRESHOLD: usize = 1;

impl FuzzHost {
    pub fn new() -> Self {
        Self {
            data: VMState::new(),
            env: Env::default(),
            code: HashMap::new(),
            hash_to_address: HashMap::new(),
            _pc: 0,
            pc_to_addresses: HashMap::new(),
            pc_to_call_hash: HashMap::new(),
            #[cfg(feature = "record_instruction_coverage")]
            pc_coverage: Default::default(),
            #[cfg(feature = "record_instruction_coverage")]
            total_instr: Default::default(),
        }
    }

    pub fn initalize<S>(&mut self, state: &S)
    where
        S: HasHashToAddress,
    {
        self.hash_to_address = state.get_hash_to_address().clone();
    }

    pub fn set_code(&mut self, address: H160, code: Bytecode) {
        self.code.insert(address, code.to_analysed::<LatestSpec>());
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
            // println!("{}", *interp.instruction_pointer);
            match *interp.instruction_pointer {
                0x57 => {
                    // JUMPI
                    let jump_dest = if interp.stack.peek(0).expect("stack underflow").is_zero() {
                        interp.stack.peek(1).expect("stack underflow").as_u64()
                    } else {
                        1
                    };
                    let idx = (interp.program_counter() ^ (jump_dest as usize)) % MAP_SIZE;
                    if jmp_map[idx] < 255 {
                        jmp_map[idx] += 1;
                    }

                    #[cfg(feature = "cmp")]
                    {
                        let idx = (interp.program_counter()) % MAP_SIZE;
                        if jump_dest != 1 {
                            CMP_MAP[idx] = U256::zero();
                        } else {
                            CMP_MAP[idx] = U256::from(1);
                        }
                    }
                }

                #[cfg(any(feature = "dataflow", feature = "cmp"))]
                0x55 => {
                    // SSTORE
                    #[cfg(feature = "dataflow")]
                    let value = interp.stack.peek(1).expect("stack underflow");
                    {
                        let mut key = interp.stack.peek(0).expect("stack underflow");
                        let v = u256_to_u8!(value) + 1;
                        WRITE_MAP[process_rw_key!(key)] = v;
                    }
                    let res = self.sload(
                        interp.contract.address,
                        interp.stack.peek(0).expect("stack underflow"),
                    );
                    state_change = res.expect("sload failed").0 != value;
                }

                #[cfg(feature = "dataflow")]
                0x54 => {
                    // SLOAD
                    let mut key = interp.stack.peek(0).expect("stack underflow");
                    READ_MAP[process_rw_key!(key)] = true;
                }

                // todo(shou): support signed checking
                #[cfg(feature = "cmp")]
                0x10 | 0x12 => {
                    // LT, SLT
                    let v1 = interp.stack.peek(0).expect("stack underflow");
                    let v2 = interp.stack.peek(1).expect("stack underflow");
                    let abs_diff = if v1 >= v2 {
                        if v1 - v2 != U256::zero() {
                            (v1 - v2)
                        } else { U256::from(1) }
                    } else { U256::zero() };
                    let idx = interp.program_counter() % MAP_SIZE;
                    if abs_diff < CMP_MAP[idx] {
                        CMP_MAP[idx] = abs_diff;
                    }
                }

                #[cfg(feature = "cmp")]
                0x11 | 0x13 => {
                    // GT, SGT
                    let v1 = interp.stack.peek(0).expect("stack underflow");
                    let v2 = interp.stack.peek(1).expect("stack underflow");
                    let abs_diff = if v1 <= v2 {
                        if v2 - v1 != U256::zero() {
                            (v2 - v1)
                        } else { U256::from(1) }
                    } else { U256::zero() };
                    let idx = interp.program_counter() % MAP_SIZE;
                    if abs_diff < CMP_MAP[idx] {
                        CMP_MAP[idx] = abs_diff;
                    }
                }

                #[cfg(feature = "cmp")]
                0x14 => {
                    // EQ
                    let v1 = interp.stack.peek(0).expect("stack underflow");
                    let v2 = interp.stack.peek(1).expect("stack underflow");
                    let abs_diff = if v1 < v2 { (v2 - v1) % (U256::max_value() - 1) + 1 } else { (v1 - v2) % (U256::max_value() - 1) + 1 };
                    let idx = interp.program_counter() % MAP_SIZE;
                    if abs_diff < CMP_MAP[idx] {
                        CMP_MAP[idx] = abs_diff;
                    }
                }

                0xf1 | 0xf2 | 0xf4 | 0xfa => {
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

        let mut input_seq = input.input.to_vec();
        // check unbound call
        if !self.pc_to_call_hash.contains_key(&self._pc) {
            self.pc_to_call_hash.insert(self._pc, HashSet::new());
        }
        self.pc_to_call_hash.get_mut(&self._pc).unwrap().insert(hash.to_vec());
        if self.pc_to_call_hash.get(&self._pc).unwrap().len() > UNBOUND_CALL_THRESHOLD && input_seq.len() >= 4 {
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

        if CONTROL_LEAK_DETECTION || contract_loc_option.is_none() {
            assert!(self._pc != 0);
            if !self.pc_to_addresses.contains_key(&self._pc) {
                self.pc_to_addresses.insert(self._pc, HashSet::new());
            }

            if self.pc_to_addresses.get(&self._pc).unwrap().len() > CONTROL_LEAK_THRESHOLD {
                return (ControlLeak, Gas::new(0), Bytes::new());
            }
            self.pc_to_addresses
                .get_mut(&self._pc)
                .unwrap()
                .insert(input.contract);
        }

        if ACTIVE_MATCH_EXT_CALL == true && contract_loc_option.is_some() {
            let mut interp = Interpreter::new::<LatestSpec>(
                Contract::new_with_context::<LatestSpec>(
                    input_bytes,
                    self.code.get(contract_loc_option.unwrap()).unwrap().clone(),
                    &input.context,
                ),
                1e10 as u64,
            );

            let ret = interp.run::<FuzzHost, LatestSpec>(self);
            return (ret, Gas::new(0), interp.return_value());
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
pub struct EVMExecutor<I, S> {
    pub host: FuzzHost,
    deployer: H160,
    phandom: PhantomData<(I, S)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub output: Bytes,
    pub reverted: bool,
    pub new_state: StagedVMState,
}

#[derive(Clone, Debug)]
pub struct IntermediateExecutionResult {
    pub output: Bytes,
    pub new_state: VMState,
    pub pc: usize,
    pub ret: Return,
    pub stack: Vec<U256>,
}

impl ExecutionResult {
    pub fn empty_result() -> Self {
        Self {
            output: Bytes::new(),
            reverted: false,
            new_state: StagedVMState::new_uninitialized(),
        }
    }
}

impl<I, S> EVMExecutor<I, S>
where
    I: VMInputT,
{
    pub fn new(FuzzHost: FuzzHost, deployer: H160) -> Self {
        Self {
            host: FuzzHost,
            deployer,
            phandom: PhantomData,
        }
    }

    pub fn finish_execution(&mut self, result: &ExecutionResult, input: &I) -> ExecutionResult {
        let new_state = result.new_state.state.clone();
        let mut last_output = result.output.clone();
        for post_exec in result.new_state.state.post_execution.clone() {
            // there are two cases
            // / 1. the post_exec finishes
            // / 2. the post_exec leads to a new control leak (i.e., there are more than 1
            //      control leak in this function)

            let mut recovering_stack = post_exec.0;
            // we need push the output of CALL instruction
            recovering_stack.push(U256::from(1));
            let r = self.execute_from_pc(
                input.get_contract(),
                input.get_caller(),
                &new_state,
                input.to_bytes(),
                // todo(@shou !important) do we need to increase pc?
                Some((recovering_stack, post_exec.1 + 1)),
                // todo(@shou !important) whats value
                0
            );
            last_output = r.output;
            if r.ret == Return::Return {
                continue;
            }
            if r.ret == ControlLeak {
                panic!("more than one reentrancy in a function! not supported yet");
            }
            if r.ret != Return::Return || r.ret != Return::Stop {
                return ExecutionResult {
                    output: last_output,
                    reverted: true,
                    new_state: StagedVMState {
                        state: new_state,
                        stage: result.new_state.stage,
                        initialized: result.new_state.initialized,
                    },
                };
            }
        }
        return ExecutionResult {
            output: last_output,
            reverted: false,
            new_state: StagedVMState {
                state: new_state,
                stage: result.new_state.stage,
                initialized: result.new_state.initialized,
            },
        };
    }

    pub fn deploy(&mut self, code: Bytecode, constructor_args: Bytes, deployed_address: H160) -> Option<H160> {
        let deployer = Contract::new::<LatestSpec>(
            constructor_args,
            code,
            deployed_address,
            self.deployer,
            U256::from(0),
        );
        let mut interp = Interpreter::new::<LatestSpec>(deployer, 1e10 as u64);
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
        self.host.set_code(
            deployed_address,
            Bytecode::new_raw(interp.return_value()).to_analysed::<LatestSpec>(),
        );
        self.host.total_instr.insert(
            deployed_address,
            EVMExecutor::<I, S>::count_instructions(
                &Bytecode::new_raw(interp.return_value()).to_analysed::<LatestSpec>(),
            ),
        );
        Some(deployed_address)
    }

    pub fn count_instructions(bytecode: &Bytecode) -> usize {
        let mut count: usize = 0;
        let mut i = 0;
        let bytes = bytecode.bytes();
        let mut complete_bytes = vec![];

        while i < bytes.len() {
            let op = *bytes.get(i).unwrap();
            complete_bytes.push(i);
            i += 1;
            count += 1;
            if op >= 0x60 && op <= 0x7f {
                i += op as usize - 0x5f;
            }
        }
        println!("complete bytes: {:?}", complete_bytes);
        count
    }

    pub fn execute<OT>(
        &mut self,
        contract_address: H160,
        caller: H160,
        state: &VMState,
        data: Bytes,
        value: usize,
        _observers: &mut OT,
    ) -> ExecutionResult
    where
        OT: ObserversTuple<I, S>,
    {
        let r = self.execute_from_pc(contract_address, caller, state, data, None, value);
        match r.ret {
            ControlLeak => {
                self.host.data.post_execution.push((r.stack, r.pc));
            }
            _ => {}
        }
        #[cfg(feature = "record_instruction_coverage")]
        {
            if random::<i32>() % 10000 == 0 {
                println!(
                    "coverage: {} out of {:?}",
                    self.host.pc_coverage.iter().fold(0, |acc, x| acc + {
                        if self.host.total_instr.contains_key(x.0) {
                            // println!("{:?}", x.1);
                            x.1.len()
                        } else {
                            0
                        }
                    }),
                    self.host
                        .total_instr
                        .keys()
                        .map(|k| (
                            self.host
                                .pc_coverage
                                .get(k)
                                .unwrap_or(&Default::default())
                                .len(),
                            self.host.total_instr.get(k).unwrap()
                        ))
                        .collect::<Vec<_>>()
                );
            }
        }
        return ExecutionResult {
            output: r.output,
            reverted: r.ret != Return::Return && r.ret != Return::Stop && r.ret != ControlLeak,
            new_state: StagedVMState::new_with_state(r.new_state),
        };
    }

    pub fn execute_from_pc(
        &mut self,
        contract_address: H160,
        caller: H160,
        state: &VMState,
        data: Bytes,
        post_exec: Option<(Vec<U256>, usize)>,
        value: usize
    ) -> IntermediateExecutionResult {
        self.host.data = state.clone();
        let call = Contract::new::<LatestSpec>(
            data,
            self.host
                .code
                .get(&contract_address)
                .expect("no code")
                .clone(),
            contract_address,
            caller,
            U256::from(value),
        );
        let mut new_bytecode: Option<*const u8> = None;
        let mut new_pc: Option<usize> = None;
        let mut new_stack: Option<Vec<U256>> = None;
        if post_exec.is_some() {
            unsafe {
                new_pc = Some(post_exec.as_ref().unwrap().1);
                new_bytecode = Some(call.bytecode.as_ptr().add(new_pc.unwrap()));
                new_stack = Some(post_exec.unwrap().0);
            }
        }
        let mut interp = Interpreter::new::<LatestSpec>(call, 1e10 as u64);
        if new_stack.is_some() {
            unsafe {
                for v in new_stack.unwrap() {
                    interp.stack.push(v);
                }
                interp.instruction_pointer = new_bytecode.unwrap();
            }
        }
        unsafe {
            state_change = false;
        }
        let r = interp.run::<FuzzHost, LatestSpec>(&mut self.host);
        IntermediateExecutionResult {
            output: interp.return_value(),
            new_state: self.host.data.clone(),
            pc: interp.program_counter(),
            ret: r,
            stack: interp.stack.data().clone(),
        }
    }
}
