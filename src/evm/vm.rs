/// EVM executor implementation
use itertools::Itertools;
use std::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::cmp::{max, min};
use std::collections::{HashMap, HashSet};

use std::collections::hash_map::DefaultHasher;
use std::fmt::{Debug, Formatter};
use std::fs::OpenOptions;

use std::hash::{Hash, Hasher};
use std::io::Write;

use std::marker::PhantomData;
use std::ops::Deref;

use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;

use crate::evm::types::{float_scale_to_u512, EVMU512};
use crate::input::{ConciseSerde, VMInputT};
use crate::state_input::StagedVMState;
use bytes::Bytes;

use libafl::prelude::{HasMetadata, HasRand};
use libafl::schedulers::Scheduler;
use libafl::state::{HasCorpus, State};

use primitive_types::{H256, U512};
use rand::random;

use revm::db::BenchmarkDB;
use revm_interpreter::{CallContext, CallScheme, Contract, InstructionResult, Interpreter};
use revm_primitives::{Bytecode, LatestSpec};

use crate::evm::bytecode_analyzer;
use crate::evm::host::{
    ControlLeak, FuzzHost, CMP_MAP, COVERAGE_NOT_CHANGED, GLOBAL_CALL_CONTEXT, JMP_MAP, READ_MAP,
    RET_OFFSET, RET_SIZE, STATE_CHANGE, WRITE_MAP,
};
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT, EVMInputTy};
use crate::evm::middlewares::middleware::{Middleware, MiddlewareType};
use crate::evm::onchain::flashloan::FlashloanData;
use crate::evm::types::{EVMAddress, EVMU256};
use crate::evm::uniswap::generate_uniswap_router_call;
use crate::generic_vm::vm_executor::{ExecutionResult, GenericVM, MAP_SIZE};
use crate::generic_vm::vm_state::VMStateT;
use crate::r#const::DEBUG_PRINT_PERCENT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasItyState};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use serde_traitobject::Any;

/// Get the token context from the flashloan middleware,
/// which contains uniswap pairs of that token
#[macro_export]
macro_rules! get_token_ctx {
    ($flashloan_mid: expr, $token: expr) => {
        $flashloan_mid
            .flashloan_oracle
            .deref()
            .borrow()
            .known_tokens
            .get(&$token)
            .expect(format!("unknown token : {:?}", $token).as_str())
    };
}

/// A post execution context
/// When control is leaked, we dump the current execution context. This context includes
/// all information needed to continue subsequent execution (e.g., stack, pc, memory, etc.)
/// Post execution context is attached to VM state if control is leaked.
///
/// When EVM input has `step` set to true, then we continue execution from the post
/// execution context available. If `step` is false, then we conduct reentrancy
/// (i.e., don't need to continue execution from the post execution context
/// but we execute the input directly
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PostExecutionCtx {
    /// Stack snapshot of VM
    pub stack: Vec<EVMU256>,
    /// Memory snapshot of VM
    pub memory: Vec<u8>,

    /// Program counter
    pub pc: usize,
    /// Current offset of the output buffer
    pub output_offset: usize,
    /// Length of the output buffer
    pub output_len: usize,

    /// Call data of the current call
    pub call_data: Bytes,

    /// Call context of the current call
    pub address: EVMAddress,
    pub caller: EVMAddress,
    pub code_address: EVMAddress,
    pub apparent_value: EVMU256,
}

impl PostExecutionCtx {
    /// Convert the post execution context to revm [`CallContext`]
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
    /// State of the EVM, which is mapping of EVMU256 slot to EVMU256 value for each contract
    pub state: HashMap<EVMAddress, HashMap<EVMU256, EVMU256>>,

    /// Post execution context
    /// If control leak happens, we add the post execution context to the VM state,
    /// which contains all information needed to continue execution.
    ///
    /// There can be more than one [`PostExecutionCtx`] when the control is leaked again
    /// on the incomplete state (i.e., double+ reentrancy)
    pub post_execution: Vec<PostExecutionCtx>,

    /// Flashloan information
    /// (e.g., how much flashloan is taken, and how much tokens are liquidated)
    pub flashloan_data: FlashloanData,

    /// Is bug() call in Solidity hit?
    pub bug_hit: bool,
    /// selftdestruct() call in Solidity hit?
    pub selfdestruct_hit: bool,
    /// bug type call in solidity type
    pub typed_bug: HashSet<String>,
}

impl Default for EVMState {
    /// Default VM state, containing empty state, no post execution context,
    /// and no flashloan usage
    fn default() -> Self {
        Self {
            state: HashMap::new(),
            post_execution: Vec::new(),
            flashloan_data: FlashloanData::new(),
            bug_hit: false,
            selfdestruct_hit: false,
            typed_bug: Default::default(),
        }
    }
}

impl VMStateT for EVMState {
    /// Calculate the hash of the VM state
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

    /// Check whether current state has post execution context
    /// This can also used to check whether a state is intermediate state (i.e., not yet
    /// finished execution)
    fn has_post_execution(&self) -> bool {
        self.post_execution.len() > 0
    }

    /// Get length needed for return data length of the call that leads to control leak
    fn get_post_execution_needed_len(&self) -> usize {
        self.post_execution.last().unwrap().output_len
    }

    /// Get the PC of last post execution context
    fn get_post_execution_pc(&self) -> usize {
        match self.post_execution.last() {
            Some(i) => i.pc,
            None => 0,
        }
    }

    /// Get amount of post execution context
    fn get_post_execution_len(&self) -> usize {
        self.post_execution.len()
    }

    /// Get flashloan information
    #[cfg(feature = "full_trace")]
    fn get_flashloan(&self) -> String {
        format!(
            "earned: {:?}, owed: {:?}",
            self.flashloan_data.earned, self.flashloan_data.owed
        )
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl EVMState {
    /// Create a new EVM state, containing empty state, no post execution context
    pub(crate) fn new() -> Self {
        Self {
            state: HashMap::new(),
            post_execution: vec![],
            flashloan_data: FlashloanData::new(),
            bug_hit: false,
            selfdestruct_hit: false,
            typed_bug: Default::default(),
        }
    }

    /// Get all storage slots of a specific contract
    pub fn get(&self, address: &EVMAddress) -> Option<&HashMap<EVMU256, EVMU256>> {
        self.state.get(address)
    }

    /// Get all storage slots of a specific contract (mutable)
    pub fn get_mut(&mut self, address: &EVMAddress) -> Option<&mut HashMap<EVMU256, EVMU256>> {
        self.state.get_mut(address)
    }

    /// Insert all storage slots of a specific contract
    pub fn insert(&mut self, address: EVMAddress, storage: HashMap<EVMU256, EVMU256>) {
        self.state.insert(address, storage);
    }
}

/// Is current EVM execution fast call
pub static mut IS_FAST_CALL: bool = false;

/// Is current EVM execution fast call (static)
/// - Fast call is a call that does not change the state of the contract
pub static mut IS_FAST_CALL_STATIC: bool = false;

/// EVM executor, wrapper of revm
#[derive(Debug, Clone)]
pub struct EVMExecutor<I, S, VS, CI>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    /// Host providing the blockchain environment (e.g., writing/reading storage), needed by revm
    pub host: FuzzHost<VS, I, S>,
    /// [Depreciated] Deployer address
    deployer: EVMAddress,
    phandom: PhantomData<(I, S, VS, CI)>,
}

/// Execution result that may have control leaked
/// Contains raw information of revm output and execution
#[derive(Clone, Debug)]
pub struct IntermediateExecutionResult {
    /// Output of the execution
    pub output: Bytes,
    /// The new state after execution
    pub new_state: EVMState,
    /// Program counter after execution
    pub pc: usize,
    /// Return value after execution
    pub ret: InstructionResult,
    /// Stack after execution
    pub stack: Vec<EVMU256>,
    /// Memory after execution
    pub memory: Vec<u8>,
}

impl<VS, I, S, CI> EVMExecutor<I, S, VS, CI>
where
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        + HasRand
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCaller<EVMAddress>
        + HasCurrentInputIdx
        + Default
        + Clone
        + Debug
        + 'static,
    VS: Default + VMStateT + 'static,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Create a new EVM executor given a host and deployer address
    pub fn new(fuzz_host: FuzzHost<VS, I, S>, deployer: EVMAddress) -> Self {
        Self {
            host: fuzz_host,
            deployer,
            phandom: PhantomData,
        }
    }

    /// Execute from a specific program counter and context
    ///
    /// `call_ctx` is the context of the call (e.g., caller address, callee address, etc.)
    /// `vm_state` is the VM state to execute on
    /// `data` is the input (function hash + serialized ABI args)
    /// `input` is the additional input information (e.g., access pattern, etc.)
    ///     If post execution context exists, then this is the return buffer of the call that leads
    ///     to control leak. This is like we are fuzzing the subsequent execution wrt the return
    ///     buffer of the control leak call.
    /// `post_exec` is the post execution context to use, if any
    ///     If `post_exec` is `None`, then the execution is from the beginning, otherwise it is from
    ///     the post execution context.
    pub fn execute_from_pc(
        &mut self,
        call_ctx: &CallContext,
        vm_state: &EVMState,
        data: Bytes,
        input: &I,
        post_exec: Option<PostExecutionCtx>,
        mut state: &mut S,
    ) -> IntermediateExecutionResult {
        // Initial setups
        self.host.coverage_changed = false;
        self.host.evmstate = vm_state.clone();
        self.host.env = input.get_vm_env().clone();
        self.host.access_pattern = input.get_access_pattern().clone();
        self.host.bug_hit = false;
        self.host.selfdestruct_hit = false;
        self.host.current_typed_bug = vec![];
        self.host.call_count = 0;
        self.host.randomness = input.get_randomness();
        let mut repeats = input.get_repeat();
        // Initially, there is no state change
        unsafe {
            STATE_CHANGE = false;
        }
        // Ensure that the call context is correct
        unsafe {
            GLOBAL_CALL_CONTEXT = Some(call_ctx.clone());
        }

        // Get the bytecode
        let mut bytecode = self
            .host
            .code
            .get(&call_ctx.code_address)
            .expect(&*format!("no code {:?}", call_ctx.code_address))
            .clone();

        // Create the interpreter
        let mut interp = if let Some(ref post_exec_ctx) = post_exec {
            // If there is a post execution context, then we need to create the interpreter from
            // the post execution context
            repeats = 1;
            unsafe {
                // setup the pc, memory, and stack as the post execution context
                let new_pc = post_exec_ctx.pc;
                let call = Contract::new_with_context_analyzed(
                    post_exec_ctx.call_data.clone(),
                    bytecode,
                    call_ctx,
                );
                let new_ip = call.bytecode.as_ptr().add(new_pc);
                let mut interp = Interpreter::new(call, 1e10 as u64, false);
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
                // set return buffer as the input
                // we remove the first 4 bytes because the first 4 bytes is the function hash (00000000 here)
                interp.return_data_buffer = data.slice(4..);
                interp
            }
        } else {
            // if there is no post execution context, then we create the interpreter from the
            // beginning
            let call = Contract::new_with_context_analyzed(data, bytecode, call_ctx);
            Interpreter::new(call, 1e10 as u64, false)
        };

        // Execute the contract for `repeats` times or until revert
        let mut r = InstructionResult::Stop;
        for v in 0..repeats - 1 {
            // println!("repeat: {:?}", v);
            r = self.host.run_inspect(&mut interp, state);
            interp.stack.data.clear();
            interp.memory.data.clear();
            interp.instruction_pointer = interp.contract.bytecode.as_ptr();
            if r == InstructionResult::Revert {
                interp.return_range = 0..0;
                break;
            }
        }
        if r != InstructionResult::Revert {
            r = self.host.run_inspect(&mut interp, state);
        }

        // Build the result
        let mut result = IntermediateExecutionResult {
            output: interp.return_value(),
            new_state: self.host.evmstate.clone(),
            pc: interp.program_counter(),
            ret: r,
            stack: interp.stack.data().clone(),
            memory: interp.memory.data().clone(),
        };

        // [todo] remove this
        unsafe {
            if self.host.coverage_changed {
                COVERAGE_NOT_CHANGED = 0;
            } else {
                COVERAGE_NOT_CHANGED += 1;
            }
        }

        // hack to record txn value
        #[cfg(feature = "flashloan_v2")]
        match self.host.flashloan_middleware {
            Some(ref m) => m
                .deref()
                .borrow_mut()
                .analyze_call(input, &mut result.new_state.flashloan_data),
            None => (),
        }

        #[cfg(not(feature = "flashloan_v2"))]
        {
            result.new_state.flashloan_data.owed +=
                EVMU512::from(call_ctx.apparent_value) * float_scale_to_u512(1.0, 5);
        }

        // remove all concolic hosts
        self.host
            .middlewares
            .deref()
            .borrow_mut()
            .retain(|k, _| *k != MiddlewareType::Concolic);

        result
    }

    /// Conduct a fast call that does not write to the feedback
    fn fast_call(
        &mut self,
        address: EVMAddress,
        data: Bytes,
        vm_state: &VS,
        state: &mut S,
        value: EVMU256,
        from: EVMAddress,
    ) -> IntermediateExecutionResult {
        unsafe {
            IS_FAST_CALL = true;
        }
        // println!("fast call: {:?} {:?} with {}", address, hex::encode(data.to_vec()), value);
        let call = Contract::new_with_context_analyzed(
            data,
            self.host
                .code
                .get(&address)
                .expect(&*format!("no code {:?}", address))
                .clone(),
            &CallContext {
                address,
                caller: from,
                code_address: address,
                apparent_value: value,
                scheme: CallScheme::Call,
            },
        );
        unsafe {
            self.host.evmstate = vm_state
                .as_any()
                .downcast_ref_unchecked::<EVMState>()
                .clone();
        }
        let mut interp = Interpreter::new(call, 1e10 as u64, false);
        let ret = self.host.run_inspect(&mut interp, state);
        unsafe {
            IS_FAST_CALL = false;
        }
        IntermediateExecutionResult {
            output: interp.return_value(),
            new_state: self.host.evmstate.clone(),
            pc: interp.program_counter(),
            ret,
            stack: Default::default(),
            memory: Default::default(),
        }
    }

    /// Execute a transaction, wrapper of [`EVMExecutor::execute_from_pc`]
    fn execute_abi(
        &mut self,
        input: &I,
        state: &mut S,
    ) -> ExecutionResult<EVMAddress, EVMAddress, VS, Vec<u8>, CI> {
        // Get necessary info from input
        let mut vm_state = unsafe {
            input
                .get_state()
                .as_any()
                .downcast_ref_unchecked::<EVMState>()
                .clone()
        };
        let is_step = input.is_step();
        let caller = input.get_caller();
        let mut data = Bytes::from(input.to_bytes());
        // use direct data (mostly used for debugging) if there is no data
        if data.len() == 0 {
            data = Bytes::from(input.get_direct_data());
        }
        let value = input.get_txn_value().unwrap_or(EVMU256::ZERO);
        let contract_address = input.get_contract();

        // Execute the transaction
        let mut r = if is_step {
            let mut post_exec = vm_state.post_execution.pop().unwrap().clone();
            self.host.origin = post_exec.caller;
            // we need push the output of CALL instruction
            post_exec.stack.push(EVMU256::from(1));
            // post_exec.pc += 1;
            self.execute_from_pc(
                &post_exec.get_call_ctx(),
                &vm_state,
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
                    apparent_value: value,
                    scheme: CallScheme::Call,
                },
                &vm_state,
                data,
                input,
                None,
                state,
            )
        };
        match r.ret {
            ControlLeak => unsafe {
                let global_ctx = GLOBAL_CALL_CONTEXT
                    .clone()
                    .expect("global call context should be set");
                r.new_state.post_execution.push(PostExecutionCtx {
                    stack: r.stack,
                    pc: r.pc,
                    output_offset: RET_OFFSET,
                    output_len: RET_SIZE,

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

        r.new_state.bug_hit = vm_state.bug_hit || self.host.bug_hit;
        r.new_state.selfdestruct_hit = vm_state.selfdestruct_hit || self.host.selfdestruct_hit;
        r.new_state.typed_bug = HashSet::from_iter(
            vm_state.typed_bug.iter().cloned().chain(
                self.host.current_typed_bug.iter().cloned()
            )
        );

        unsafe {
            ExecutionResult {
                output: r.output.to_vec(),
                reverted: r.ret != InstructionResult::Return
                    && r.ret != InstructionResult::Stop
                    && r.ret != ControlLeak
                    && r.ret != InstructionResult::SelfDestruct,
                new_state: StagedVMState::new_with_state(
                    VMStateT::as_any(&mut r.new_state)
                        .downcast_ref_unchecked::<VS>()
                        .clone(),
                ),
                additional_info: if r.ret == ControlLeak {
                    Some(vec![self.host.call_count as u8])
                } else {
                    None
                },
            }
        }
    }

    pub fn reexecute_with_middleware(
        &mut self,
        input: &I,
        state: &mut S,
        middleware: Rc<RefCell<dyn Middleware<VS, I, S>>>,
    ) {
        self.host.add_middlewares(middleware.clone());
        self.execute(input, state);
        self.host.remove_middlewares(middleware);
    }
}

pub static mut IN_DEPLOY: bool = false;

impl<VS, I, S, CI> GenericVM<VS, Bytecode, Bytes, EVMAddress, EVMAddress, EVMU256, Vec<u8>, I, S, CI>
    for EVMExecutor<I, S, VS, CI>
where
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        + HasRand
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCaller<EVMAddress>
        + HasCurrentInputIdx
        + Default
        + Clone
        + Debug
        + 'static,
    VS: VMStateT + Default + 'static,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde
{
    /// Deploy a contract
    fn deploy(
        &mut self,
        code: Bytecode,
        constructor_args: Option<Bytes>,
        deployed_address: EVMAddress,
        state: &mut S,
    ) -> Option<EVMAddress> {
        let deployer = Contract::new(
            constructor_args.unwrap_or(Bytes::new()),
            code,
            deployed_address,
            self.deployer,
            EVMU256::from(0),
        );
        // disable middleware for deployment
        unsafe {
            IN_DEPLOY = true;
        }
        let mut interp = Interpreter::new(deployer, 1e10 as u64, false);
        let mut dummy_state = S::default();
        let r = self.host.run_inspect(&mut interp, &mut dummy_state);
        unsafe {
            IN_DEPLOY = false;
        }
        if r != InstructionResult::Return {
            println!("deploy failed: {:?}", r);
            return None;
        }
        println!(
            "deployer = 0x{} contract = {:?}",
            hex::encode(self.deployer),
            hex::encode(interp.return_value())
        );
        let contract_code = Bytecode::new_raw(interp.return_value());
        bytecode_analyzer::add_analysis_result_to_state(&contract_code, state);
        self.host.set_code(deployed_address, contract_code, state);
        Some(deployed_address)
    }

    /// Execute an input (transaction)
    #[cfg(not(feature = "flashloan_v2"))]
    fn execute(
        &mut self,
        input: &I,
        state: &mut S,
    ) -> ExecutionResult<EVMAddress, EVMAddress, VS, Vec<u8>, CI> {
        self.execute_abi(input, state)
    }

    /// Execute an input (can be transaction or borrow)
    #[cfg(feature = "flashloan_v2")]
    fn execute(
        &mut self,
        input: &I,
        state: &mut S,
    ) -> ExecutionResult<EVMAddress, EVMAddress, VS, Vec<u8>, CI> {
        match input.get_input_type() {
            // buy (borrow because we have infinite ETH) tokens with ETH using uniswap
            EVMInputTy::Borrow => {
                let token = input.get_contract();

                let path_idx = input.get_randomness()[0] as usize;
                // generate the call to uniswap router for buying tokens using ETH
                let call_info = generate_uniswap_router_call(
                    get_token_ctx!(
                        self.host
                            .flashloan_middleware
                            .as_ref()
                            .unwrap()
                            .deref()
                            .borrow(),
                        token
                    ),
                    path_idx,
                    input.get_txn_value().unwrap(),
                    input.get_caller(),
                );
                // execute the transaction to get the state with the token borrowed
                match call_info {
                    Some((abi, value, target)) => {
                        let bys = abi.get_bytes();
                        let mut res = self.fast_call(
                            target,
                            Bytes::from(bys),
                            input.get_state(),
                            state,
                            value,
                            input.get_caller(),
                        );
                        #[cfg(feature = "flashloan_v2")]
                        match self.host.flashloan_middleware {
                            Some(ref m) => m
                                .deref()
                                .borrow_mut()
                                .analyze_call(input, &mut res.new_state.flashloan_data),
                            None => (),
                        }
                        unsafe {
                            ExecutionResult {
                                output: res.output.to_vec(),
                                reverted: res.ret != InstructionResult::Return
                                    && res.ret != InstructionResult::Stop
                                    && res.ret != ControlLeak,
                                new_state: StagedVMState::new_with_state(
                                    VMStateT::as_any(&mut res.new_state)
                                        .downcast_ref_unchecked::<VS>()
                                        .clone(),
                                ),
                                additional_info: None,
                            }
                        }
                    }
                    None => ExecutionResult {
                        // we don't have enough liquidity to buy the token
                        output: vec![],
                        reverted: false,
                        new_state: StagedVMState::new_with_state(input.get_state().clone()),
                        additional_info: None,
                    },
                }
            }
            EVMInputTy::Liquidate => {
                unreachable!("liquidate should be handled by middleware");
            }
            EVMInputTy::ABI => self.execute_abi(input, state),
        }
    }

    /// Execute a static call
    fn fast_static_call(
        &mut self,
        data: &Vec<(EVMAddress, Bytes)>,
        vm_state: &VS,
        state: &mut S,
    ) -> Vec<Vec<u8>> {
        unsafe {
            IS_FAST_CALL_STATIC = true;
            self.host.evmstate = vm_state
                .as_any()
                .downcast_ref_unchecked::<EVMState>()
                .clone();
            self.host.bug_hit = false;
            self.host.selfdestruct_hit = false;
            self.host.call_count = 0;
            self.host.current_typed_bug = vec![];
            self.host.randomness = vec![9];
        }

        let res = data.iter()
            .map(|(address, by)| {
                let ctx = CallContext {
                    address: *address,
                    caller: Default::default(),
                    code_address: *address,
                    apparent_value: Default::default(),
                    scheme: CallScheme::StaticCall,
                };
                let code = self.host.code.get(&address).expect("no code").clone();
                let call = Contract::new_with_context_analyzed(by.clone(), code.clone(), &ctx);
                let mut interp = Interpreter::new(call, 1e10 as u64, false);
                let ret = self.host.run_inspect(&mut interp, state);
                if ret == InstructionResult::Revert {
                    vec![]
                } else {
                    interp.return_value().to_vec()
                }
            })
            .collect::<Vec<Vec<u8>>>();

        unsafe {
            IS_FAST_CALL_STATIC = false;
        }
        res
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

    fn get_cmp(&self) -> &'static mut [EVMU256; MAP_SIZE] {
        unsafe { &mut CMP_MAP }
    }

    fn state_changed(&self) -> bool {
        unsafe { STATE_CHANGE }
    }
}

mod tests {
    use crate::evm::host::{FuzzHost, JMP_MAP};
    use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputTy};
    use crate::evm::mutator::AccessPattern;
    use crate::evm::types::{generate_random_address, EVMFuzzState, EVMU256};
    use crate::evm::vm::{EVMExecutor, EVMState};
    use crate::generic_vm::vm_executor::{GenericVM, MAP_SIZE};
    use crate::state::FuzzState;
    use crate::state_input::StagedVMState;
    use bytes::Bytes;
    use libafl::prelude::{tuple_list, StdScheduler};
    use revm_primitives::Bytecode;
    use std::cell::RefCell;
    use std::path::Path;
    use std::rc::Rc;
    use std::sync::Arc;

    #[test]
    fn test_fuzz_executor() {
        let mut state: EVMFuzzState = FuzzState::new(0);
        let path = Path::new("work_dir");
        if !path.exists() {
            std::fs::create_dir(path).unwrap();
        }
        let mut evm_executor: EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput> = EVMExecutor::new(
            FuzzHost::new(Arc::new(StdScheduler::new()), "work_dir".to_string()),
            generate_random_address(&mut state),
        );
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
                generate_random_address(&mut state),
                &mut FuzzState::new(0),
            )
            .unwrap();

        println!("deployed to address: {:?}", deployment_loc);

        let function_hash = hex::decode("90b6e333").unwrap();

        let input_0 = EVMInput {
            caller: generate_random_address(&mut state),
            contract: deployment_loc,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            #[cfg(feature = "flashloan_v2")]
            liquidation_percent: 0,
            direct_data: Bytes::from(
                [
                    function_hash.clone(),
                    hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                        .unwrap(),
                ]
                .concat(),
            ),
            #[cfg(feature = "flashloan_v2")]
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
        };

        let mut state = FuzzState::new(0);

        // process(0)
        let execution_result_0 = evm_executor.execute(&input_0, &mut state);
        let mut know_map: Vec<u8> = vec![0; MAP_SIZE];

        for i in 0..MAP_SIZE {
            know_map[i] = unsafe { JMP_MAP[i] };
            unsafe { JMP_MAP[i] = 0 };
        }
        assert_eq!(execution_result_0.reverted, false);

        // process(5)

        let input_5 = EVMInput {
            caller: generate_random_address(&mut state),
            contract: deployment_loc,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            #[cfg(feature = "flashloan_v2")]
            liquidation_percent: 0,
            direct_data: Bytes::from(
                [
                    function_hash.clone(),
                    hex::decode("0000000000000000000000000000000000000000000000000000000000000005")
                        .unwrap(),
                ]
                .concat(),
            ),
            #[cfg(feature = "flashloan_v2")]
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
        };

        let execution_result_5 = evm_executor.execute(&input_5, &mut state);

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
