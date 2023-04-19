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

use crate::input::VMInputT;

use crate::state_input::StagedVMState;
use crate::tracer::build_basic_txn_from_input;
use bytes::Bytes;

use libafl::prelude::HasMetadata;
use libafl::schedulers::Scheduler;
use libafl::state::{HasCorpus, State};

use primitive_types::{H160, H256, U256, U512};
use rand::random;

use revm::db::BenchmarkDB;
use revm::Return::{Continue, Revert};
use revm::{
    Bytecode, CallContext, CallInputs, CallScheme, Contract, CreateInputs, Env, Gas, Host,
    Interpreter, LatestSpec, Return, SelfDestructResult, Spec,
};

use crate::evm::bytecode_analyzer;
use crate::evm::concolic::concolic_exe_host::ConcolicEVMExecutor;
use crate::evm::host::{
    ControlLeak, FuzzHost, CMP_MAP, COVERAGE_NOT_CHANGED, GLOBAL_CALL_CONTEXT, JMP_MAP, READ_MAP,
    RET_OFFSET, RET_SIZE, STATE_CHANGE, WRITE_MAP,
};
use crate::evm::input::{EVMInputT, EVMInputTy};
use crate::evm::middleware::MiddlewareType;
use crate::evm::onchain::flashloan::FlashloanData;
use crate::evm::uniswap::generate_uniswap_router_call;
use crate::generic_vm::vm_executor::{ExecutionResult, GenericVM, MAP_SIZE};
use crate::generic_vm::vm_state::VMStateT;
use crate::r#const::DEBUG_PRINT_PERCENT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasItyState};
use crate::types::float_scale_to_u512;
use serde::{Deserialize, Serialize};
use serde_traitobject::Any;

#[macro_export]
macro_rules! get_token_ctx {
    ($flashloan_mid: expr, $token: expr) => {
        $flashloan_mid
            .flashloan_oracle
            .deref()
            .borrow()
            .known_tokens
            .get(&$token)
            .unwrap()
    };
}

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

    fn get_post_execution_len(&self) -> usize {
        self.post_execution.len()
    }

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

pub static mut IS_FAST_CALL: bool = false;

#[derive(Debug, Clone)]
pub struct EVMExecutor<I, S, VS>
where
    S: State + HasCaller<H160> + Debug + Clone + 'static,
    I: VMInputT<VS, H160, H160> + EVMInputT,
    VS: VMStateT,
{
    pub host: FuzzHost<VS, I, S>,
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
    I: VMInputT<VS, H160, H160> + EVMInputT + 'static,
    S: State
        + HasCorpus<I>
        + HasItyState<H160, H160, VS>
        + HasMetadata
        + HasCaller<H160>
        + HasCurrentInputIdx
        + Default
        + Clone
        + Debug
        + 'static,
    VS: Default + VMStateT + 'static,
{
    pub fn new(fuzz_host: FuzzHost<VS, I, S>, deployer: H160) -> Self {
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
        mut state: &mut S,
    ) -> IntermediateExecutionResult {
        self.host.coverage_changed = false;
        self.host.evmstate = vm_state.clone();
        self.host.env = input.get_vm_env().clone();
        self.host.access_pattern = input.get_access_pattern().clone();

        unsafe {
            GLOBAL_CALL_CONTEXT = Some(call_ctx.clone());
        }

        let mut bytecode = self
            .host
            .code
            .get(&call_ctx.code_address)
            .expect(&*format!("no code {:?}", call_ctx.code_address))
            .clone();

        unsafe {
            STATE_CHANGE = false;
        }

        let mut repeats = input.get_repeat();

        let mut interp = if let Some(ref post_exec_ctx) = post_exec {
            repeats = 1;
            unsafe {
                let new_pc = post_exec_ctx.pc;
                let call = Contract::new_with_context_not_cloned::<LatestSpec>(
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
                interp.return_data_buffer = data.slice(4..);
                interp
            }
        } else {
            let call =
                Contract::new_with_context_not_cloned::<LatestSpec>(data, bytecode, call_ctx);
            Interpreter::new::<LatestSpec>(call, 1e10 as u64)
        };

        let mut r = Return::Stop;
        for v in 0..repeats - 1 {
            // println!("repeat: {:?}", v);
            r = interp.run::<FuzzHost<VS, I, S>, LatestSpec, S>(&mut self.host, state);
            interp.stack.data.clear();
            interp.memory.data.clear();
            interp.instruction_pointer = interp.contract.bytecode.as_ptr();
            if r == Revert {
                interp.return_range = 0..0;
                break;
            }
        }

        if r != Revert {
            r = interp.run::<FuzzHost<VS, I, S>, LatestSpec, S>(&mut self.host, state);
        }

        let mut result = IntermediateExecutionResult {
            output: interp.return_value(),
            new_state: self.host.evmstate.clone(),
            pc: interp.program_counter(),
            ret: r,
            stack: interp.stack.data().clone(),
            memory: interp.memory.data().clone(),
        };

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
                U512::from(call_ctx.apparent_value) * float_scale_to_u512(1.0, 5);
        }

        // remove all concolic hosts
        self.host
            .middlewares
            .deref()
            .borrow_mut()
            .retain(|k, _| *k != MiddlewareType::Concolic);

        result
    }

    fn fast_call(
        &mut self,
        address: H160,
        data: Bytes,
        vm_state: &VS,
        state: &mut S,
        value: U256,
        from: H160,
    ) -> IntermediateExecutionResult {
        unsafe {
            IS_FAST_CALL = true;
        }
        // println!("fast call: {:?} {:?} with {}", address, hex::encode(data.to_vec()), value);
        let call = Contract::new_with_context_not_cloned::<LatestSpec>(
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
        let mut interp = Interpreter::new::<LatestSpec>(call, 1e10 as u64);
        let ret = interp.run::<FuzzHost<VS, I, S>, LatestSpec, S>(&mut self.host, state);
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

    fn execute_abi(
        &mut self,
        input: &I,
        state: &mut S,
    ) -> ExecutionResult<H160, H160, VS, Vec<u8>> {
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
        let mut data = Bytes::from(input.to_bytes());
        #[cfg(any(test, feature = "debug"))]
        if data.len() == 0 {
            data = Bytes::from(input.get_direct_data());
        }

        let value = input.get_txn_value().unwrap_or(U256::zero());
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
            let _input_len_concolic = data.len() * 8;

            // TODO: implement baseline here
            if self.host.middlewares_enabled && self.host.concolic_enabled {
                unsafe {
                    // here probably we should reset the number to 0?
                    // or let concolic run for ten times?
                    if COVERAGE_NOT_CHANGED > 10000 {
                        COVERAGE_NOT_CHANGED = 0;
                        let mut txntrace = input.get_staged_state().trace.clone();
                        txntrace.add_txn(build_basic_txn_from_input(input));
                        let mut concolic_exe_host = ConcolicEVMExecutor::new(
                            self.host.clone(),
                            self.deployer,
                            contract_address,
                            txntrace,
                        );
                        concolic_exe_host.execute_all(state);
                    }
                }
            }
            self.host.origin = caller;
            self.execute_from_pc(
                &CallContext {
                    address: contract_address,
                    caller,
                    code_address: contract_address,
                    apparent_value: value,
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
        #[cfg(feature = "record_instruction_coverage")]
        if random::<usize>() % DEBUG_PRINT_PERCENT == 0 {
            self.host.record_instruction_coverage();
        }
        unsafe {
            ExecutionResult {
                output: r.output.to_vec(),
                reverted: r.ret != Return::Return && r.ret != Return::Stop && r.ret != ControlLeak,
                new_state: StagedVMState::new_with_state(
                    VMStateT::as_any(&mut r.new_state)
                        .downcast_ref_unchecked::<VS>()
                        .clone(),
                ),
            }
        }
    }
}

impl<VS, I, S> GenericVM<VS, Bytecode, Bytes, H160, H160, U256, Vec<u8>, I, S>
    for EVMExecutor<I, S, VS>
where
    I: VMInputT<VS, H160, H160> + EVMInputT + 'static,
    S: State
        + HasCorpus<I>
        + HasItyState<H160, H160, VS>
        + HasMetadata
        + HasCaller<H160>
        + HasCurrentInputIdx
        + Default
        + Clone
        + Debug
        + 'static,
    VS: VMStateT + Default + 'static,
{
    fn deploy(
        &mut self,
        code: Bytecode,
        constructor_args: Option<Bytes>,
        deployed_address: H160,
        state: &mut S,
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
        let mut dummy_state = S::default();
        let r = interp.run::<FuzzHost<VS, I, S>, LatestSpec, S>(&mut self.host, &mut dummy_state);
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
        let contract_code = Bytecode::new_raw(interp.return_value());
        bytecode_analyzer::add_analysis_result_to_state(&contract_code, state);
        self.host.set_code(deployed_address, contract_code);
        Some(deployed_address)
    }

    #[cfg(not(feature = "flashloan_v2"))]
    fn execute(&mut self, input: &I, state: &mut S) -> ExecutionResult<H160, H160, VS, Vec<u8>> {
        self.execute_abi(input, state)
    }

    #[cfg(feature = "flashloan_v2")]
    fn execute(&mut self, input: &I, state: &mut S) -> ExecutionResult<H160, H160, VS, Vec<u8>> {
        match input.get_input_type() {
            EVMInputTy::Borrow => {
                let token = input.get_contract();

                let path_idx = input.get_randomness()[0] as usize;
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
                match call_info {
                    Some((abi, value, target)) => {
                        // println!("borrow: {:?} {:?} {:?}", hex::encode(abi.get_bytes()), value, target);
                        let mut res = self.fast_call(
                            target,
                            Bytes::from(abi.get_bytes()),
                            input.get_state(),
                            state,
                            value,
                            input.get_caller(),
                        );
                        // println!("borrow: {:?}", ret);
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
                                reverted: res.ret != Return::Return
                                    && res.ret != Return::Stop
                                    && res.ret != ControlLeak,
                                new_state: StagedVMState::new_with_state(
                                    VMStateT::as_any(&mut res.new_state)
                                        .downcast_ref_unchecked::<VS>()
                                        .clone(),
                                ),
                            }
                        }
                    }
                    None => ExecutionResult {
                        output: vec![],
                        reverted: false,
                        new_state: StagedVMState::new_with_state(input.get_state().clone()),
                    },
                }
            }
            EVMInputTy::Liquidate => {
                unreachable!("liquidate should be handled by middleware");
            }
            EVMInputTy::ABI => self.execute_abi(input, state),
        }
    }

    fn fast_static_call(
        &mut self,
        address: H160,
        data: Bytes,
        vm_state: &VS,
        state: &mut S,
    ) -> Vec<u8> {
        let call = Contract::new_with_context_not_cloned::<LatestSpec>(
            data,
            self.host.code.get(&address).expect("no code").clone(),
            &CallContext {
                address,
                caller: Default::default(),
                code_address: address,
                apparent_value: Default::default(),
                scheme: CallScheme::StaticCall,
            },
        );
        unsafe {
            self.host.evmstate = vm_state
                .as_any()
                .downcast_ref_unchecked::<EVMState>()
                .clone();
        }
        let mut interp = Interpreter::new::<LatestSpec>(call, 1e10 as u64);
        let ret = interp.run::<FuzzHost<VS, I, S>, LatestSpec, S>(&mut self.host, state);
        if ret == Return::Revert {
            return vec![];
        }

        interp.return_value().to_vec()
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
        unsafe { STATE_CHANGE }
    }
}

mod tests {
    use crate::evm::host::{FuzzHost, JMP_MAP};
    use crate::evm::input::{EVMInput, EVMInputTy};
    use crate::evm::mutator::AccessPattern;
    use crate::evm::types::EVMFuzzState;
    use crate::evm::vm::{EVMExecutor, EVMState};
    use crate::generic_vm::vm_executor::{GenericVM, MAP_SIZE};
    use crate::rand_utils::generate_random_address;
    use crate::state::FuzzState;
    use crate::state_input::StagedVMState;
    use bytes::Bytes;
    use libafl::prelude::{tuple_list, StdScheduler};
    use primitive_types::U256;
    use revm::Bytecode;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    #[test]
    fn test_fuzz_executor() {
        let mut evm_executor: EVMExecutor<EVMInput, EVMFuzzState, EVMState> = EVMExecutor::new(
            FuzzHost::new(Arc::new(StdScheduler::new())),
            generate_random_address(),
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
                generate_random_address(),
                &mut FuzzState::new(),
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
            txn_value: Some(U256::zero()),
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

        let mut state = FuzzState::new();

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
            caller: generate_random_address(),
            contract: deployment_loc,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(U256::zero()),
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
