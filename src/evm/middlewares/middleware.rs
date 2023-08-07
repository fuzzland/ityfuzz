use crate::evm::host::{FuzzHost, JMP_MAP, READ_MAP, WRITE_MAP, CMP_MAP, STATE_CHANGE, 
    WRITTEN, RET_SIZE, RET_OFFSET};
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT};
use crate::generic_vm::vm_executor::MAP_SIZE;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasItyState};

use bytes::Bytes;
use libafl::corpus::{Corpus, Testcase};
use libafl::inputs::Input;
use libafl::schedulers::Scheduler;
use libafl::state::{HasCorpus, HasMetadata, State};
use primitive_types::{H160, U256, U512};
use revm::{Bytecode, Interpreter, Host};
use serde::{Deserialize, Serialize};

use std::clone::Clone;
use std::fmt::Debug;

use std::time::Duration;
use revm_interpreter::Interpreter;
use revm_primitives::Bytecode;
use crate::evm::types::{EVMAddress, EVMU256};

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Copy)]
pub enum MiddlewareType {
    OnChain,
    Concolic,
    Flashloan,
    Selfdestruct,
    InstructionCoverage,
    BranchCoverage,
    Sha3Bypass,
    Sha3TaintAnalysis
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Copy)]
pub enum ExecutionStage {
    Call,
    Create,
    Log,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallMiddlewareReturn {
    Continue,
    ReturnRevert,
    ReturnSuccess(Bytes),
}

#[derive(Clone, Debug)]
pub enum MiddlewareOp {
    UpdateSlot(MiddlewareType, EVMAddress, EVMU256, EVMU256),
    UpdateCode(MiddlewareType, EVMAddress, Bytecode),
    AddCorpus(MiddlewareType, String, EVMAddress),
    AddCaller(MiddlewareType, EVMAddress),
    AddAddress(MiddlewareType, EVMAddress),
    AddBlacklist(MiddlewareType, EVMAddress),
    Owed(MiddlewareType, U512),
    Earned(MiddlewareType, U512),
    MakeSubsequentCallSuccess(Bytes),
}

pub fn add_corpus<VS, I, S>(host: &FuzzHost<VS, I, S>, state: &mut S, input: &EVMInput)
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCaller<EVMAddress>
        + Clone
        + Debug
        + 'static,
    VS: VMStateT + Default,
{
    let mut tc = Testcase::new(input.as_any().downcast_ref::<I>().unwrap().clone()) as Testcase<I>;
    tc.set_exec_time(Duration::from_secs(0));
    let idx = state.corpus_mut().add(tc).expect("failed to add");
    host.scheduler
        .on_add(state, idx)
        .expect("failed to call scheduler on_add");
}

pub trait Middleware<VS, I, S>: Debug
where
    S: State + HasCaller<EVMAddress> + Clone + Debug,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    // called on every instruction
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S>,
        state: &mut S,
    ) {
        macro_rules! fast_peek {
            ($idx:expr) => {
                interp.stack.data()[interp.stack.len() - 1 - $idx]
            };
        }
        unsafe {
            match *interp.instruction_pointer {
                0x57 => { // JUMPI
                    let br = fast_peek!(1);
                    let jump_dest = if br.is_zero() {
                        1
                    } else {
                        fast_peek!(0).as_u64()
                    };
                    let idx = (interp.program_counter() * (jump_dest as usize)) % MAP_SIZE;
                    if JMP_MAP[idx] == 0 {
                        *host.coverage_changed = true;
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

                #[cfg(any(feature = "dataflow", feature = "cmp", feature = "reentrancy"))]
                0x55 => { // SSTORE
                    #[cfg(feature = "dataflow")]
                    let value = fast_peek!(1);
                    {
                        let mut key = fast_peek!(0);
                        let v = u256_to_u8!(value) + 1;
                        WRITE_MAP[process_rw_key!(key)] = v;
                    }
                    let res = host.sload(interp.contract.address, fast_peek!(0));
                    let value_changed = res.expect("sload failed").0 != value;

                    let idx = interp.program_counter() % MAP_SIZE;
                    JMP_MAP[idx] = if value_changed { 1 } else { 0 };

                    STATE_CHANGE |= value_changed;

                    WRITTEN = true;
                }

                #[cfg(feature = "dataflow")]
                0x54 => { // SLOAD
                    let mut key = fast_peek!(0);
                    READ_MAP[process_rw_key!(key)] = true;
                }

                #[cfg(feature = "cmp")]
                0x10 | 0x12 => { // LT | SLT
                    let v1 = fast_peek!(0);
                    let v2 = fast_peek!(1);
                    let abs_diff = if v1 >= v2 {
                        if v1 - v2 != U256::zero() {
                            v1 - v2
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
                0x11 | 0x13 => { // GT | SGT
                    let v1 = fast_peek!(0);
                    let v2 = fast_peek!(1);
                    let abs_diff = if v1 <= v2 {
                        if v2 - v1 != U256::zero() {
                            v2 - v1
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
                0x14 => { // EQ
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

                0xf1 | 0xf2 | 0xf4 | 0xfa => { // CALL | CALLCODE | DELEGATECALL | STATICCALL
                    let offset_of_ret_size: usize = match *interp.instruction_pointer {
                        0xf1 | 0xf2 => 6,
                        0xf4 | 0xfa => 5,
                        _ => unreachable!(),
                    };
                    unsafe {
                        RET_OFFSET = fast_peek!(offset_of_ret_size - 1).as_usize();
                        RET_SIZE = fast_peek!(offset_of_ret_size).as_usize();
                    }
                    *host._pc = interp.program_counter();
                }

                _ => {}
            }
        }
    }

    unsafe fn on_return(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S>,
        state: &mut S,
    );

    unsafe fn on_insert(&mut self,
                        bytecode: &mut Bytecode,
                        address: EVMAddress,
                        host: &mut FuzzHost<VS, I, S>,
                        state: &mut S);
    fn get_type(&self) -> MiddlewareType;
}
