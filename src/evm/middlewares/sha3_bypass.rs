use std::collections::{HashMap, HashSet};
use std::fmt::{Debug};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use itertools::Itertools;
use libafl::inputs::Input;
use libafl::prelude::{HasCorpus, HasMetadata, State};
use revm_interpreter::Interpreter;
use revm_primitives::Bytecode;
use crate::evm::host::FuzzHost;
use crate::evm::input::EVMInputT;
use crate::evm::middlewares::middleware::{Middleware, MiddlewareType};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasItyState};
use crate::evm::types::{EVMAddress, EVMU256};


#[derive(Clone, Debug)]
pub struct Sha3Bypass {
    pub dirty_memory: Vec<bool>,
    pub dirty_storage: HashMap<EVMU256, bool>,
    pub dirty_stack: Vec<bool>,

    pub tainted_jumpi: HashSet<usize>
}


impl Sha3Bypass {
    
}


impl<I, VS, S> Middleware<VS, I, S> for Sha3Bypass
    where
        I: Input + VMInputT<VS, EVMAddress, EVMAddress> + EVMInputT + 'static,
        VS: VMStateT,
        S: State
        + HasCaller<EVMAddress>
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS>
        + HasMetadata
        + HasCurrentInputIdx
        + Debug
        + Clone,
{
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S>,
        state: &mut S,
    ) {
        macro_rules! pop_push {
            ($pop_cnt: expr,$push_cnt: expr) => {
                {
                    let mut res = false;
                    for _ in 0..$pop_cnt {
                        res |= self.dirty_stack.pop().expect("stack is empty");
                    }
                    for _ in 0..$push_cnt {
                        self.dirty_stack.push(res);
                    }
                }
            };
        }

        macro_rules! stack_pop_n {
            ($pop_cnt: expr) => {
                for _ in 0..$pop_cnt {
                    self.dirty_stack.pop().expect("stack is empty");
                }
            }

        }

        macro_rules! push_false {
            () => {
                self.dirty_stack.push(false);
            };
        }

        match *interp.instruction_pointer {
            0x01..=0x7 => { pop_push!(2, 1) },
            0x08..=0x0a => { pop_push!(3, 1) },
            0x0b | 0x10..=0x14 => { pop_push!(2, 1); }
            0x16..=0x18 => { pop_push!(2, 1); }
            0x1a..=0x1d => { pop_push!(2, 1); }
            0x20 => {
                // sha3
                stack_pop_n!(2);
                self.dirty_stack.push(true);
            }
            0x30 => push_false!(),
            // ORIGIN
            0x32 =>  push_false!(),
            // CALLER
            0x33 =>  push_false!(),
            // CALLVALUE
            0x34 =>  push_false!(),
            // CALLDATASIZE
            0x36 => push_false!(),
            // CALLDATACOPY
            0x37 => {
                stack_pop_n!(3);
                todo!("write to symbolic memory")
            }
            // CODESIZE
            0x38 => push_false!(),
            // CODECOPY
            0x39 => {
                stack_pop_n!(3);
                todo!("write to symbolic memory")
            }
            // GASPRICE
            0x3a => push_false!(),
            // EXTCODECOPY
            0x3c => {
                stack_pop_n!(3);
                todo!("write to symbolic memory")
            }
            // RETURNDATASIZE
            0x3d => push_false!(),
            // RETURNDATACOPY
            0x3e => {
                stack_pop_n!(3);
                todo!("write to symbolic memory")
            }
            // COINBASE
            0x41..=0x48 => push_false!(),
            // POP
            0x50 => {
                self.dirty_stack.pop();
            }
            // MLOAD
            0x51 => {
                todo!("read from symbolic memory")
            }
            // MSTORE
            0x52 => {
                todo!("write to symbolic memory")
            }
            // MSTORE8
            0x53 => {
                todo!("write to symbolic memory")
            }
            // SLOAD
            0x54 => {
                todo!("read from symbolic storage")
            }
            // SSTORE
            0x55 => {
                todo!("write to symbolic storage")
            }
            // JUMP
            0x56 => {
                self.dirty_stack.pop();
            }
            // JUMPI
            0x57 => {
                self.dirty_stack.pop();
                let v = self.dirty_stack.pop().expect("stack is empty");
                if v {
                    self.tainted_jumpi.insert(interp.program_counter());
                }
            }
            // PC
            0x58 | 0x59 | 0x5a => {
                push_false!();
            }
            // PUSH
            0x5f..=0x7f => {
                push_false!();
            }
            // DUP
            0x80..=0x8f => {
                let _n = (*interp.instruction_pointer) - 0x80 + 1;
                self.dirty_stack.push(self.dirty_stack[self.dirty_stack.len() - _n as usize]);
            }
            // SWAP
            0x90..=0x9f => {
                let _n = (*interp.instruction_pointer) - 0x90 + 1;
                let _l = self.dirty_stack.len();
                let tmp = self.dirty_stack[_l - _n as usize];
                self.dirty_stack[_l - _n as usize] = self.dirty_stack[_l - 1];
                self.dirty_stack[_l - 1] = tmp;
            }
            // LOG
            0xa0..=0xa4 => {
                let _n = (*interp.instruction_pointer) - 0xa0 + 2;
                stack_pop_n!(_n);
            }
            0xf0 => {
                pop_push!(3, 1);
            }
            0xf1 => {
                pop_push!(7, 1);
            }
            0xf2 => {
                pop_push!(7, 1);
            }
            0xf3 => {
                self.dirty_stack.pop();
                self.dirty_stack.pop();
            }
            0xf4 => {
                pop_push!(6, 1);
            }
            0xf5 => {
                pop_push!(4, 1);
            }
            0xfa => {
                pop_push!(6, 1);
            }
            0xfd => {
                pop_push!(2, 0);
            }
            0xff => {
                stack_pop_n!(1);
            }
            _ => {}

        }
    }

    unsafe fn on_insert(&mut self, bytecode: &mut Bytecode, address: EVMAddress, host: &mut FuzzHost<VS, I, S>, state: &mut S) {
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::Sha3Bypass
    }
}


mod tests {
    use super::*;

    #[test]
    fn test_hash() {
    }

}
