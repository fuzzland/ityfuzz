use std::collections::{HashMap, HashSet};
use std::fmt::{Debug};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::ops::AddAssign;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use itertools::Itertools;
use libafl::inputs::Input;
use libafl::prelude::{HasCorpus, HasMetadata, State};
use revm_interpreter::Interpreter;
use revm_interpreter::opcode::{INVALID, JUMPDEST, JUMPI, REVERT, STOP};
use revm_primitives::Bytecode;
use serde::{Deserialize, Serialize};
use crate::evm::host::FuzzHost;
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT};
use crate::evm::middlewares::middleware::{Middleware, MiddlewareType};
use crate::evm::srcmap::parser::{pretty_print_source_map, SourceMapAvailability, SourceMapLocation, SourceMapWithCode};
use crate::evm::srcmap::parser::SourceMapAvailability::Available;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasItyState};
use crate::evm::types::{as_u64, convert_u256_to_h160, EVMAddress, is_zero, ProjectSourceMapTy};
use crate::evm::vm::IN_DEPLOY;
use serde_json;

#[derive(Clone, Debug, Serialize, Default, Deserialize)]
pub struct CallPrinter {
    pub layer: usize,
    pub data: String
}


impl CallPrinter {
    pub fn new() -> Self {
        Self { layer: 0, data: "".to_string() }
    }

    pub fn register_input(&mut self, input: &EVMInput) {
        self.layer = 0;
        self.data = "".to_string();
        self.data.push_str(
            format!("[{:?}]=>{:?} {}", input.get_caller(), input.get_contract(), hex::encode(input.to_bytes()))
                .as_str()
        )
    }

    pub fn get_trace(&self) -> String {
        self.data.clone()
    }
}


impl<I, VS, S> Middleware<VS, I, S> for CallPrinter
    where
        I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
        VS: VMStateT,
        S: State
        + HasCaller<EVMAddress>
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
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
        let (arg_offset, arg_len) = match unsafe { *interp.instruction_pointer } {
            0xf1 | 0xf2 => {
                (
                    interp.stack.peek(3).unwrap(),
                    interp.stack.peek(4).unwrap(),
                )
            }
            0xf4 | 0xfa => {
                (
                    interp.stack.peek(2).unwrap(),
                    interp.stack.peek(3).unwrap(),
                )
            }
            _ => {
                return;
            }
        };

        self.layer += 1;

        let arg_offset = as_u64(arg_offset) as usize;
        let arg_len = as_u64(arg_len) as usize;

        let arg = interp.memory.get_slice(arg_offset, arg_len);

        let caller = interp.contract.address;
        let address = match *interp.instruction_pointer {
            0xf1 | 0xf2 | 0xf4 | 0xfa => interp.stack.peek(1).unwrap(),
            0x3b | 0x3c => interp.stack.peek(0).unwrap(),
            _ => {
                unreachable!()
            }
        };
        let address_h160 = convert_u256_to_h160(address);
        let padding = " ".repeat(self.layer * 4);
        self.data.push_str(
            format!(
                "\n{}[{:?}]=>{:?} {}",
                padding,
                caller,
                address_h160,
                hex::encode(arg)
            )
                .as_str(),
        );

    }

    unsafe fn on_return(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S>,
        state: &mut S,
    ) {
        self.layer -= 1;
    }

    unsafe fn on_insert(&mut self, bytecode: &mut Bytecode, address: EVMAddress, host: &mut FuzzHost<VS, I, S>, state: &mut S) {

    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::CallPrinter
    }
}

