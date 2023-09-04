use std::collections::{HashMap, HashSet};
use std::fmt::{Debug};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::ops::AddAssign;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use bytes::Bytes;
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
use crate::evm::srcmap::parser::{decode_instructions, pretty_print_source_map, SourceMapAvailability, SourceMapLocation, SourceMapWithCode};
use crate::evm::srcmap::parser::SourceMapAvailability::Available;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasItyState};
use crate::evm::types::{as_u64, convert_u256_to_h160, EVMAddress, EVMU256, is_zero, ProjectSourceMapTy};
use crate::evm::vm::IN_DEPLOY;
use serde_json;
use crate::evm::blaz::builder::ArtifactInfoMetadata;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CallType {
    Call,
    CallCode,
    DelegateCall,
    StaticCall,
    FirstLevelCall
}

impl Default for CallType {
    fn default() -> Self {
        CallType::Call
    }
}

#[derive(Clone, Debug, Serialize, Default, Deserialize)]
pub struct SingleCall {
    pub call_type: CallType,
    pub caller: String,
    pub contract: String,
    pub input: String,
    pub value: String,
    pub source: Option<SourceMapLocation>,
    pub results: String
}

#[derive(Clone, Debug, Serialize, Default, Deserialize)]
pub struct CallPrinterResult {
    pub data: Vec<(usize, SingleCall)>
}

#[derive(Clone, Debug)]
pub struct CallPrinter {
    pub address_to_name: HashMap<EVMAddress, String>,
    pub sourcemaps: ProjectSourceMapTy,
    pub current_layer: usize,
    pub results: CallPrinterResult,
    pub offsets: usize,

    entry: bool
}

impl CallPrinter {
    pub fn new(
        address_to_name: HashMap<EVMAddress, String>,
        sourcemaps: ProjectSourceMapTy,
    ) -> Self {
        Self {
            address_to_name,
            sourcemaps,
            current_layer: 0,
            results: Default::default(),
            entry: true,
            offsets: 0
        }
    }

    pub fn cleanup(&mut self) {
        self.current_layer = 0;
        self.results = Default::default();
        self.entry = true;
    }

    pub fn mark_new_tx(&mut self, layer: usize) {
        self.current_layer = layer;
        self.entry = true;
    }

    /// Wont collect the starting tx
    pub fn mark_step_tx(&mut self) {
        self.entry = false;
    }

    pub fn get_trace(&self) -> String {
        self.results.data.iter().map(|(layer, call)| {
            let padding = (0..*layer).map(|_| "  ").join("");
            format!("{}[{} -> {}] ({}) > ({})", padding, call.caller, call.contract, call.input, call.results)
        }).join("\n")
    }

    pub fn save_trace(&self, path: &str) {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(false)
            .open(path)
            .unwrap();
        file.write_all(self.get_trace().as_bytes()).unwrap();

        let mut json_file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(false)
            .open(format!("{}.json", path))
            .unwrap();
        let json = serde_json::to_string(&self.results).unwrap();
        json_file.write_all(json.as_bytes()).unwrap();
    }

    fn translate_address(&self, a: EVMAddress) -> String {
        self.address_to_name.get(&a).unwrap_or(&format!("{:?}", a)).to_string()
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
        if self.entry {
            self.entry = false;
            let code_address = interp.contract.address;
            let caller_code = host.code.get(&interp.contract.code_address).map(
                |code| {
                    Vec::from(code.bytecode())
                },
            ).unwrap_or(vec![]);
            self.results.data.push((self.current_layer, SingleCall {
                call_type: CallType::FirstLevelCall,
                caller: self.translate_address(interp.contract.caller),
                contract: self.translate_address(interp.contract.address),
                input: hex::encode(interp.contract.input.clone()),
                value: format!("{}", interp.contract.value),
                source: if let Some(Some(source)) = self.sourcemaps.get(&code_address)
                    && let Some(source) = source.get(&interp.program_counter()) {
                    Some(source.clone())
                } else if let Some(artifact) = state.metadata_mut().get_mut::<ArtifactInfoMetadata>() && let Some(build_result) = artifact.get_mut(&code_address) {
                    if let Some(srcmap) = build_result.get_sourcemap(caller_code).get(&interp.program_counter()) {
                        Some(srcmap.clone())
                    } else {
                        None
                    }
                } else {
                    None
                },
                results: "".to_string(),
            }));
        }

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

        let call_type = match unsafe { *interp.instruction_pointer } {
            0xf1 => CallType::Call,
            0xf2 => CallType::CallCode,
            0xf4 => CallType::DelegateCall,
            0xfa => CallType::StaticCall,
            _ => {
                return;
            }
        };

        self.current_layer += 1;

        let arg_offset = as_u64(arg_offset) as usize;
        let arg_len = as_u64(arg_len) as usize;


        let arg = if interp.memory.len() < arg_offset + arg_len {
            hex::encode(interp.memory.data[arg_len..].to_vec())
        } else {
            hex::encode(interp.memory.get_slice(arg_offset, arg_len))
        };


        let caller = interp.contract.address;
        let address = match *interp.instruction_pointer {
            0xf1 | 0xf2 | 0xf4 | 0xfa => interp.stack.peek(1).unwrap(),
            0x3b | 0x3c => interp.stack.peek(0).unwrap(),
            _ => {
                unreachable!()
            }
        };

        let value = match *interp.instruction_pointer {
            0xf1 | 0xf2 => interp.stack.peek(2).unwrap(),
            _ => EVMU256::ZERO,

        };

        let target = convert_u256_to_h160(address);

        let caller_code_address = interp.contract.code_address;
        let caller_code = host.code.get(&interp.contract.code_address).map(
            |code| {
                Vec::from(code.bytecode())
            },
        ).unwrap_or(vec![]);

        self.offsets = 0;
        self.results.data.push((self.current_layer, SingleCall {
            call_type,
            caller: self.translate_address(caller),
            contract: self.translate_address(target),
            input: arg,
            value: format!("{}", value),
            source: if let Some(Some(source)) = self.sourcemaps.get(&caller_code_address)
                && let Some(source) = source.get(&interp.program_counter()) {
                Some(source.clone())
            } else if let Some(artifact) = state.metadata_mut().get_mut::<ArtifactInfoMetadata>() && let Some(build_result) = artifact.get_mut(&caller_code_address) {
                if let Some(srcmap) = build_result.get_sourcemap(caller_code).get(&interp.program_counter()) {
                    Some(srcmap.clone())
                } else {
                    None
                }
            } else {
                None
            },
            results: "".to_string(),
        }));
    }

    unsafe fn on_return(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S>,
        state: &mut S,
        by: &Bytes
    ) {
        self.offsets += 1;
        let l = self.results.data.len();
        self.results.data[l - self.offsets]
            .1.results = hex::encode(by);

        self.current_layer -= 1;
    }

    unsafe fn on_insert(&mut self, bytecode: &mut Bytecode, address: EVMAddress, host: &mut FuzzHost<VS, I, S>, state: &mut S) {

    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::CallPrinter
    }
}

