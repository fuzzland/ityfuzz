use std::{any, collections::HashMap, fmt::Debug};

use bytes::Bytes;
use itertools::Itertools;
use libafl::schedulers::Scheduler;
use revm_interpreter::Interpreter;
use serde::{Deserialize, Serialize};
use serde_json;
use tracing::debug;

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    srcmap::{RawSourceMapInfo, SOURCE_MAP_PROVIDER},
    types::{as_u64, convert_u256_to_h160, EVMAddress, EVMFuzzState, EVMU256},
    utils,
};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum CallType {
    #[default]
    Call,
    CallCode,
    DelegateCall,
    StaticCall,
    FirstLevelCall,
    Event,
}

#[derive(Clone, Debug, Serialize, Default, Deserialize)]
pub struct SingleCall {
    pub call_type: CallType,
    pub caller: String,
    pub contract: String,
    pub input: String,
    pub value: String,
    pub source: Option<RawSourceMapInfo>,
    pub results: String,
}

#[derive(Clone, Debug, Serialize, Default, Deserialize)]
pub struct CallPrinterResult {
    pub data: Vec<(usize, SingleCall)>,
}

#[derive(Clone, Debug)]
pub struct CallPrinter {
    pub address_to_name: HashMap<EVMAddress, String>,
    pub current_layer: usize,
    pub results: CallPrinterResult,
    pub offsets: usize,

    entry: bool,
}

impl CallPrinter {
    pub fn new(address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self {
            address_to_name,
            current_layer: 0,
            results: Default::default(),
            entry: true,
            offsets: 0,
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
        self.results
            .data
            .iter()
            .map(|(layer, call)| {
                let padding = (0..*layer).map(|_| "  ").join("");
                format!(
                    "{}[{:?}][{} -> {}] ({}) > ({})",
                    padding, call.call_type, call.caller, call.contract, call.input, call.results
                )
            })
            .join("\n")
    }

    pub fn save_trace(&self, path: &str) {
        utils::try_write_file(path, &self.get_trace(), false).unwrap();

        utils::try_write_file(
            &format!("{}.json", path),
            &serde_json::to_string(&self.results).unwrap(),
            false,
        )
        .unwrap();
    }

    fn translate_address(&self, a: EVMAddress) -> String {
        self.address_to_name.get(&a).unwrap_or(&format!("{:?}", a)).to_string()
    }
}

impl<SC> Middleware<SC> for CallPrinter
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, _host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) {
        if self.entry {
            self.entry = false;
            let code_address = interp.contract.address;
            self.results.data.push((
                self.current_layer,
                SingleCall {
                    call_type: CallType::FirstLevelCall,
                    caller: self.translate_address(interp.contract.caller),
                    contract: self.translate_address(interp.contract.address),
                    input: hex::encode(interp.contract.input.clone()),
                    value: format!("{}", interp.contract.value),
                    source: SOURCE_MAP_PROVIDER
                        .lock()
                        .unwrap()
                        .get_raw_source_map_info(&code_address, interp.program_counter()),
                    results: "".to_string(),
                },
            ));
        }

        // events
        if *interp.instruction_pointer >= 0xa0 && *interp.instruction_pointer <= 0xa4 {
            let offset = as_u64(interp.stack.peek(0).unwrap()) as usize;
            let len = as_u64(interp.stack.peek(1).unwrap()) as usize;
            let arg = if interp.memory.len() < offset {
                debug!(
                    "encountered unknown event at PC {} of contract {:?}",
                    interp.program_counter(),
                    interp.contract.address
                );
                "unknown".to_string()
            } else if interp.memory.len() < offset + len {
                hex::encode(&interp.memory.data[offset..])
            } else {
                hex::encode(interp.memory.get_slice(offset, len))
            };
            let topic_amount = *interp.instruction_pointer - 0xa0;
            let mut topics = Vec::new();
            for i in 0..topic_amount {
                let topic = interp.stack.peek(i as usize + 2).unwrap();
                let topic = format!("{:x}", topic);
                topics.push(topic);
            }

            let arg = format!("{}({})", arg, topics.join(","));

            self.results.data.push((
                self.current_layer,
                SingleCall {
                    call_type: CallType::Event,
                    caller: self.translate_address(interp.contract.caller),
                    contract: self.translate_address(interp.contract.address),
                    input: arg.clone(),
                    value: "".to_string(),
                    source: None,
                    results: "".to_string(),
                },
            ));
        }
        // external calls
        else if *interp.instruction_pointer <= 0xfa && *interp.instruction_pointer >= 0xf1 {
            let (arg_offset, arg_len) = match unsafe { *interp.instruction_pointer } {
                0xf1 | 0xf2 => (interp.stack.peek(3).unwrap(), interp.stack.peek(4).unwrap()),
                0xf4 | 0xfa => (interp.stack.peek(2).unwrap(), interp.stack.peek(3).unwrap()),
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
                hex::encode(&interp.memory.data[arg_len..])
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

            self.offsets = 0;
            self.results.data.push((
                self.current_layer,
                SingleCall {
                    call_type,
                    caller: self.translate_address(caller),
                    contract: self.translate_address(target),
                    input: arg,
                    value: format!("{}", value),
                    source: SOURCE_MAP_PROVIDER
                        .lock()
                        .unwrap()
                        .get_raw_source_map_info(&caller_code_address, interp.program_counter()),
                    results: "".to_string(),
                },
            ));
        }
    }

    unsafe fn on_return(
        &mut self,
        _interp: &mut Interpreter,
        _host: &mut FuzzHost<SC>,
        _state: &mut EVMFuzzState,
        by: &Bytes,
    ) {
        self.offsets += 1;
        let l = self.results.data.len();
        self.results.data[l - self.offsets].1.results = hex::encode(by);

        self.current_layer -= 1;
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::CallPrinter
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }
}
