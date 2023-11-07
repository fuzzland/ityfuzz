use std::fmt::Debug;

use libafl::{
    inputs::Input,
    prelude::{HasCorpus, HasMetadata, State},
    schedulers::Scheduler,
};
use revm_interpreter::Interpreter;
use serde::Serialize;
use tracing::debug;

use crate::{
    evm::{
        host::FuzzHost,
        input::{ConciseEVMInput, EVMInputT},
        middlewares::middleware::{Middleware, MiddlewareType},
        types::EVMAddress,
    },
    generic_vm::vm_state::VMStateT,
    input::VMInputT,
    state::{HasCaller, HasCurrentInputIdx, HasItyState},
};

#[derive(Serialize, Debug, Clone, Default)]
pub struct IntegerOverflowMiddleware;

impl IntegerOverflowMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl<I, VS, S, SC> Middleware<VS, I, S, SC> for IntegerOverflowMiddleware
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    VS: VMStateT,
    S: State
        + HasCaller<EVMAddress>
        + HasCorpus
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCurrentInputIdx
        + Debug
        + Clone,
    SC: Scheduler<State = S> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<VS, I, S, SC>, _state: &mut S) {
        macro_rules! l_r {
            () => {
                (interp.stack.peek(0).unwrap(), interp.stack.peek(1).unwrap())
            };
        }
        let addr = interp.contract.code_address;
        let pc = interp.program_counter();
        match *interp.instruction_pointer {
            0x01 => {
                // +ADD
                let (l, r) = l_r!();
                if l.overflowing_add(r).1 {
                    debug!("contract {:?} overflow on pc[{pc:x}]: {} + {}", addr, l, r);
                    host.current_integer_overflow.insert((addr, pc, "+"));
                }
            }
            0x02 => {
                // *MUL
                let (l, r) = l_r!();
                if l.overflowing_mul(r).1 {
                    debug!("contract {:?} overflow on pc[{pc:x}]: {} * {}", addr, l, r);
                    host.current_integer_overflow.insert((addr, pc, "*"));
                }
            }
            0x03 => {
                // -SUB
                let (l, r) = l_r!();
                if l.overflowing_sub(r).1 {
                    debug!("contract {:?} overflow on pc[{pc:x}]: {} - {}", addr, l, r);
                    host.current_integer_overflow.insert((addr, pc, "-"));
                }
            }
            0x04 | 0x05 => {
                // DIV/ SDIV
                let (l, r) = l_r!();
                if l < r {
                    debug!("contract {:?} loss of accuracy on pc[{pc:x}]: {} / {}", addr, l, r);
                    host.current_integer_overflow.insert((addr, pc, "/"));
                }
            }
            0x0a => {
                // ** EXP
                let (l, r) = l_r!();
                if l.overflowing_pow(r).1 {
                    debug!("contract {:?} overflow on pc[{pc:x}]: {} ** {}", addr, l, r);
                    host.current_integer_overflow.insert((addr, pc, "**"));
                }
            }
            _ => {}
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::IntegerOverflow
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn test_merge() {}
}
