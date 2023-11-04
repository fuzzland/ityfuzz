use crate::evm::host::FuzzHost;
use crate::evm::input::{ConciseEVMInput, EVMInputT};
use crate::evm::middlewares::middleware::{Middleware, MiddlewareType};
use crate::evm::types::{as_u64, EVMAddress, EVMU256};
use crate::evm::vm::EVMState;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasItyState};
use bytes::Bytes;
use libafl::inputs::Input;
use libafl::prelude::{HasCorpus, HasMetadata, State};
use libafl::schedulers::Scheduler;
use revm_interpreter::Interpreter;
use revm_primitives::uint;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use tracing::debug;

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
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S, SC>,
        _state: &mut S,
    ) {
        macro_rules! l_r {
            () => {
                (interp.stack.peek(0).unwrap(), interp.stack.peek(1).unwrap())
            };
        }
        let addr = interp.contract.address;
        let pc = interp.program_counter();
        match *interp.instruction_pointer {
            0x01 => {
                // +ADD
                let (l, r) = l_r!();
                if l.overflowing_add(r).1 {
                    debug!("contract {:?} overflow on pc[{pc:x}]: {} + {}", addr, l, r);
                    host.current_integer_overflow.push((addr, pc));
                }
            }
            0x02 => {
                // *MUL
                let (l, r) = l_r!();
                if l.overflowing_mul(r).1 {
                    debug!("contract {:?} overflow on pc[{pc:x}]: {} * {}", addr, l, r);
                    host.current_integer_overflow.push((addr, pc));
                }
            }
            0x03 => {
                // -SUB
                let (l, r) = l_r!();
                if l.overflowing_sub(r).1 {
                    debug!("contract {:?} overflow on pc[{pc:x}]: {} - {}", addr, l, r);
                    host.current_integer_overflow.push((addr, pc));
                }
            }
            0x0a => {
                // ** EXP
                let (l, r) = l_r!();
                if l.overflowing_pow(r).1 {
                    debug!("contract {:?} overflow on pc[{pc:x}]: {} ** {}", addr, l, r);
                    host.current_integer_overflow.push((addr, pc));
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
    use super::*;
    #[test]
    fn test_merge() {}
}
