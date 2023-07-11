
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT, EVMInputTy};
use crate::evm::middlewares::middleware::CallMiddlewareReturn::ReturnSuccess;
use crate::evm::middlewares::middleware::{Middleware, MiddlewareOp, MiddlewareType, add_corpus};
use crate::evm::host::FuzzHost;
use crate::generic_vm::vm_state::VMStateT;
use libafl::inputs::Input;
use libafl::prelude::{HasCorpus, State, HasMetadata};
use crate::state::{HasCaller, HasItyState};
use crate::evm::types::{convert_u256_to_h160, EVMAddress, EVMU256};
use std::fmt::Debug;
use crate::input::VMInputT;
use revm_interpreter::Interpreter;
use revm_primitives::Bytecode;
use crate::evm::abi::get_abi_type_boxed;
use crate::evm::mutator::AccessPattern;
use crate::state_input::StagedVMState;

use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use std::cell::RefCell;

pub struct Selfdestruct<VS, I, S>
    where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    _phantom: std::marker::PhantomData<(VS, I, S)>,
}

impl<VS, I, S> Selfdestruct<VS, I, S>
    where
        S: State + HasCaller<EVMAddress> + HasCorpus<I> + Debug + Clone + 'static,
        I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
        VS: VMStateT,
{
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<VS, I, S> Debug for Selfdestruct<VS, I, S>
    where
        S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
        I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
        VS: VMStateT,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Selfdestruct")
            .finish()
    }
}


impl<VS, I, S> Middleware<VS, I, S> for Selfdestruct<VS, I, S>
    where
        S: State
        + Debug
        + HasCaller<EVMAddress>
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + Clone
        + 'static,
        I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
        VS: VMStateT,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<VS, I, S>, state: &mut S)
        where
            S: HasCaller<EVMAddress>,
    {


        let offset_of_arg_offset = match *interp.instruction_pointer {
            // detect whether it mutates token balance
            0xff => {
                host.selfdestruct_hit = true;

            }
            _ => {
                return;
            }
        };
    }

    unsafe fn on_insert(&mut self, bytecode: &mut Bytecode, address: EVMAddress, host: &mut FuzzHost<VS, I, S>, state: &mut S) {

    }

    fn get_type(&self) -> MiddlewareType {
        return MiddlewareType::Selfdestruct;
    }
}