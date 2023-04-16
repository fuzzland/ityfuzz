use std::fmt::Debug;
use libafl::prelude::State;
use primitive_types::H160;
use crate::evm::input::{EVMInput, EVMInputT};
use crate::evm::vm::EVMExecutor;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::HasCaller;


pub trait Preset<I, S, VS>
    where
        S: State + HasCaller<H160> + Debug + Clone + 'static,
        I: VMInputT<VS, H160, H160> + EVMInputT,
        VS: VMStateT
{
    fn presets(
        &self,
        function_sig: [u8; 4],
        input: &EVMInput,
        evm_executor: &EVMExecutor<I, S, VS>,
    ) -> Vec<EVMInput>;
}