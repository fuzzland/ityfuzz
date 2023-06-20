use crate::evm::input::{EVMInput, EVMInputT};
use crate::evm::vm::EVMExecutor;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::HasCaller;
use libafl::prelude::State;
use std::fmt::Debug;
use crate::evm::types::EVMAddress;

pub trait Preset<I, S, VS>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress> + EVMInputT,
    VS: VMStateT,
{
    fn presets(
        &self,
        function_sig: [u8; 4],
        input: &EVMInput,
        evm_executor: &EVMExecutor<I, S, VS>,
    ) -> Vec<EVMInput>;
}
