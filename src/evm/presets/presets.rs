use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT};
use crate::evm::vm::EVMExecutor;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::HasCaller;
use libafl::prelude::State;
use libafl::schedulers::Scheduler;
use libafl::state::HasCorpus;
use std::fmt::Debug;
use crate::evm::types::EVMAddress;

pub trait Preset<I, S, VS, SC>
where
    S: State + HasCorpus + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
    SC: Scheduler<State = S> + Clone,
{
    fn presets(
        &self,
        function_sig: [u8; 4],
        input: &EVMInput,
        evm_executor: &EVMExecutor<I, S, VS, ConciseEVMInput, SC>,
    ) -> Vec<EVMInput>;
}
