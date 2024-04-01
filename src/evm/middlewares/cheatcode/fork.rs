use foundry_cheatcodes::Vm;
use libafl::schedulers::Scheduler;

use super::Cheatcode;
use crate::evm::types::EVMFuzzState;

/// Cheat VmCalls
impl<SC> Cheatcode<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    #[inline]
    pub fn todo(&self, args: Vm::assertTrue_0Call) -> Option<Vec<u8>> {
        todo!()
    }
}
