use libafl::executors::{Executor, ExitKind};
use libafl::inputs::Input;
use libafl::Error;

use crate::input::VMInputT;
use crate::EVMExecutor;

#[derive(Debug, Clone)]
pub struct FuzzExecutor {
    pub evm_executor: EVMExecutor,
}

impl<EM, I, S, Z> Executor<EM, I, S, Z> for FuzzExecutor
where
    I: VMInputT + Input,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        self.evm_executor.execute(
            input.get_contract(),
            input.get_caller(),
            input.get_state(),
            input.to_bytes().clone(),
        );
        // todo: run oracle here
        Ok(ExitKind::Ok)
    }
}
