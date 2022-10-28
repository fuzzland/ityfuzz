use crate::evm::ExecutionResult;
use crate::input::VMInput;
use crate::{EVMExecutor, VMState};
use bytes::Bytes;
use libafl::prelude::{tuple_list, SerdeAnyMap};
use primitive_types::H160;

pub struct OracleCtx<'a, I, S> {
    pub state: &'a mut VMState,
    pub metadata: SerdeAnyMap,
    pub executor: &'a mut EVMExecutor<I, S>,
}

impl<'a, I, S> OracleCtx<'a, I, S> {
    pub fn new(state: &'a mut VMState, executor: &'a mut EVMExecutor<I, S>) -> Self {
        Self {
            state,
            metadata: SerdeAnyMap::new(),
            executor,
        }
    }

    fn call(&mut self, contract_address: H160, address: H160, data: Bytes) -> ExecutionResult {
        self.executor.execute(
            contract_address,
            address,
            &mut self.state,
            data,
            &mut tuple_list!(),
        )
    }
}

trait Oracle<I, S> {
    fn pre_condition(&self, ctx: &OracleCtx<I, S>, stage: u64) -> u64;
    fn oracle(&self, ctx: &OracleCtx<I, S>, stage: u64) -> bool;
}
