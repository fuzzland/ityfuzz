use std::cell::RefCell;
use std::fmt::Debug;
use std::ops::Deref;
use std::rc::Rc;
use libafl::events::EventManager;
use libafl::prelude::{Executor, StdScheduler};
use serde::de::DeserializeOwned;
use serde::Serialize;
use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::types::{EVMAddress, EVMFuzzExecutor, EVMFuzzState, EVMQueueExecutor};
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::input::ConciseSerde;
use crate::minimizer::SequentialMinimizer;
use crate::tracer::TxnTrace;

pub struct EVMMinimizer {
    evm_executor_ref: Rc<RefCell<EVMQueueExecutor>>,
}

impl EVMMinimizer {
    pub fn new(evm_executor_ref: Rc<RefCell<EVMQueueExecutor>>) -> Self {
        Self {
            evm_executor_ref,
        }
    }
}

impl<E> SequentialMinimizer<
    EVMFuzzState,
    E, EVMAddress, EVMAddress, ConciseEVMInput,
> for EVMMinimizer
{
    fn minimize(&mut self,
                state: &mut EVMFuzzState,
                _: &mut E,
                input: &TxnTrace<EVMAddress, EVMAddress, ConciseEVMInput>) -> Vec<ConciseEVMInput> {
        let executor = self.evm_executor_ref.deref().borrow_mut();
        todo!("Implement EVMMinimizer::minimize");
        return vec![];
    }
}
