use std::fmt::Formatter;
use std::marker::PhantomData;

use libafl::executors::{Executor, ExitKind};
use libafl::inputs::Input;
use libafl::prelude::{HasObservers, ObserversTuple};
use libafl::{Error};
use std::fmt::Debug;

use crate::input::VMInputT;
use crate::EVMExecutor;

#[derive(Clone)]
pub struct FuzzExecutor<I, S, OT>
where
    I: VMInputT,
    OT: ObserversTuple<I, S>,
{
    pub evm_executor: EVMExecutor,
    observers: OT,
    phantom: PhantomData<(I, S)>,
}

impl<I, S, OT> Debug for FuzzExecutor<I, S, OT>
where
    I: VMInputT,
    OT: ObserversTuple<I, S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuzzExecutor")
            .field("evm_executor", &self.evm_executor)
            .field("observers", &self.observers)
            .finish()
    }
}

impl<I, S, OT> FuzzExecutor<I, S, OT>
where
    I: VMInputT,
    OT: ObserversTuple<I, S>,
{
    pub fn new(evm_executor: EVMExecutor, observers: OT) -> Self {
        Self {
            evm_executor,
            observers,
            phantom: PhantomData,
        }
    }
}

impl<EM, I, S, Z, OT> Executor<EM, I, S, Z> for FuzzExecutor<I, S, OT>
where
    I: VMInputT + Input,
    OT: ObserversTuple<I, S>,
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

// implement HasObservers trait for ItyFuzzer
impl<I, OT, S> HasObservers<I, OT, S> for FuzzExecutor<I, S, OT>
where
    I: VMInputT,
    OT: ObserversTuple<I, S>,
{
    fn observers(&self) -> &OT {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}
