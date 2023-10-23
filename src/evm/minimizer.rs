use crate::evm::host::CALL_UNTIL;
use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::types::{EVMAddress, EVMFuzzExecutor, EVMFuzzState, EVMQueueExecutor};
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::feedback::OracleFeedback;
use crate::generic_vm::vm_executor::{ExecutionResult, GenericVM};
use crate::input::ConciseSerde;
use crate::minimizer::SequentialMinimizer;
use crate::state::{FuzzState, HasExecutionResult, HasInfantStateState};
use crate::tracer::TxnTrace;
use bytes::Bytes;
use itertools::Itertools;
use libafl::events::EventManager;
use libafl::observers;
use libafl::prelude::{Corpus, Executor, Feedback, ObserversTuple, StdScheduler, ExitKind, SimpleEventManager, SimpleMonitor};
use libafl::state::HasCorpus;
use revm_primitives::Bytecode;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::cell::RefCell;
use std::fmt::Debug;
use std::ops::Deref;
use std::rc::Rc;

use super::types::EVMStagedVMState;

pub struct EVMMinimizer {
    evm_executor_ref: Rc<RefCell<EVMQueueExecutor>>,
}

impl EVMMinimizer {
    pub fn new(
        evm_executor_ref: Rc<RefCell<EVMQueueExecutor>>,
    ) -> Self {
        Self {
            evm_executor_ref,
        }
    }

    fn get_call_seq(vm_state: &EVMStagedVMState, state: &mut EVMFuzzState) -> Vec<(EVMInput, u32)> {
        if let Some(from_idx) = vm_state.trace.from_idx {
            let corpus_item = state.get_infant_state_state().corpus().get(from_idx.into());
            // This happens when full_trace feature is not enabled, the corpus item may be discarded
            if corpus_item.is_err() {
                return vec![];
            }
            let testcase = corpus_item.unwrap().clone().into_inner();
            let testcase_input = testcase.input();
            if testcase_input.is_none() {
                return vec![];
            }
            let prev_state = testcase_input.clone().unwrap();
            let prev = Self::get_call_seq(testcase_input.as_ref().unwrap(), state);

            return vec![
                prev,
                vm_state
                    .trace
                    .transactions
                    .iter()
                    .enumerate()
                    .map(|(idx, ci)| {
                        if idx == 0 {
                            ci.to_input(prev_state.clone())
                        } else {
                            ci.to_input(EVMStagedVMState::new_uninitialized())
                        }
                    })
                    .collect_vec(),
            ]
            .concat();
        }
        vec![]
    }
}


type EVMOracleFeedback<'a> = OracleFeedback<
    'a,
    EVMState,
    revm_primitives::B160,
    Bytecode,
    Bytes,
    revm_primitives::B160,
    revm_primitives::ruint::Uint<256, 4>,
    Vec<u8>,
    EVMInput,
    FuzzState<
        EVMInput,
        EVMState,
        revm_primitives::B160,
        revm_primitives::B160,
        Vec<u8>,
        ConciseEVMInput,
    >,
    ConciseEVMInput,
>;

impl<E: libafl::executors::HasObservers>
    SequentialMinimizer<EVMFuzzState, E, EVMAddress, EVMAddress, ConciseEVMInput, EVMOracleFeedback<'_>>
    for EVMMinimizer
{
    fn minimize(
        &mut self,
        state: &mut EVMFuzzState,
        exec: &mut E,
        input: &TxnTrace<EVMAddress, EVMAddress, ConciseEVMInput>,
        objective: &mut EVMOracleFeedback<'_>,
    ) -> Vec<ConciseEVMInput> {
        let mut executor = self.evm_executor_ref.deref().borrow_mut();

        let current_idx = input.from_idx.unwrap();
        let testcase = state
            .corpus()
            .get(current_idx.into())
            .unwrap()
            .borrow()
            .clone();
        let last_input = testcase.input().as_ref().expect("Input should be present");
        let mut txs = Self::get_call_seq(&last_input.sstate, state);
        let mut results = vec![];
        let mut minimized = false;
        while !minimized {
            minimized = true;
            for try_skip in 0..(txs.len() - 1) {
                results = vec![];
                for (i, item) in txs.iter().enumerate() {
                    if i == try_skip {
                        continue;
                    }
                    let (tx, call_leak) = item;
                    unsafe {
                        CALL_UNTIL = *call_leak;
                    }
                    let res = executor.execute(tx, state);
                    results.push(res);
                    let reverted = state.get_execution_result().reverted;
                    if reverted {
                        break;
                    }
                }
                let monitor = SimpleMonitor::new(|s| println!("{}", s));
                let mut mgr = SimpleEventManager::new(monitor);
                let is_solution = objective.is_interesting(
                    state,
                    &mut mgr,
                    &txs[txs.len() - 1].0,
                    &(),
                    &ExitKind::Ok,
                ).expect("Oracle feedback should not fail");

                if is_solution {
                    txs = txs
                        .into_iter()
                        .enumerate()
                        .filter(|(i, _)| *i != try_skip)
                        .map(|(_, s)| s)
                        .collect();
                    minimized = false;
                    break;
                }
            }
        }

        if results.is_empty() {
            assert!(txs.len() == 1);
            let res = executor.execute(&txs[0].0, state);
            results = vec![res];
        }
        txs.into_iter()
            .zip(results)
            .map(|(tx, res)| ConciseEVMInput::from_input(&tx.0, &res))
            .collect_vec()
    }
}
