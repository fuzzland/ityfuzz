use std::{cell::RefCell, ops::Deref, rc::Rc};

use bytes::Bytes;
use itertools::Itertools;
use libafl::{
    prelude::Corpus,
    state::{HasCorpus, HasMetadata},
};
use revm_primitives::Bytecode;

use super::types::EVMStagedVMState;
use crate::{
    evm::{
        host::CALL_UNTIL,
        input::{ConciseEVMInput, EVMInput},
        types::{EVMAddress, EVMFuzzState, EVMQueueExecutor},
        vm::EVMState,
    },
    feedback::OracleFeedback,
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::VMInputT,
    minimizer::SequentialMinimizer,
    oracle::BugMetadata,
    state::{FuzzState, HasExecutionResult, HasInfantStateState},
    tracer::TxnTrace,
};

pub struct EVMMinimizer {
    evm_executor_ref: Rc<RefCell<EVMQueueExecutor>>,
}

impl EVMMinimizer {
    pub fn new(evm_executor_ref: Rc<RefCell<EVMQueueExecutor>>) -> Self {
        Self { evm_executor_ref }
    }

    fn get_call_seq(vm_state: &EVMStagedVMState, state: &mut EVMFuzzState) -> Vec<(EVMInput, u32)> {
        if let Some(from_idx) = vm_state.trace.from_idx {
            let corpus_item = state.get_infant_state_state().corpus().get(from_idx.into());
            // This happens when full_trace feature is not enabled, the corpus item may be
            // discarded
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

            return [
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
    FuzzState<EVMInput, EVMState, revm_primitives::B160, revm_primitives::B160, Vec<u8>, ConciseEVMInput>,
    ConciseEVMInput,
    EVMQueueExecutor,
>;

impl<E: libafl::executors::HasObservers>
    SequentialMinimizer<EVMFuzzState, E, EVMAddress, EVMAddress, ConciseEVMInput, EVMOracleFeedback<'_>>
    for EVMMinimizer
{
    fn minimize(
        &mut self,
        state: &mut EVMFuzzState,
        _exec: &mut E,
        input: &TxnTrace<EVMAddress, EVMAddress, ConciseEVMInput>,
        objective: &mut EVMOracleFeedback<'_>,
        corpus_id: usize,
    ) -> Vec<ConciseEVMInput> {
        let bug_meta = state.metadata::<BugMetadata>().unwrap();
        let bug_idx_needed = bug_meta
            .corpus_idx_to_bug
            .get(&corpus_id)
            .expect("Bug idx needed")
            .clone();

        let current_idx = input.from_idx.unwrap();
        let testcase = state
            .infant_states_state
            .corpus()
            .get(current_idx.into())
            .unwrap()
            .borrow()
            .clone();
        let last_sstate = testcase.input().as_ref().expect("Input should be present");
        let mut txs = Self::get_call_seq(last_sstate, state);
        txs.extend(input.transactions.iter().map(|ci| ci.to_input(last_sstate.clone())));
        assert!(!txs.is_empty());
        let mut minimized = false;
        let mut initial_state = txs[0].0.sstate.clone();
        while !minimized {
            minimized = true;
            for try_skip in 0..(txs.len()) {
                let mut is_solution = false;
                let mut current_state = initial_state.clone();

                for (i, item) in txs.iter().enumerate() {
                    if i == try_skip {
                        continue;
                    }

                    // skip when there is no post execution but the tx is step
                    if item.0.is_step() && !current_state.state.has_post_execution() {
                        break;
                    }

                    let (mut tx, call_leak) = item.clone();
                    unsafe {
                        CALL_UNTIL = call_leak;
                    }
                    tx.sstate = current_state.clone();
                    let res = {
                        let mut executor = self.evm_executor_ref.deref().borrow_mut();
                        executor.execute(&tx, state)
                    };

                    state.set_execution_result(res.clone());
                    let trial_is_solution = objective.reproduces(state, &tx, &bug_idx_needed);
                    is_solution |= trial_is_solution;
                    current_state = state.get_execution_result().new_state.clone();
                    let reverted = state.get_execution_result().reverted;
                    if reverted {
                        break;
                    }
                }

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

        txs.into_iter()
            .map(|(tx, call_leak)| ConciseEVMInput::from_input_with_call_leak(&tx, call_leak))
            .collect_vec()
    }
}
