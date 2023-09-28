use std::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::fmt::Debug;
use std::fs;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::Arc;
use itertools::Itertools;
use libafl::{Error, Evaluator, Fuzzer};
use libafl_bolts::{impl_serdeany, Named};
use libafl::corpus::{Corpus, Testcase};
use libafl::events::{EventFirer, ProgressReporter};
use libafl::executors::ExitKind;
use libafl::feedbacks::Feedback;
use libafl::inputs::Input;
use libafl::prelude::{HasClientPerfMonitor, HasMetadata, ObserversTuple, Stage, CorpusId};
use libafl::state::{HasCorpus, UsesState};
use revm_primitives::HashSet;
use serde::{Deserialize, Serialize};
use crate::evm::concolic::concolic_host::{ConcolicHost, Field, Solution};
use crate::evm::host::CALL_UNTIL;
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT};
use crate::evm::middlewares::call_printer::CallPrinter;
use crate::evm::middlewares::coverage::{Coverage, EVAL_COVERAGE};
use crate::evm::middlewares::middleware::MiddlewareType;
use crate::evm::types::{EVMFuzzExecutor, EVMFuzzState, EVMStagedVMState, EVMQueueExecutor};
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::executor::FuzzExecutor;
use crate::generic_vm::vm_executor::GenericVM;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::oracle::BugMetadata;
use crate::state::HasInfantStateState;

pub struct CoverageStage<OT> {
    pub last_corpus_idx: usize,
    executor: Rc<RefCell<EVMQueueExecutor>>,
    coverage: Rc<RefCell<Coverage>>,
    call_printer: Rc<RefCell<CallPrinter>>,
    trace_dir: String,
    pub phantom: std::marker::PhantomData<OT>,
}

impl<OT> UsesState for CoverageStage<OT> {
    type State = EVMFuzzState;
}

impl <OT> CoverageStage<OT> {
    pub fn new(
        executor: Rc<RefCell<EVMQueueExecutor>>,
        coverage: Rc<RefCell<Coverage>>,
        call_printer: Rc<RefCell<CallPrinter>>,
        work_dir: String,
    ) -> Self {
        let trace_dir = format!("{}/traces", work_dir);
        if !std::path::Path::new(&trace_dir).exists() {
            std::fs::create_dir_all(&trace_dir).unwrap();
        }
        Self {
            last_corpus_idx: 0,
            executor,
            coverage,
            call_printer,
            trace_dir,
            phantom: std::marker::PhantomData,
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
                vm_state.trace.transactions.iter().enumerate().map(
                    |(idx, ci)| {
                        if idx == 0 {
                            ci.to_input(prev_state.clone())
                        } else {
                            ci.to_input(EVMStagedVMState::new_uninitialized())
                        }
                    }
                ).collect_vec()
            ].concat();
        }
        vec![]
    }
}

impl <EM, Z, OT> Stage<EVMFuzzExecutor<OT>, EM, Z> for CoverageStage<OT>
where
    Z: Evaluator<EVMFuzzExecutor<OT>, EM, State = Self::State>,
    EM: ProgressReporter + UsesState<State = Self::State>,
    OT: ObserversTuple<Self::State>,
{
    fn perform(&mut self,
               fuzzer: &mut Z,
               executor: &mut EVMFuzzExecutor<OT>,
               state: &mut Self::State,
               manager: &mut EM,
               corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        let last_idx = state.corpus().last();
        if last_idx.is_none() {
            return Ok(());
        }
        let last_idx = last_idx.unwrap().into();
        if self.last_corpus_idx == last_idx {
            return Ok(());
        }

        let mut exec = self.executor.deref().borrow_mut();
        exec.host.add_middlewares(self.call_printer.clone());

        let meta = state.metadata_map().get::<BugMetadata>().unwrap().clone();
        let mut current_idx = CorpusId::from(self.last_corpus_idx);
        while let Some(i) = state.corpus().next(current_idx) {
            self.call_printer.deref().borrow_mut().cleanup();
            let testcase = state.corpus().get(i).unwrap().borrow().clone();
            let last_input = testcase.input().as_ref().expect("Input should be present");

            let mut last_state: EVMStagedVMState = Default::default();
            for (mut tx, call_until) in Self::get_call_seq(&last_input.sstate, state) {
                if tx.step {
                    self.call_printer.deref().borrow_mut().mark_step_tx();
                }
                unsafe { CALL_UNTIL = call_until; }
                if !tx.sstate.initialized {
                    tx.sstate = last_state.clone();
                }
                let res = exec.execute(&tx, state);
                last_state = res.new_state.clone();
                self.call_printer.deref().borrow_mut().mark_new_tx(
                    last_state.state.post_execution.len()
                );
            }
            unsafe { CALL_UNTIL = u32::MAX; }
            unsafe { EVAL_COVERAGE = true; }

            {
                if last_input.step {
                    self.call_printer.deref().borrow_mut().mark_step_tx();
                }
                exec.execute(last_input, state);
            }

            self.call_printer.deref().borrow_mut().save_trace(format!("{}/{}", self.trace_dir, i).as_str());
            if let Some(bug_idx) = meta.corpus_idx_to_bug.get(&i.into()) {
                for id in bug_idx {
                    fs::copy(format!("{}/{}.json", self.trace_dir, i), format!("{}/bug_{}.json", self.trace_dir, id)).unwrap();
                }
            }
            unsafe { EVAL_COVERAGE = false; }

            current_idx = i;
        }

        exec.host.remove_middlewares_by_ty(&MiddlewareType::CallPrinter);

        if self.last_corpus_idx == last_idx {
            return Ok(());
        }

        self.coverage.deref().borrow_mut().record_instruction_coverage();
        self.last_corpus_idx = last_idx;
        Ok(())
    }
}
