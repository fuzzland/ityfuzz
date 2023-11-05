use std::{cell::RefCell, fs, ops::Deref, rc::Rc};

use itertools::Itertools;
use libafl::{
    corpus::Corpus,
    events::ProgressReporter,
    prelude::{CorpusId, HasMetadata, ObserversTuple, Stage},
    state::{HasCorpus, UsesState},
    Error,
    Evaluator,
};

use crate::{
    evm::{
        host::CALL_UNTIL,
        input::EVMInput,
        middlewares::{
            call_printer::CallPrinter,
            coverage::{Coverage, EVAL_COVERAGE},
            middleware::MiddlewareType,
        },
        types::{EVMFuzzExecutor, EVMFuzzState, EVMQueueExecutor, EVMStagedVMState},
    },
    generic_vm::vm_executor::GenericVM,
    oracle::BugMetadata,
    state::HasInfantStateState,
};

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

impl<OT> CoverageStage<OT> {
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

impl<EM, Z, OT> Stage<EVMFuzzExecutor<OT>, EM, Z> for CoverageStage<OT>
where
    Z: Evaluator<EVMFuzzExecutor<OT>, EM, State = Self::State>,
    EM: ProgressReporter + UsesState<State = Self::State>,
    OT: ObserversTuple<Self::State>,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut EVMFuzzExecutor<OT>,
        state: &mut Self::State,
        _manager: &mut EM,
        _corpus_idx: CorpusId,
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
                unsafe {
                    CALL_UNTIL = call_until;
                }
                if !tx.sstate.initialized {
                    tx.sstate = last_state.clone();
                }
                let res = exec.execute(&tx, state);
                last_state = res.new_state.clone();
                self.call_printer
                    .deref()
                    .borrow_mut()
                    .mark_new_tx(last_state.state.post_execution.len());
            }
            unsafe {
                CALL_UNTIL = u32::MAX;
            }
            unsafe {
                EVAL_COVERAGE = true;
            }

            {
                if last_input.step {
                    self.call_printer.deref().borrow_mut().mark_step_tx();
                }
                exec.execute(last_input, state);
            }

            self.call_printer
                .deref()
                .borrow_mut()
                .save_trace(format!("{}/{}", self.trace_dir, i).as_str());
            if let Some(bug_idx) = meta.corpus_idx_to_bug.get(&i.into()) {
                for id in bug_idx {
                    fs::copy(
                        format!("{}/{}.json", self.trace_dir, i),
                        format!("{}/bug_{}.json", self.trace_dir, id),
                    )
                    .unwrap();
                }
            }
            unsafe {
                EVAL_COVERAGE = false;
            }

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
