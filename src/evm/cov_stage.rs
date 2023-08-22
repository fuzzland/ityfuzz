use std::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::fmt::Debug;
use std::fs;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::Arc;
use libafl::{Error, Evaluator, Fuzzer, impl_serdeany};
use libafl::corpus::{Corpus, Testcase};
use libafl::events::{EventFirer, ProgressReporter};
use libafl::executors::ExitKind;
use libafl::feedbacks::Feedback;
use libafl::inputs::Input;
use libafl::prelude::{HasClientPerfMonitor, HasMetadata, Named, ObserversTuple, Stage};
use libafl::state::HasCorpus;
use revm_primitives::HashSet;
use serde::{Deserialize, Serialize};
use crate::evm::concolic::concolic_host::{ConcolicHost, Field, Solution};
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT};
use crate::evm::middlewares::call_printer::CallPrinter;
use crate::evm::middlewares::coverage::{Coverage, EVAL_COVERAGE};
use crate::evm::middlewares::middleware::MiddlewareType;
use crate::evm::types::{EVMFuzzExecutor, EVMFuzzState};
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::executor::FuzzExecutor;
use crate::generic_vm::vm_executor::GenericVM;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::oracle::BugMetadata;

pub struct CoverageStage<OT> {
    pub last_corpus_idx: usize,
    executor: Rc<RefCell<EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>>>,
    coverage: Rc<RefCell<Coverage>>,
    call_printer: Rc<RefCell<CallPrinter>>,
    trace_dir: String,
    pub phantom: std::marker::PhantomData<(OT)>,
}

impl <OT> CoverageStage<OT> {
    pub fn new(
        executor: Rc<RefCell<EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>>>,
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
}

impl<EM, Z, OT> Stage<EVMFuzzExecutor<OT>, EM, EVMFuzzState, Z> for CoverageStage<OT>
    where Z: Evaluator<EVMFuzzExecutor<OT>, EM, EVMInput, EVMFuzzState>,
          EM: ProgressReporter<EVMInput>,
          OT: ObserversTuple<EVMInput, EVMFuzzState>
{
    fn perform(&mut self,
               fuzzer: &mut Z,
               executor: &mut EVMFuzzExecutor<OT>,
               state: &mut EVMFuzzState,
               manager: &mut EM,
               corpus_idx: usize
    ) -> Result<(), Error> {
        let total = state.corpus().count();
        if self.last_corpus_idx == total {
            return Ok(());
        }

        let mut exec = self.executor.deref().borrow_mut();
        exec.host.add_middlewares(self.call_printer.clone());

        let meta = state.metadata().get::<BugMetadata>().unwrap().clone();
        for i in self.last_corpus_idx..total {
            self.call_printer.deref().borrow_mut().cleanup();
            let testcase = state.corpus().get(i).unwrap().borrow().clone();
            let input = testcase.input().as_ref().expect("Input should be present");
            unsafe { EVAL_COVERAGE = true; }
            exec.execute(input, state);
            self.call_printer.deref().borrow_mut().save_trace(format!("{}/{}", self.trace_dir, i).as_str());
            if let Some(bug_idx) = meta.corpus_idx_to_bug.get(&i) {

                for id in bug_idx {
                    fs::copy(format!("{}/{}.json", self.trace_dir, i), format!("{}/bug_{}.json", self.trace_dir, id)).unwrap();
                }
            }
            unsafe { EVAL_COVERAGE = false; }
        }
        exec.host.remove_middlewares_by_ty(&MiddlewareType::CallPrinter);

        if self.last_corpus_idx == total {
            return Ok(());
        }

        self.coverage.deref().borrow_mut().record_instruction_coverage();
        self.last_corpus_idx = total;
        Ok(())
    }
}

