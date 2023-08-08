use std::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::fmt::Debug;
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
use crate::evm::middlewares::coverage::{Coverage, EVAL_COVERAGE};
use crate::evm::middlewares::middleware::MiddlewareType;
use crate::evm::types::{EVMFuzzExecutor, EVMFuzzState};
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::executor::FuzzExecutor;
use crate::generic_vm::vm_executor::GenericVM;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;

pub struct CoverageStage<OT> {
    pub last_corpus_idx: usize,
    executor: Rc<RefCell<EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>>>,
    coverage: Rc<RefCell<Coverage>>,
    pub phantom: std::marker::PhantomData<(OT)>,
}

impl <OT> CoverageStage<OT> {
    pub fn new(
        executor: Rc<RefCell<EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>>>,
        coverage: Rc<RefCell<Coverage>>
    ) -> Self {
        Self {
            last_corpus_idx: 0,
            executor,
            coverage,
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
        for i in self.last_corpus_idx..total {
            let testcase = state.corpus().get(i).unwrap().borrow().clone();
            let input = testcase.input().as_ref().expect("Input should be present");
            unsafe { EVAL_COVERAGE = true; }
            self.executor.deref().borrow_mut().execute(input, state);
            unsafe { EVAL_COVERAGE = false; }
        }

        if self.last_corpus_idx == total {
            return Ok(());
        }

        self.coverage.deref().borrow_mut().record_instruction_coverage();
        self.last_corpus_idx = total;
        Ok(())
    }
}

