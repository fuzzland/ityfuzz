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
use crate::evm::middlewares::middleware::MiddlewareType;
use crate::evm::types::{EVMFuzzExecutor, EVMFuzzState, ProjectSourceMapTy};
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::executor::FuzzExecutor;
use crate::generic_vm::vm_executor::GenericVM;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;

pub struct ConcolicStage<OT> {
    pub enabled: bool,
    pub allow_symbolic_addresses: bool,
    pub known_state_input: HashSet<(usize, usize)>,
    pub vm_executor: Rc<RefCell<EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>>>,
    pub phantom: std::marker::PhantomData<(OT)>,
    pub sourcemap: ProjectSourceMapTy,
}

impl <OT> ConcolicStage<OT> {
    pub fn new(enabled: bool,
               allow_symbolic_addresses: bool,
               vm_executor: Rc<RefCell<EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>>>,
               source_map: ProjectSourceMapTy
            ) -> Self {
        Self {
            enabled,
            allow_symbolic_addresses,
            known_state_input: HashSet::new(),
            vm_executor,
            phantom: std::marker::PhantomData,
            sourcemap: source_map,
        }
    }
}


#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ConcolicPrioritizationMetadata {
    pub interesting_idx: Vec<usize>,
    pub solutions: Vec<(Solution, Arc<EVMInput>)>
}

impl_serdeany!(ConcolicPrioritizationMetadata);

impl<EM, Z, OT> Stage<EVMFuzzExecutor<OT>, EM, EVMFuzzState, Z> for ConcolicStage<OT>
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
        if !self.enabled {
            return Ok(());
        }

        if !state.metadata().contains::<ConcolicPrioritizationMetadata>() {
            state.metadata_mut().insert(ConcolicPrioritizationMetadata {
                interesting_idx: Default::default(),
                solutions: vec![],
            });
        }

        let meta = state
            .metadata()
            .get::<ConcolicPrioritizationMetadata>()
            .unwrap()
            .clone();

        for idx in &meta.interesting_idx {
            println!("Running concolic execution on testcase #{}", idx);

            let testcase = state.corpus()
                .get(*idx).unwrap()
                .borrow()
                .input()
                .clone()
                .expect("input should exist");

            if testcase.get_data_abi().is_none() || testcase.get_state().has_post_execution() {
                // borrow/step tx?
                continue;
            }

            let testcase_ref = Arc::new(testcase.clone());


            {
                let mut vm = self.vm_executor.deref().borrow_mut();
                vm.host.add_middlewares(
                    Rc::new(RefCell::new(
                        ConcolicHost::new(
                            testcase_ref.clone(),
                            self.sourcemap.clone()
                        )
                    ))
                );
                vm.execute(&testcase_ref, state);
                vm.host.remove_middlewares_by_ty(&MiddlewareType::Concolic);
            }

        }

        {
            let mut metadata = state.metadata_mut().get_mut::<ConcolicPrioritizationMetadata>().unwrap();
            metadata.interesting_idx.clear();

            let mut testcases = vec![];

            while let Some((solution, orig_testcase)) = metadata.solutions.pop() {
                println!("We have a solution from concolic execution: {}", solution.to_string());
                let mut data_abi = orig_testcase.get_data_abi().expect("data abi");
                data_abi.set_bytes(solution.input);
                let mut new_testcase = (*orig_testcase).clone();
                new_testcase.data = Some(data_abi);

                for mod_fields in solution.fields {
                    match mod_fields {
                        Field::Caller => {
                            if self.allow_symbolic_addresses {
                                new_testcase.set_caller(solution.caller);
                            }
                        }
                        Field::CallDataValue => {
                            new_testcase.set_txn_value(solution.value);
                        }
                    }
                }
                // println!("new testcase: {:?}", new_testcase);
                testcases.push(new_testcase);
            }

            for testcase in testcases {
                fuzzer.evaluate_input(
                    state, executor, manager, testcase
                ).expect("evaluate input");
            }
        }

        Ok(())
    }
}



#[derive(Debug)]
pub struct ConcolicFeedbackWrapper<F: Named + Debug> {
    pub inner: F
}

impl<F: Named + Debug> ConcolicFeedbackWrapper<F> {
    pub fn new(inner: F) -> Self {
        Self {
            inner
        }
    }
}

impl<F: Named + Debug> Named for ConcolicFeedbackWrapper<F> {
    fn name(&self) -> &str {
        "ConcolicFeedbackWrapper"
    }
}

impl<I, S, F> Feedback<I, S> for ConcolicFeedbackWrapper<F>
where F: Feedback<I, S> + Named + Debug,
      I: Input,
      S: HasClientPerfMonitor + HasMetadata + HasCorpus<I>,{
    fn is_interesting<EM, OT>(&mut self, state: &mut S, manager: &mut EM, input: &I, observers: &OT, exit_kind: &ExitKind) -> Result<bool, Error> where EM: EventFirer<I>, OT: ObserversTuple<I, S> {
        self.inner.is_interesting(state, manager, input, observers, exit_kind)
    }

    fn append_metadata(&mut self, state: &mut S, _testcase: &mut Testcase<I>) -> Result<(), Error> {
        if !state.metadata().contains::<ConcolicPrioritizationMetadata>() {
            state.metadata_mut().insert(ConcolicPrioritizationMetadata {
                interesting_idx: Default::default(),
                solutions: vec![],
            });
        }

        let idx = state.corpus().count();
        let mut meta = state
            .metadata_mut()
            .get_mut::<ConcolicPrioritizationMetadata>()
            .unwrap();

        meta.interesting_idx.push(idx);
        Ok(())
    }
}

