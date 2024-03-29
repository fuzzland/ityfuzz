use std::{cell::RefCell, fmt::Debug, ops::Deref, rc::Rc};

use libafl::{
    corpus::{Corpus, Testcase},
    events::{EventFirer, ProgressReporter},
    executors::ExitKind,
    feedbacks::Feedback,
    inputs::Input,
    prelude::{CorpusId, HasMetadata, ObserversTuple, Stage, UsesInput},
    state::{HasCorpus, State, UsesState},
    Error,
    Evaluator,
};
use libafl_bolts::{impl_serdeany, Named};
use revm_primitives::HashSet;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::{
    evm::{
        concolic::concolic_host::{ConcolicHost, Field, Solution, ALL_SOLUTIONS, ALL_WORKER_THREADS},
        input::{EVMInput, EVMInputT},
        middlewares::middleware::MiddlewareType,
        types::{EVMFuzzExecutor, EVMFuzzState, EVMQueueExecutor},
    },
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::VMInputT,
};
pub struct ConcolicStage<OT> {
    pub enabled: bool,
    pub allow_symbolic_addresses: bool,
    pub known_state_input: HashSet<(usize, usize)>,
    pub vm_executor: Rc<RefCell<EVMQueueExecutor>>,
    pub phantom: std::marker::PhantomData<OT>,
    pub num_threads: usize,
}

impl<OT> UsesState for ConcolicStage<OT> {
    type State = EVMFuzzState;
}

impl<OT> ConcolicStage<OT> {
    pub fn new(
        enabled: bool,
        allow_symbolic_addresses: bool,
        vm_executor: Rc<RefCell<EVMQueueExecutor>>,
        num_threads: usize,
    ) -> Self {
        Self {
            enabled,
            allow_symbolic_addresses,
            known_state_input: HashSet::new(),
            vm_executor,
            phantom: std::marker::PhantomData,
            num_threads,
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ConcolicPrioritizationMetadata {
    pub interesting_idx: Vec<usize>,
    pub solutions: Vec<(Solution, Rc<EVMInput>)>,
}

impl_serdeany!(ConcolicPrioritizationMetadata);

impl<EM, Z, OT> Stage<EVMFuzzExecutor<OT>, EM, Z> for ConcolicStage<OT>
where
    Z: Evaluator<EVMFuzzExecutor<OT>, EM, State = Self::State>,
    EM: ProgressReporter + UsesState<State = Self::State>,
    OT: ObserversTuple<Self::State>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut EVMFuzzExecutor<OT>,
        state: &mut Self::State,
        manager: &mut EM,
        _corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        if !state.metadata_map().contains::<ConcolicPrioritizationMetadata>() {
            // 0..state.corpus().count() is the range of indexes of the corpus
            let idxs = (0..state.corpus().count()).collect::<Vec<_>>();
            state.metadata_map_mut().insert(ConcolicPrioritizationMetadata {
                interesting_idx: idxs,
                solutions: vec![],
            });
        }

        let meta = state
            .metadata_map()
            .get::<ConcolicPrioritizationMetadata>()
            .unwrap()
            .clone();

        for idx in &meta.interesting_idx {
            info!("Running concolic execution on testcase #{}", idx);

            let testcase = state
                .corpus()
                .get((*idx).into())
                .unwrap()
                .borrow()
                .input()
                .clone()
                .expect("input should exist");

            if testcase.get_data_abi().is_none() || testcase.get_state().has_post_execution() {
                // borrow/step tx?
                continue;
            }

            let testcase_ref = Rc::new(testcase.clone());

            {
                let mut vm = self.vm_executor.deref().borrow_mut();
                vm.host.add_middlewares(Rc::new(RefCell::new(ConcolicHost::new(
                    testcase_ref.clone(),
                    self.num_threads,
                ))));
                vm.execute(&testcase_ref, state);

                let mut worker_threads = ALL_WORKER_THREADS.lock().unwrap();
                while worker_threads.len() > 0 {
                    let curr_thread = worker_threads.remove(0);
                    curr_thread.join().unwrap();
                }
                drop(worker_threads);

                let mut solutions = ALL_SOLUTIONS.lock().unwrap();
                if solutions.len() > 0 {
                    let meta = state
                        .metadata_map_mut()
                        .get_mut::<ConcolicPrioritizationMetadata>()
                        .expect("Failed to get metadata");
                    for solution in solutions.iter() {
                        meta.solutions.push((solution.clone(), testcase_ref.clone()));
                    }
                    solutions.clear();
                }
                drop(solutions);

                vm.host.remove_middlewares_by_ty(&MiddlewareType::Concolic);
            }
        }

        {
            let metadata = state
                .metadata_map_mut()
                .get_mut::<ConcolicPrioritizationMetadata>()
                .unwrap();
            metadata.interesting_idx.clear();

            let mut testcases = vec![];

            while let Some((solution, orig_testcase)) = metadata.solutions.pop() {
                debug!("We have a solution from concolic execution: {}", solution.to_string());
                let mut data_abi = orig_testcase.get_data_abi().expect("data abi");
                let mut new_testcase = (*orig_testcase).clone();

                // if cannot set_bytes AND no fields to modify, skip
                if data_abi.set_bytes(solution.input) {
                    // This can fail if e.g. solving for an array
                    new_testcase.data = Some(data_abi);
                } else if solution.fields.is_empty() {
                    continue;
                }

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
                        Field::Origin => {
                            if self.allow_symbolic_addresses {
                                new_testcase.set_origin(solution.origin);
                            }
                        }
                    }
                }
                // debug!("new testcase: {:?}", new_testcase);
                testcases.push(new_testcase);
            }

            for testcase in testcases {
                fuzzer
                    .evaluate_input(state, executor, manager, testcase)
                    .expect("evaluate input");
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct ConcolicFeedbackWrapper<F: Named + Debug> {
    pub inner: F,
}

impl<F: Named + Debug> ConcolicFeedbackWrapper<F> {
    pub fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<F: Named + Debug> Named for ConcolicFeedbackWrapper<F> {
    fn name(&self) -> &str {
        "ConcolicFeedbackWrapper"
    }
}

impl<I, S, F> Feedback<S> for ConcolicFeedbackWrapper<F>
where
    I: Input,
    F: Feedback<S> + Named + Debug,
    S: State + HasMetadata + HasCorpus + UsesInput<Input = I>,
{
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        self.inner.is_interesting(state, manager, input, observers, exit_kind)
    }

    #[inline]
    #[allow(unused_variables)]
    fn append_metadata<OT>(
        &mut self,
        state: &mut S,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
    {
        if !state.metadata_map().contains::<ConcolicPrioritizationMetadata>() {
            // 0..state.corpus().count() is the range of indexes of the corpus
            let idxs = (0..state.corpus().count()).collect::<Vec<_>>();
            state.metadata_map_mut().insert(ConcolicPrioritizationMetadata {
                interesting_idx: idxs,
                solutions: vec![],
            });
        }

        let idx = state.corpus().count();
        let meta = state
            .metadata_map_mut()
            .get_mut::<ConcolicPrioritizationMetadata>()
            .unwrap();

        meta.interesting_idx.push(idx);

        self.inner.append_metadata(state, observers, testcase)
    }
}
