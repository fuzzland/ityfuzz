use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use libafl::{Error, Evaluator, Fuzzer, impl_serdeany};
use libafl::corpus::Corpus;
use libafl::events::ProgressReporter;
use libafl::prelude::{HasMetadata, Stage};
use libafl::state::HasCorpus;
use revm_primitives::HashSet;
use serde::{Deserialize, Serialize};
use crate::evm::concolic::concolic_host::ConcolicHost;
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT};
use crate::evm::middlewares::middleware::MiddlewareType;
use crate::evm::types::EVMFuzzState;
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::generic_vm::vm_executor::GenericVM;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;

pub struct ConcolicStage<ST> {
    pub enabled: bool,
    pub known_state_input: HashSet<(usize, usize)>,
    pub phantom: std::marker::PhantomData<ST>,
}


#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ConcolicPrioritizationMetadata {
    pub interesting_idx: Vec<usize>,
    pub solutions: Vec<(String, Arc<EVMInput>)>
}

impl_serdeany!(ConcolicPrioritizationMetadata);

impl<EM, Z, ST> Stage<EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>, EM, EVMFuzzState, Z> for ConcolicStage<ST>
where Z: Fuzzer<EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>, EM, EVMInput, EVMFuzzState, ST> +
         Evaluator<EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>, EM, EVMInput, EVMFuzzState>,
      EM: ProgressReporter<EVMInput>,
{
    fn perform(&mut self,
               fuzzer: &mut Z,
               executor: &mut EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>,
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
            executor.host.add_middlewares(
                Rc::new(RefCell::new(
                    ConcolicHost::new(
                        testcase_ref.clone()
                    )
                ))
            );
            executor.execute(&testcase_ref, state);
            executor.host.remove_middlewares_by_ty(&MiddlewareType::Concolic);
        }

        {
            let mut metadata = state.metadata_mut().get_mut::<ConcolicPrioritizationMetadata>().unwrap();
            metadata.interesting_idx.clear();

            let mut testcases = vec![];

            while let Some((solution, orig_testcase)) = metadata.solutions.pop() {
                let solution_hex = hex::decode(solution).expect("hex decode");
                let mut data_abi = orig_testcase.get_data_abi().expect("data abi");
                data_abi.set_bytes(solution_hex);
                let mut new_testcase = (*orig_testcase).clone();
                new_testcase.data = Some(data_abi);
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
