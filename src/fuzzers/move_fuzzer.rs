use std::{cell::RefCell, rc::Rc};

use libafl::{
    feedbacks::Feedback,
    prelude::{MapFeedback, MaxMapFeedback, QueueScheduler, SimpleEventManager, SimpleMonitor, StdMapObserver},
    stages::StdMutationalStage,
    Fuzzer,
};
use libafl_bolts::tuples::tuple_list;
use tracing::info;

#[cfg(feature = "sui_support")]
use crate::r#move::corpus_initializer::MoveCorpusInitializer;
#[cfg(feature = "sui_support")]
use crate::r#move::input::MoveFunctionInput;
#[cfg(feature = "sui_support")]
use crate::r#move::minimizer::MoveMinimizer;
#[cfg(feature = "sui_support")]
use crate::r#move::movevm::MoveVM;
#[cfg(feature = "sui_support")]
use crate::r#move::mutator::MoveFuzzMutator;
#[cfg(feature = "sui_support")]
use crate::r#move::oracles::typed_bug::TypedBugOracle;
#[cfg(feature = "sui_support")]
use crate::r#move::scheduler::{MoveTestcaseScheduler, MoveVMStateScheduler};
#[cfg(feature = "sui_support")]
use crate::r#move::types::MoveFuzzState;
#[cfg(feature = "sui_support")]
use crate::scheduler::SortedDroppingScheduler;
use crate::{
    executor::FuzzExecutor,
    feedback::{CmpFeedback, DataflowFeedback, OracleFeedback},
    fuzzer::ItyFuzzer,
    generic_vm::vm_executor::GenericVM,
    oracle::Oracle,
    state::FuzzState,
};

pub struct MoveFuzzConfig {
    pub target: String,
    pub work_dir: String,
    pub seed: u64,
}

pub static mut MOVE_ENABLED: bool = cfg!(feature = "move_support");

#[cfg(feature = "sui_support")]
pub fn move_fuzzer(config: &MoveFuzzConfig) {
    let mut state: MoveFuzzState = FuzzState::new(config.seed);
    let mut vm: MoveVM<MoveFunctionInput, MoveFuzzState> = MoveVM::new();
    let monitor = SimpleMonitor::new(|s| info!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);

    let infant_scheduler = MoveVMStateScheduler {
        inner: SortedDroppingScheduler::new(),
    };
    let scheduler = MoveTestcaseScheduler {
        inner: QueueScheduler::new(),
    };

    {
        MoveCorpusInitializer::new(&mut state, &mut vm, scheduler.clone(), infant_scheduler.clone())
            .setup(vec![config.target.clone()]);
    }

    let vm_ref = Rc::new(RefCell::new(vm));

    let jmp_observer = unsafe { StdMapObserver::new("jmp", vm_ref.borrow().get_jmp()) };
    let mut feedback: MapFeedback<_, _, _, MoveFuzzState, _> = MaxMapFeedback::new(&jmp_observer);
    feedback.init_state(&mut state).expect("Failed to init state");

    let mutator = MoveFuzzMutator::new(infant_scheduler.clone());

    let std_stage = StdMutationalStage::new(mutator);
    let mut stages = tuple_list!(std_stage);

    let mut executor = FuzzExecutor::new(vm_ref.clone(), tuple_list!(jmp_observer));

    let infant_feedback = CmpFeedback::new(vm_ref.borrow().get_cmp(), infant_scheduler.clone(), vm_ref.clone());
    let infant_result_feedback = DataflowFeedback::new(vm_ref.borrow().get_read(), vm_ref.borrow().get_write());

    let mut oracles: Vec<Rc<RefCell<dyn Oracle<_, _, _, _, _, _, _, _, _, _, _>>>> =
        vec![Rc::new(RefCell::new(TypedBugOracle::new()))];
    let mut producers = vec![];

    let objective = OracleFeedback::new(&mut oracles, &mut producers, vm_ref.clone());

    //
    let mut fuzzer = ItyFuzzer::new(
        scheduler,
        infant_scheduler,
        feedback,
        infant_feedback,
        infant_result_feedback,
        objective,
        MoveMinimizer,
        config.work_dir.clone(),
    );
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Fuzzing failed");
}

#[cfg(not(feature = "sui_support"))]
pub fn move_fuzzer(_config: &MoveFuzzConfig) {
    panic!("Move fuzzer is not enabled");
}
