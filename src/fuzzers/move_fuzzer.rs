use bytes::Bytes;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;

use crate::{
    evm::contract_utils::FIX_DEPLOYER, evm::host::FuzzHost, evm::vm::EVMExecutor,
    executor::FuzzExecutor, fuzzer::ItyFuzzer,
};
use libafl::feedbacks::Feedback;
use libafl::prelude::{HasMetadata, MapFeedback, ShMemProvider};
use libafl::prelude::{QueueScheduler, SimpleEventManager};
use libafl::stages::{CalibrationStage, StdMutationalStage};
use libafl::{
    prelude::{tuple_list, MaxMapFeedback, SimpleMonitor, StdMapObserver},
    Evaluator, Fuzzer,
};
use glob::glob;
use itertools::Itertools;
use crate::feedback::{CmpFeedback, DataflowFeedback, OracleFeedback};
use crate::generic_vm::vm_executor::GenericVM;
use crate::oracle::Oracle;

#[cfg(feature = "move_support")]
use crate::r#move::corpus_initializer::MoveCorpusInitializer;
#[cfg(feature = "move_support")]
use crate::r#move::input::MoveFunctionInput;
#[cfg(feature = "move_support")]
use crate::r#move::movevm::MoveVM;
#[cfg(feature = "move_support")]
use crate::r#move::mutator::MoveFuzzMutator;
#[cfg(feature = "move_support")]
use crate::r#move::oracles::typed_bug::TypedBugOracle;
#[cfg(feature = "move_support")]
use crate::r#move::types::MoveFuzzState;
#[cfg(feature = "move_support")]
use crate::scheduler::SortedDroppingScheduler;
use crate::state::FuzzState;

pub struct MoveFuzzConfig {
    pub target: String,
    pub work_dir: String,
    pub seed: u64,
}

pub static mut MOVE_ENABLED: bool = cfg!(feature = "move_support");

#[cfg(feature = "move_support")]
pub fn move_fuzzer(
    config: &MoveFuzzConfig,
) {
    let mut state: MoveFuzzState = FuzzState::new(config.seed);
    let mut vm: MoveVM<MoveFunctionInput, MoveFuzzState> = MoveVM::new();
    let monitor = SimpleMonitor::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);

    let infant_scheduler = SortedDroppingScheduler::new();
    let mut scheduler = QueueScheduler::new();

    {
        MoveCorpusInitializer::new(
            &mut state,
            &mut vm,
            &scheduler,
            &infant_scheduler,
        ).setup(vec![config.target.clone()]);
    }

    let vm_ref = Rc::new(RefCell::new(vm));

    let jmp_observer = StdMapObserver::new("jmp", vm_ref.borrow().get_jmp());
    let mut feedback:
        MapFeedback<MoveFunctionInput, _, _, _, MoveFuzzState, _>
        = MaxMapFeedback::new(&jmp_observer);
    feedback
        .init_state(&mut state)
        .expect("Failed to init state");
    let calibration: CalibrationStage<MoveFunctionInput, _, (StdMapObserver<u8>, ()), MoveFuzzState> = CalibrationStage::new(&feedback);

    let mutator = MoveFuzzMutator::new(&infant_scheduler);

    let std_stage = StdMutationalStage::new(mutator);
    let mut stages = tuple_list!(calibration, std_stage);

    let mut executor = FuzzExecutor::new(vm_ref.clone(), tuple_list!(jmp_observer));

    let infant_feedback = CmpFeedback::new(vm_ref.borrow().get_cmp(), &infant_scheduler, vm_ref.clone());
    let infant_result_feedback = DataflowFeedback::new(vm_ref.borrow().get_read(), vm_ref.borrow().get_write());

    let mut oracles: Vec<Rc<RefCell<dyn Oracle<_, _, _, _, _, _, _, _, _, _>>>> = vec![
        Rc::new(RefCell::new(TypedBugOracle::new()))
    ];
    let mut producers = vec![];

    let objective = OracleFeedback::new(&mut oracles, &mut producers, vm_ref.clone());


    //
    let mut fuzzer = ItyFuzzer::new(
        scheduler,
        &infant_scheduler,
        feedback,
        infant_feedback,
        infant_result_feedback,
        objective,
        config.work_dir.clone(),
    );
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Fuzzing failed");
}


#[cfg(not(feature = "move_support"))]
pub fn move_fuzzer(
    _config: &MoveFuzzConfig,
) {
    panic!("Move fuzzer is not enabled");
}
