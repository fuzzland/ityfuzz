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
use crate::r#move::config::MoveFuzzConfig;
use crate::r#move::input::MoveFunctionInput;
use crate::r#move::movevm::MoveVM;
use crate::r#move::mutator::MoveFuzzMutator;
use crate::r#move::oracles::typed_bug::TypedBugOracle;
use crate::r#move::types::MoveFuzzState;
use crate::scheduler::SortedDroppingScheduler;


pub fn move_fuzzer(
    config: &MoveFuzzConfig,
    state: &mut MoveFuzzState
) {
    let vm: MoveVM<MoveFunctionInput, MoveFuzzState> = MoveVM::new();
    let vm_ref = Rc::new(RefCell::new(vm));
    let monitor = SimpleMonitor::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);

    let infant_scheduler = SortedDroppingScheduler::new();
    let mut scheduler = QueueScheduler::new();

    let jmp_observer = StdMapObserver::new("jmp", vm_ref.borrow().get_jmp());
    let mut feedback:
        MapFeedback<MoveFunctionInput, _, _, _, MoveFuzzState, _>
        = MaxMapFeedback::new(&jmp_observer);
    feedback
        .init_state(state)
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
        .fuzz_loop(&mut stages, &mut executor, state, &mut mgr)
        .expect("Fuzzing failed");
}
