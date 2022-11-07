use crate::{
    evm::{EVMExecutor, FuzzHost, JMP_MAP},
    executor::FuzzExecutor,
    fuzzer::ItyFuzzer,
    input::{VMInput},
    mutator::FuzzMutator,
};
use libafl::feedbacks::Feedback;
use libafl::prelude::{
    powersched::PowerSchedule, QueueScheduler, SimpleEventManager,
};
use libafl::prelude::{PowerQueueScheduler, ShMemProvider};
use libafl::stages::CalibrationStage;
use libafl::{
    prelude::{
        tuple_list, MaxMapFeedback, SimpleMonitor,
        StdMapObserver,
    },
    stages::StdPowerMutationalStage, Fuzzer,
};


use std::{
    path::PathBuf,
};

use crate::contract_utils::{set_hash, ContractLoader};
use crate::feedback::{InfantFeedback, OracleFeedback};
use crate::oracle::{FunctionHarnessOracle};
use crate::rand_utils::generate_random_address;
use crate::state::FuzzState;

use primitive_types::H160;


struct ABIConfig {
    abi: String,
    function: [u8; 4],
}

struct ContractInfo {
    name: String,
    abi: Vec<ABIConfig>,
}

pub fn basic_fuzzer(
    _corpus_dir: PathBuf,
    _objective_dir: PathBuf,
    _logfile: PathBuf,
    contracts_glob: &String,
) {
    // Fuzzbench style, which requires a host and can have many fuzzing client
    // let log = RefCell::new(
    //     OpenOptions::new()
    //         .append(true)
    //         .create(true)
    //         .open(&logfile)?,
    // );

    // let mut stdout_cpy = unsafe {
    //     let new_fd = dup(io::stdout().as_raw_fd())?;
    //     File::from_raw_fd(new_fd)
    // };

    // // TODO: display useful information of the current run
    // let monitor = SimpleMonitor::new(|s| {
    //     writeln!(&mut stdout_cpy, "{}", s).unwrap();
    //     writeln!(log.borrow_mut(), "{:?} {}", current_time(), s).unwrap();
    // });

    // let mut shmem_provider = StdShMemProvider::new()?;

    // let (_, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider) {
    //     // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
    //     Ok(res) => res,
    //     Err(err) => match err {
    //         Error::ShuttingDown => {
    //             return Ok(());
    //         }
    //         _ => {
    //             panic!("Failed to setup the restarter: {}", err);
    //         }
    //     },
    // };

    let monitor = SimpleMonitor::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);
    let infant_scheduler = QueueScheduler::new();

    let jmps = unsafe { &mut JMP_MAP };
    let jmp_observer = StdMapObserver::new("jmp_labels", jmps);
    // TODO: implement OracleFeedback
    let mut feedback = MaxMapFeedback::new(&jmp_observer);
    let calibration = CalibrationStage::new(&feedback);
    let mut state = FuzzState::new();

    let mut scheduler = PowerQueueScheduler::new(PowerSchedule::FAST);

    let mutator = FuzzMutator::new(&infant_scheduler);

    let std_stage = StdPowerMutationalStage::new(mutator, &jmp_observer);
    let mut stages = tuple_list!(calibration, std_stage);

    // TODO: Fill EVMExecutor with real data?
    let evm_executor: EVMExecutor<VMInput, FuzzState> =
        EVMExecutor::new(FuzzHost::new(), generate_random_address());

    let mut executor = FuzzExecutor::new(evm_executor, tuple_list!(jmp_observer));

    let contract_info = ContractLoader::from_glob(contracts_glob).contracts;
    state.initialize(
        contract_info,
        &mut executor.evm_executor,
        &mut scheduler,
        &infant_scheduler,
        false,
    );
    executor.evm_executor.host.initalize(&mut state);
    feedback
        .init_state(&mut state)
        .expect("Failed to init state");

    // now evm executor is ready, we can clone it
    let harness_code = "oracle_harness()";
    let mut harness_hash: [u8; 4] = [0; 4];
    set_hash(harness_code, &mut harness_hash);
    let oracle = FunctionHarnessOracle::new_no_condition(H160::zero(), Vec::from(harness_hash));
    let objective = OracleFeedback::new(&oracle, executor.evm_executor.clone());

    let infant_feedback = InfantFeedback::new(&oracle, executor.evm_executor.clone());

    let mut fuzzer = ItyFuzzer::new(
        scheduler,
        &infant_scheduler,
        feedback,
        infant_feedback,
        objective,
    );

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Fuzzing failed");
}
