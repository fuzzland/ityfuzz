use crate::{
    evm::{EVMExecutor, FuzzHost, JMP_MAP},
    executor::FuzzExecutor,
    fuzzer::ItyFuzzer,
    input::{VMInput, VMInputT},
    mutator::FuzzMutator,
};
use libafl::feedbacks::Feedback;
use libafl::prelude::{
    powersched::PowerSchedule, MapFeedback, ObserversTuple, QueueScheduler, SimpleEventManager,
};
use libafl::prelude::{PowerQueueScheduler, ShMemProvider, StdShMemProvider};
use libafl::stages::CalibrationStage;
use libafl::{
    prelude::{
        current_nanos, current_time, tuple_list, ConstFeedback, HitcountsMapObserver,
        InMemoryCorpus, MaxMapFeedback, OnDiskCorpus, SimpleMonitor, SimpleRestartingEventManager,
        StdMapObserver, StdRand,
    },
    schedulers::StdScheduler,
    stages::StdPowerMutationalStage,
    state::StdState,
    Error, Fuzzer,
};
use std::io::Write;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    io,
    path::PathBuf,
};

use crate::contract_utils::{set_hash, ContractLoader};
use crate::evm::CMP_MAP;
use crate::feedback::{CmpFeedback, InfantFeedback, OracleFeedback};
use crate::oracle::{FunctionHarnessOracle, IERC20Oracle, NoOracle};
use crate::rand_utils::generate_random_address;
use crate::scheduler::SortedDroppingScheduler;
use crate::state::{FuzzState, InfantStateState};
use crate::state_input::StagedVMState;
use nix::unistd::dup;
use primitive_types::H160;
use revm::EVM;

struct ABIConfig {
    abi: String,
    function: [u8; 4],
}

struct ContractInfo {
    name: String,
    abi: Vec<ABIConfig>,
}

pub fn cmp_fuzzer(contracts_glob: &String) {
    let monitor = SimpleMonitor::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);
    let mut infant_scheduler: SortedDroppingScheduler<StagedVMState, InfantStateState> =
        SortedDroppingScheduler::new();

    let jmps = unsafe { &mut JMP_MAP };
    let cmps = unsafe { &mut CMP_MAP };
    let jmp_observer = StdMapObserver::new("jmp_labels", jmps);
    let mut feedback = MaxMapFeedback::new(&jmp_observer);
    let calibration = CalibrationStage::new(&feedback);
    let mut state = FuzzState::new();

    let mut scheduler = PowerQueueScheduler::new(PowerSchedule::FAST);

    let mutator = FuzzMutator::new(&infant_scheduler);

    let std_stage = StdPowerMutationalStage::new(mutator, &jmp_observer);
    let mut stages = tuple_list!(calibration, std_stage);
    let deployer = generate_random_address();
    let evm_executor: EVMExecutor<VMInput, FuzzState> =
        EVMExecutor::new(FuzzHost::new(), deployer);
    let mut executor = FuzzExecutor::new(evm_executor, tuple_list!(jmp_observer));
    let contract_info = ContractLoader::from_glob(contracts_glob).contracts;
    state.initialize(
        contract_info,
        &mut executor.evm_executor,
        &mut scheduler,
        &infant_scheduler,
        true,
    );
    #[cfg(feature = "deployer_is_attacker")]
    state.add_deployer_to_callers(deployer);
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

    let infant_feedback = CmpFeedback::new(cmps, &infant_scheduler);

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
