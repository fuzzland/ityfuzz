use std::str::FromStr;

use crate::{
    contract_utils::FIX_DEPLOYER,
    evm::{EVMExecutor, FuzzHost, JMP_MAP},
    executor::FuzzExecutor,
    fuzzer::ItyFuzzer,
    input::VMInput,
    mutator::FuzzMutator,
    rand_utils::fixed_address,
};
use libafl::feedbacks::Feedback;
use libafl::prelude::{powersched::PowerSchedule, SimpleEventManager};
use libafl::prelude::{PowerQueueScheduler, ShMemProvider};
use libafl::stages::CalibrationStage;
use libafl::{
    prelude::{tuple_list, MaxMapFeedback, SimpleMonitor, StdMapObserver},
    stages::StdPowerMutationalStage,
    Fuzzer,
};

use crate::contract_utils::{set_hash, ContractLoader};
use crate::evm::CMP_MAP;
use crate::feedback::{CmpFeedback, OracleFeedback};
use crate::oracle::FunctionHarnessOracle;
use crate::rand_utils::generate_random_address;
use crate::scheduler::SortedDroppingScheduler;
use crate::state::{FuzzState, InfantStateState};
use crate::state_input::StagedVMState;

use crate::config::Config;
use crate::middleware::Middleware;
use crate::onchain::onchain::OnChain;
use primitive_types::H160;

struct ABIConfig {
    abi: String,
    function: [u8; 4],
}

struct ContractInfo {
    name: String,
    abi: Vec<ABIConfig>,
}

pub fn cmp_fuzzer(config: Config<VMInput, FuzzState>) {
    let monitor = SimpleMonitor::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);
    let infant_scheduler: SortedDroppingScheduler<StagedVMState, InfantStateState> =
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
    let deployer = fixed_address(FIX_DEPLOYER);
    let middlewares: Vec<Box<dyn Middleware>> = match config.onchain {
        Some(onchain) => {
            vec![Box::new(OnChain::new(onchain))]
        }
        None => {
            vec![]
        }
    };
    let evm_executor: EVMExecutor<VMInput, FuzzState> =
        EVMExecutor::new(FuzzHost::with_middlewares(middlewares), deployer);
    let mut executor = FuzzExecutor::new(evm_executor, tuple_list!(jmp_observer));
    state.initialize(
        config.contract_info,
        &mut executor.evm_executor,
        &mut scheduler,
        &infant_scheduler,
        true,
    );
    #[cfg(feature = "deployer_is_attacker")]
    state.add_deployer_to_callers(deployer);
    executor.evm_executor.host.initialize(&mut state);
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
