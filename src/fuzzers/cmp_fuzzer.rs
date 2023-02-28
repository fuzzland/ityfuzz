use bytes::Bytes;
use std::str::FromStr;
use std::sync::Arc;

use crate::{
    evm::contract_utils::FIX_DEPLOYER,
    evm::vm::{EVMExecutor, FuzzHost, JMP_MAP},
    executor::FuzzExecutor,
    fuzzer::ItyFuzzer,
    mutator::FuzzMutator,
    rand_utils::fixed_address,
};
use libafl::feedbacks::Feedback;
use libafl::prelude::{powersched::PowerSchedule, SimpleEventManager};
use libafl::prelude::{PowerQueueScheduler, ShMemProvider};
use libafl::stages::{CalibrationStage, Stage};
use libafl::{
    prelude::{tuple_list, MaxMapFeedback, SimpleMonitor, StdMapObserver},
    stages::StdPowerMutationalStage,
    Fuzzer,
};

use crate::evm::contract_utils::{set_hash, ContractLoader};
use crate::evm::oracle::{FunctionHarnessOracle, IERC20OracleFlashloan};
use crate::evm::vm::{EVMState, CMP_MAP};
use crate::feedback::{CmpFeedback, OracleFeedback};
use crate::rand_utils::generate_random_address;
use crate::scheduler::SortedDroppingScheduler;
use crate::state::{FuzzState, InfantStateState};
use crate::state_input::StagedVMState;

use crate::evm::config::Config;
use crate::evm::middleware::Middleware;
use crate::evm::onchain::flashloan::Flashloan;
use crate::evm::onchain::onchain::OnChain;
use primitive_types::{H160, U256};
use revm::Bytecode;
use crate::evm::corpus_initializer::EVMCorpusInitializer;
use crate::evm::input::EVMInput;
use crate::evm::types::{EVMFuzzMutator, EVMFuzzState};

struct ABIConfig {
    abi: String,
    function: [u8; 4],
}

struct ContractInfo {
    name: String,
    abi: Vec<ABIConfig>,
}

pub fn cmp_fuzzer(
    config: Config<EVMState, H160, Bytecode, Bytes, H160, U256, EVMInput, EVMFuzzState>,
) {
    let monitor = SimpleMonitor::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);
    let infant_scheduler = SortedDroppingScheduler::new();

    let jmps = unsafe { &mut JMP_MAP };
    let cmps = unsafe { &mut CMP_MAP };
    let jmp_observer = StdMapObserver::new("jmp_labels", jmps);
    let mut feedback = MaxMapFeedback::new(&jmp_observer);
    let calibration = CalibrationStage::new(&feedback);
    let mut state: EVMFuzzState = FuzzState::new();

    let mut scheduler = PowerQueueScheduler::new(PowerSchedule::FAST);

    let mutator: EVMFuzzMutator<'_> = FuzzMutator::new(&infant_scheduler);

    let std_stage = StdPowerMutationalStage::new(mutator, &jmp_observer);
    let mut stages = tuple_list!(calibration, std_stage);
    let deployer = fixed_address(FIX_DEPLOYER);
    let mut fuzz_host = FuzzHost::new();
    match config.onchain {
        Some(onchain) => {
            let mut mid = Box::new(
                OnChain::<EVMState, EVMInput, EVMFuzzState>::new(
                    // scheduler can be cloned because it never uses &mut self
                    onchain,
                    scheduler.clone(),
                ),
            );
            mid.add_blacklist(H160::from_str("6aed013308d847cb87502d86e7d9720b17b4c1f2").unwrap());
            fuzz_host.add_middlewares(mid);
        }
        None => {}
    };

    match config.flashloan {
        Some(flashloan) => {
            fuzz_host.add_middlewares(Box::new(flashloan));
        }
        None => {}
    };
    let mut evm_executor: EVMExecutor<EVMInput, EVMFuzzState, EVMState> =
        EVMExecutor::new(fuzz_host, deployer);

    EVMCorpusInitializer::new(
        &mut evm_executor,
        &mut scheduler,
        &infant_scheduler,
        &mut state
    ).initialize(config.contract_info);

    evm_executor.host.initialize(&mut state);

    // now evm executor is ready, we can clone it
    let cloned_evm = evm_executor.clone();
    let cloned_evm2 = evm_executor.clone();

    let mut executor = FuzzExecutor::new(Box::new(evm_executor), tuple_list!(jmp_observer));

    #[cfg(feature = "deployer_is_attacker")]
    state.add_deployer_to_callers(deployer);
    feedback
        .init_state(&mut state)
        .expect("Failed to init state");
    let infant_feedback = CmpFeedback::new(cmps, &infant_scheduler, Box::new(cloned_evm2));

    let oracles = config.oracle;

    let objective = OracleFeedback::new(&oracles, Box::new(cloned_evm));

    ItyFuzzer::new(
        scheduler,
        &infant_scheduler,
        feedback,
        infant_feedback,
        objective,
    )
    .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
    .expect("Fuzzing failed");
}
