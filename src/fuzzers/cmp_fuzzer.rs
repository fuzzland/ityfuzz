use std::cell::RefCell;
use std::fs::File;
use std::io::Read;
use std::rc::Rc;
use bytes::Bytes;
use std::str::FromStr;
use std::sync::Arc;

use crate::{
    evm::contract_utils::FIX_DEPLOYER,
    evm::vm::{EVMExecutor, FuzzHost, JMP_MAP},
    executor::FuzzExecutor,
    fuzzer::ItyFuzzer,
    rand_utils::fixed_address,
};
use libafl::feedbacks::Feedback;
use libafl::prelude::{powersched::PowerSchedule, QueueScheduler, SimpleEventManager};
use libafl::prelude::{PowerQueueScheduler, ShMemProvider};
use libafl::stages::{CalibrationStage, Stage, StdMutationalStage};
use libafl::{prelude::{tuple_list, MaxMapFeedback, SimpleMonitor, StdMapObserver}, stages::StdPowerMutationalStage, Fuzzer, Evaluator};

use crate::evm::contract_utils::{set_hash, ContractLoader};
use crate::evm::oracle::{FunctionHarnessOracle, IERC20OracleFlashloan};
use crate::evm::vm::{EVMState, CMP_MAP};
use crate::feedback::{CmpFeedback, OracleFeedback};
use crate::rand_utils::generate_random_address;
use crate::scheduler::SortedDroppingScheduler;
use crate::state::{FuzzState, HasExecutionResult, InfantStateState};
use crate::state_input::StagedVMState;

use crate::evm::config::Config;
use crate::evm::corpus_initializer::EVMCorpusInitializer;
use crate::evm::input::{AccessPattern, EVMInput};
use crate::evm::middleware::Middleware;
use crate::evm::mutator::FuzzMutator;
use crate::evm::onchain::flashloan::Flashloan;
use crate::evm::onchain::onchain::OnChain;
use crate::evm::types::{EVMFuzzMutator, EVMFuzzState};
use primitive_types::{H160, U256};
use revm::Bytecode;

struct ABIConfig {
    abi: String,
    function: [u8; 4],
}

struct ContractInfo {
    name: String,
    abi: Vec<ABIConfig>,
}

pub fn cmp_fuzzer(
    config: Config<EVMState, H160, Bytecode, Bytes, H160, U256, Vec<u8>, EVMInput, EVMFuzzState>,
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

    let mut scheduler = QueueScheduler::new();

    let mutator: EVMFuzzMutator<'_> = FuzzMutator::new(&infant_scheduler);

    let std_stage = StdMutationalStage::new(mutator);
    let mut stages = tuple_list!(calibration, std_stage);
    let deployer = fixed_address(FIX_DEPLOYER);
    let mut fuzz_host = FuzzHost::new(Arc::new(scheduler.clone()));

    match config.concolic_prob {
        Some(prob) => fuzz_host.set_concolic_prob(prob),
        None => {}
    }

    let onchain_middleware = match config.onchain.clone() {
        Some(onchain) => {
            Some({
                let mut mid = Rc::new(RefCell::new(OnChain::<EVMState, EVMInput, EVMFuzzState>::new(
                    // scheduler can be cloned because it never uses &mut self
                    onchain,
                    config.onchain_storage_fetching.unwrap(),
                )));
                fuzz_host.add_middlewares(mid.clone());
                mid
            })
        }
        None => { None }
    };

    if config.flashloan {
        // we should use real balance of tokens in the contract instead of providing flashloan
        // to contract as well for on chain env
        #[cfg(not(feature = "flashloan_v2"))]
        fuzz_host.add_middlewares(Rc::new(RefCell::new(Flashloan::<EVMState, EVMInput, EVMFuzzState>::new(
            config.onchain.is_some(),
        ))));

        #[cfg(feature = "flashloan_v2")]
        {
            assert!(
                onchain_middleware.is_some(),
                "Flashloan v2 requires onchain env"
            );
            fuzz_host.add_flashloan_middleware(Flashloan::<EVMState, EVMInput, EVMFuzzState>::new(
                true,
                config.onchain.clone().unwrap(),
                config.price_oracle,
                onchain_middleware.unwrap()
            ));
        }
    }


    let mut evm_executor: EVMExecutor<EVMInput, EVMFuzzState, EVMState> =
        EVMExecutor::new(fuzz_host, deployer);

    EVMCorpusInitializer::new(
        &mut evm_executor,
        &mut scheduler,
        &infant_scheduler,
        &mut state,
    )
    .initialize(config.contract_info);

    evm_executor.host.initialize(&mut state);

    // now evm executor is ready, we can clone it

    let evm_executor_ref = Rc::new(RefCell::new(evm_executor));

    let mut executor = FuzzExecutor::new(evm_executor_ref.clone(), tuple_list!(jmp_observer));

    #[cfg(feature = "deployer_is_attacker")]
    state.add_deployer_to_callers(deployer);
    feedback
        .init_state(&mut state)
        .expect("Failed to init state");
    let infant_feedback = CmpFeedback::new(cmps, &infant_scheduler, evm_executor_ref.clone());

    let mut oracles = config.oracle;

    let objective = OracleFeedback::new(&mut oracles, evm_executor_ref.clone());

    let mut fuzzer = ItyFuzzer::new(
        scheduler,
        &infant_scheduler,
        feedback,
        infant_feedback,
        objective,
    );
    match config.debug_file {
        None => {
            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                .expect("Fuzzing failed");
        }
        Some(file) => {
            let mut f = File::open(file).expect("Failed to open file");
            let mut transactions = String::new();
            f.read_to_string(&mut transactions).expect("Failed to read file");

            let mut vm_state = StagedVMState::new_with_state(EVMState::new());

            for txn in transactions.split("\n") {
                let splitter = txn.split(" ").collect::<Vec<&str>>();

                // [is_step] [caller] [target] [input] [value]

                let is_step = splitter[0] == "step";
                let caller = H160::from_str(splitter[1]).unwrap();
                let contract = H160::from_str(splitter[1]).unwrap();
                let input = hex::decode(splitter[3]).unwrap();
                let value = splitter[4].parse::<usize>().unwrap();


                fuzzer.evaluate_input_events(
                    &mut state, &mut executor, &mut mgr, EVMInput {
                        caller,
                        contract,
                        data: None,
                        sstate: vm_state.clone(),
                        sstate_idx: 0,
                        txn_value: if value == 0 { None } else { Some(value) },
                        step: is_step,
                        env: Default::default(),
                        access_pattern: AccessPattern::new(),

                        #[cfg(any(test, feature = "debug"))]
                        direct_data: Bytes::from(input.clone()),

                    },
                    false
                ).unwrap();

                vm_state = state.get_execution_result().new_state.clone();
            }
        }
    }
}
