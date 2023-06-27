use bytes::Bytes;
use std::cell::RefCell;
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
use libafl::prelude::ShMemProvider;
use libafl::prelude::{QueueScheduler, SimpleEventManager};
use libafl::stages::{CalibrationStage, StdMutationalStage};
use libafl::{
    prelude::{tuple_list, MaxMapFeedback, SimpleMonitor, StdMapObserver},
    Evaluator, Fuzzer,
};
use glob::glob;

use crate::evm::host::{ACTIVE_MATCH_EXT_CALL, CMP_MAP, JMP_MAP, WRITE_RELATIONSHIPS};
use crate::evm::host::{CALL_UNTIL};
use crate::evm::vm::EVMState;
use crate::feedback::{CmpFeedback, OracleFeedback};

use crate::scheduler::SortedDroppingScheduler;
use crate::state::{FuzzState, HasCaller, HasExecutionResult};
use crate::state_input::StagedVMState;

use crate::evm::config::Config;
use crate::evm::corpus_initializer::EVMCorpusInitializer;
use crate::evm::input::{EVMInput, EVMInputTy};

use crate::evm::mutator::{AccessPattern, FuzzMutator};
use crate::evm::onchain::flashloan::Flashloan;
use crate::evm::onchain::onchain::OnChain;
use crate::evm::presets::pair::PairPreset;
use crate::evm::types::{EVMAddress, EVMFuzzMutator, EVMFuzzState, EVMU256, fixed_address};
use primitive_types::{H160, U256};
use revm_primitives::{BlockEnv, Bytecode, Env};
use revm_primitives::bitvec::view::BitViewSized;
use crate::evm::middlewares::instruction_coverage::InstructionCoverage;

struct ABIConfig {
    abi: String,
    function: [u8; 4],
}

struct ContractInfo {
    name: String,
    abi: Vec<ABIConfig>,
}

pub fn evm_fuzzer(
    config: Config<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState>, state: &mut EVMFuzzState
) {
    // create work dir if not exists
    let path = Path::new(config.work_dir.as_str());
    if !path.exists() {
        std::fs::create_dir(path).unwrap();
    }

    let cov_middleware = Rc::new(RefCell::new(InstructionCoverage::new()));

    let monitor = SimpleMonitor::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);
    let infant_scheduler = SortedDroppingScheduler::new();

    let jmps = unsafe { &mut JMP_MAP };
    let cmps = unsafe { &mut CMP_MAP };
    let jmp_observer = StdMapObserver::new("jmp_labels", jmps);
    let mut feedback = MaxMapFeedback::new(&jmp_observer);
    let calibration = CalibrationStage::new(&feedback);

    let mut scheduler = QueueScheduler::new();

    let mutator: EVMFuzzMutator<'_> = FuzzMutator::new(&infant_scheduler);

    let std_stage = StdMutationalStage::new(mutator);
    let mut stages = tuple_list!(calibration, std_stage);
    let deployer = fixed_address(FIX_DEPLOYER);
    let mut fuzz_host = FuzzHost::new(Arc::new(scheduler.clone()), config.work_dir.clone());
    fuzz_host.set_concolic_enabled(config.concolic);

    let onchain_middleware = match config.onchain.clone() {
        Some(onchain) => {
            Some({
                let mid = Rc::new(RefCell::new(
                    OnChain::<EVMState, EVMInput, EVMFuzzState>::new(
                        // scheduler can be cloned because it never uses &mut self
                        onchain,
                        config.onchain_storage_fetching.unwrap(),
                    ),
                ));
                fuzz_host.add_middlewares(mid.clone());
                mid
            })
        }
        None => {
            // enable active match for offchain fuzzing (todo: handle this more elegantly)
            unsafe {
                ACTIVE_MATCH_EXT_CALL = true;
            }
            None
        }
    };

    if config.write_relationship {
        unsafe {
            WRITE_RELATIONSHIPS = true;
        }
    }

    if config.flashloan {
        // we should use real balance of tokens in the contract instead of providing flashloan
        // to contract as well for on chain env
        #[cfg(not(feature = "flashloan_v2"))]
        fuzz_host.add_middlewares(Rc::new(RefCell::new(Flashloan::<
            EVMState,
            EVMInput,
            EVMFuzzState,
        >::new(
            config.onchain.is_some()
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
                onchain_middleware.unwrap(),
                config.flashloan_oracle,
            ));
        }
    }

    let mut evm_executor: EVMExecutor<EVMInput, EVMFuzzState, EVMState> =
        EVMExecutor::new(fuzz_host, deployer);

    if config.replay_file.is_some() {
        // add coverage middleware for replay
        evm_executor.host.add_middlewares(cov_middleware.clone());
    }

    let mut corpus_initializer = EVMCorpusInitializer::new(
        &mut evm_executor,
        &mut scheduler,
        &infant_scheduler,
        state,
    );

    #[cfg(feature = "use_presets")]
    corpus_initializer.register_preset(&PairPreset {});

    corpus_initializer.initialize(config.contract_info);

    evm_executor.host.initialize(state);

    // now evm executor is ready, we can clone it

    let evm_executor_ref = Rc::new(RefCell::new(evm_executor));

    let mut executor = FuzzExecutor::new(evm_executor_ref.clone(), tuple_list!(jmp_observer));

    #[cfg(feature = "deployer_is_attacker")]
    state.add_caller(&deployer);
    feedback
        .init_state(state)
        .expect("Failed to init state");
    let infant_feedback = CmpFeedback::new(cmps, &infant_scheduler, evm_executor_ref.clone());

    let mut oracles = config.oracle;
    let mut producers = config.producers;

    let objective = OracleFeedback::new(&mut oracles, &mut producers, evm_executor_ref.clone());

    let mut fuzzer = ItyFuzzer::new(
        scheduler,
        &infant_scheduler,
        feedback,
        infant_feedback,
        objective,
        config.work_dir,
    );
    match config.replay_file {
        None => {
            fuzzer
                .fuzz_loop(&mut stages, &mut executor, state, &mut mgr)
                .expect("Fuzzing failed");
        }
        Some(files) => {
            for file in glob(files.as_str()).expect("Failed to read glob pattern") {
                let mut f = File::open(file.expect("glob issue")).expect("Failed to open file");
                let mut transactions = String::new();
                f.read_to_string(&mut transactions)
                    .expect("Failed to read file");

                let mut vm_state = StagedVMState::new_with_state(EVMState::new());

                let mut idx = 0;

                for txn in transactions.split("\n") {
                    idx += 1;
                    let splitter = txn.split(" ").collect::<Vec<&str>>();
                    if splitter.len() < 4 {
                        continue;
                    }

                    // [is_step] [caller] [target] [input] [value]
                    unsafe {CALL_UNTIL = u32::MAX;}

                    let inp = match splitter[0] {
                        "abi" => {
                            let caller = EVMAddress::from_str(splitter[1]).unwrap();
                            let contract = EVMAddress::from_str(splitter[2]).unwrap();
                            let input = hex::decode(splitter[3]).unwrap();
                            let value = EVMU256::from_str_radix(splitter[4], 10).unwrap();
                            let liquidation_percent = splitter[5].parse::<u8>().unwrap_or(0);
                            let warp_to = splitter[6].parse::<u64>().unwrap_or(0);
                            let repeat = splitter[7].parse::<usize>().unwrap_or(0);
                            let reentrancy_call_limits = splitter[8].parse::<u32>().unwrap_or(u32::MAX);
                            let is_step = splitter[9].parse::<bool>().unwrap_or(false);

                            unsafe {CALL_UNTIL = reentrancy_call_limits;}
                            EVMInput {
                                caller,
                                contract,
                                data: None,
                                sstate: vm_state.clone(),
                                sstate_idx: 0,
                                txn_value: if value == EVMU256::ZERO {
                                    None
                                } else {
                                    Some(value)
                                },
                                step: is_step,
                                env: Env {
                                    cfg: Default::default(),
                                    block: BlockEnv {
                                        number: EVMU256::from(warp_to),
                                        coinbase: Default::default(),
                                        timestamp: EVMU256::from(warp_to * 1000),
                                        difficulty: Default::default(),
                                        prevrandao: None,
                                        basefee: Default::default(),
                                        gas_limit: Default::default(),
                                    },
                                    tx: Default::default(),
                                },
                                access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                                #[cfg(feature = "flashloan_v2")]
                                liquidation_percent,

                                #[cfg(feature = "flashloan_v2")]
                                input_type: EVMInputTy::ABI,
                                direct_data: if input.len() == 1 && input[0] == 0 {
                                    Bytes::new()
                                } else {
                                    Bytes::from(input.clone())
                                },
                                randomness: vec![],
                                repeat,
                            }
                        }
                        "borrow" => {
                            let caller = EVMAddress::from_str(splitter[1]).unwrap();
                            let contract = EVMAddress::from_str(splitter[2]).unwrap();
                            let randomness = hex::decode(splitter[3]).unwrap();
                            let value = EVMU256::from_str(splitter[4]).unwrap();
                            let _liquidation_percent = splitter[5].parse::<u8>().unwrap_or(0);
                            let warp_to = splitter[6].parse::<u64>().unwrap_or(0);
                            EVMInput {
                                caller,
                                contract,
                                data: None,
                                sstate: vm_state.clone(),
                                sstate_idx: 0,
                                txn_value: if value == EVMU256::ZERO {
                                    None
                                } else {
                                    Some(value)
                                },
                                step: false,
                                env: Env {
                                    cfg: Default::default(),
                                    block: BlockEnv {
                                        number: EVMU256::from(warp_to),
                                        coinbase: Default::default(),
                                        timestamp: EVMU256::from(warp_to * 1000),
                                        difficulty: Default::default(),
                                        prevrandao: None,
                                        basefee: Default::default(),
                                        gas_limit: Default::default(),
                                    },
                                    tx: Default::default(),
                                },
                                access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                                #[cfg(feature = "flashloan_v2")]
                                liquidation_percent: 0,
                                #[cfg(feature = "flashloan_v2")]
                                input_type: EVMInputTy::Borrow,
                                direct_data: Bytes::new(),
                                randomness,
                                repeat: 1,
                            }
                        }
                        _ => {
                            unreachable!()
                        }
                    };

                    fuzzer
                        .evaluate_input_events(state, &mut executor, &mut mgr, inp, false)
                        .unwrap();

                    println!("============ Execution result {} =============", idx);
                    println!(
                        "reverted: {:?}",
                        state.get_execution_result().clone().reverted
                    );
                    println!(
                        "trace: {:?}",
                        state.get_execution_result().clone().new_state.trace
                    );
                    println!(
                        "output: {:?}",
                        hex::encode(state.get_execution_result().clone().output)
                    );
                    println!("================================================");

                    vm_state = state.get_execution_result().new_state.clone();
                }
            }

            // dump coverage:
            cov_middleware.borrow_mut().record_instruction_coverage();
        }
    }
}
