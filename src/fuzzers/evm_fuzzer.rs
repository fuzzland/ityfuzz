use bytes::Bytes;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::ops::Deref;
use std::path::Path;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;

use crate::{
    evm::contract_utils::{
        parse_buildjob_result_sourcemap, save_builder_source_code, FIX_DEPLOYER,
    },
    evm::host::FuzzHost,
    evm::{
        abi::BoxedABI,
        contract_utils::{copy_local_source_code, modify_concolic_skip},
        middlewares::{integer_overflow::IntegerOverflowMiddleware, reentrancy::ReentrancyTracer},
        oracle,
        oracles::{
            integer_overflow::IntegerOverflowOracle, invariant::InvariantOracle,
            reentrancy::ReentrancyOracle,
        },
        types::ProjectSourceMapTy,
        vm::EVMExecutor,
    },
    executor::FuzzExecutor,
    fuzzer::ItyFuzzer, scheduler::{PowerABIMutationalStage, PowerABIScheduler},
};
use itertools::Itertools;
use libafl::feedbacks::Feedback;
use libafl::prelude::HasMetadata;
use libafl::prelude::{QueueScheduler, SimpleEventManager};
use libafl::stages::{CalibrationStage, StdPowerMutationalStage};
use libafl::{
    prelude::{MaxMapFeedback, SimpleMonitor, StdMapObserver},
    Evaluator, Fuzzer,
};
use libafl_bolts::bolts_prelude::ShMemProvider;

use glob::glob;
use libafl_bolts::tuples::tuple_list;

use crate::evm::host::CALL_UNTIL;
use crate::evm::host::{
    ACTIVE_MATCH_EXT_CALL, CMP_MAP, JMP_MAP, PANIC_ON_BUG, READ_MAP, WRITE_MAP, WRITE_RELATIONSHIPS,
};
use crate::evm::minimizer::EVMMinimizer;
use crate::evm::vm::EVMState;
use crate::feedback::{CmpFeedback, DataflowFeedback, OracleFeedback};

use crate::scheduler::SortedDroppingScheduler;
use crate::state::{FuzzState, HasCaller, HasExecutionResult, HasPresets};
use crate::state_input::StagedVMState;

use crate::evm::config::Config;
use crate::evm::corpus_initializer::EVMCorpusInitializer;
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT, EVMInputTy};

use crate::evm::abi::ABIAddressToInstanceMap;
use crate::evm::blaz::builder::{ArtifactInfoMetadata, BuildJob};
use crate::evm::concolic::concolic_host::{ConcolicHost, CONCOLIC_TIMEOUT};
use crate::evm::concolic::concolic_stage::{ConcolicFeedbackWrapper, ConcolicStage};
use crate::evm::cov_stage::CoverageStage;
use crate::evm::feedbacks::Sha3WrappedFeedback;
use crate::evm::middlewares::call_printer::CallPrinter;
use crate::evm::middlewares::coverage::{Coverage, EVAL_COVERAGE};
use crate::evm::middlewares::middleware::Middleware;
use crate::evm::middlewares::sha3_bypass::{Sha3Bypass, Sha3TaintAnalysis};
use crate::evm::mutator::FuzzMutator;
use crate::evm::onchain::flashloan::Flashloan;
use crate::evm::onchain::onchain::{OnChain, WHITELIST_ADDR};
use crate::evm::oracles::arb_call::ArbitraryCallOracle;
use crate::evm::oracles::echidna::EchidnaOracle;
use crate::evm::oracles::selfdestruct::SelfdestructOracle;
use crate::evm::oracles::state_comp::StateCompOracle;
use crate::evm::oracles::typed_bug::TypedBugOracle;
use crate::evm::presets::{pair::PairPreset, presets::ExploitTemplate};
use crate::evm::srcmap::parser::{SourceMapLocation, BASE_PATH};
use crate::evm::types::{
    fixed_address, EVMAddress, EVMFuzzMutator, EVMFuzzState, EVMQueueExecutor, EVMU256,
};
use crate::fuzzer::{REPLAY, RUN_FOREVER};
use crate::input::{ConciseSerde, VMInputT};
use crate::oracle::BugMetadata;
use primitive_types::{H160, U256};
use revm_primitives::Bytecode;

pub fn evm_fuzzer(
    config: Config<
        EVMState,
        EVMAddress,
        Bytecode,
        Bytes,
        EVMAddress,
        EVMU256,
        Vec<u8>,
        EVMInput,
        EVMFuzzState,
        ConciseEVMInput,
    >,
    state: &mut EVMFuzzState,
) {
    println!("\n\n ================ EVM Fuzzer Start ===================\n\n");

    // create work dir if not exists
    let path = Path::new(config.work_dir.as_str());
    if !path.exists() {
        std::fs::create_dir(path).unwrap();
    }

    let monitor = SimpleMonitor::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);
    let infant_scheduler = SortedDroppingScheduler::new();
    let scheduler = PowerABIScheduler::new();

    let jmps = unsafe { &mut JMP_MAP };
    let cmps = unsafe { &mut CMP_MAP };
    let reads = unsafe { &mut READ_MAP };
    let writes = unsafe { &mut WRITE_MAP };
    let jmp_observer = unsafe { StdMapObserver::new("jmp", jmps) };

    let deployer = fixed_address(FIX_DEPLOYER);
    let mut fuzz_host = FuzzHost::new(scheduler.clone(), config.work_dir.clone());
    fuzz_host.set_spec_id(config.spec_id);

    #[allow(unused_variables)]
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

                if let Some(builder) = config.builder.clone() {
                    mid.borrow_mut().add_builder(builder);
                }

                println!("onchain middleware enabled");
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

    unsafe {
        BASE_PATH = config.base_path.clone();
    }

    if config.run_forever {
        unsafe {
            RUN_FOREVER = true;
        }
    }

    unsafe {
        PANIC_ON_BUG = config.panic_on_bug;
    }

    if !config.only_fuzz.is_empty() {
        unsafe {
            WHITELIST_ADDR = Some(config.only_fuzz.clone());
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
                onchain_middleware.clone().unwrap(),
                config.flashloan_oracle,
            ));
        }
    }
    let sha3_taint = Rc::new(RefCell::new(Sha3TaintAnalysis::new()));

    if config.sha3_bypass {
        println!("sha3 bypass enabled");
        fuzz_host.add_middlewares(Rc::new(RefCell::new(Sha3Bypass::new(sha3_taint.clone()))));
    }

    if config.reentrancy_oracle {
        println!("reentrancy oracle enabled");
        fuzz_host.add_middlewares(Rc::new(RefCell::new(ReentrancyTracer::new())));
    }

    if config.integer_overflow_oracle {
        fuzz_host.add_middlewares(Rc::new(RefCell::new(IntegerOverflowMiddleware::new())));
    }

    let mut evm_executor: EVMQueueExecutor = EVMExecutor::new(fuzz_host, deployer);

    if config.replay_file.is_some() {
        // add coverage middleware for replay
        unsafe {
            REPLAY = true;
        }
    }

    // moved here to ensure state has ArtifactInfoMetadata during corpus initialization
    if !state.has_metadata::<ArtifactInfoMetadata>() {
        state.add_metadata(ArtifactInfoMetadata::new());
    }
    let mut corpus_initializer = EVMCorpusInitializer::new(
        &mut evm_executor,
        scheduler.clone(),
        infant_scheduler.clone(),
        state,
        config.work_dir.clone(),
    );

    let mut artifacts = corpus_initializer.initialize(&mut config.contract_loader.clone());

    let mut instance_map = ABIAddressToInstanceMap::new();
    artifacts
        .address_to_abi_object
        .iter()
        .for_each(|(addr, abi)| {
            instance_map.map.insert(*addr, abi.clone());
        });

    #[cfg(feature = "use_presets")]
    {
        let (has_preset_match, matched_templates, sig_to_addr_abi_map): (
            bool,
            Vec<ExploitTemplate>,
            HashMap<[u8; 4], (EVMAddress, BoxedABI)>,
        ) = if config.preset_file_path.len() > 0 {
            let mut sig_to_addr_abi_map = HashMap::new();
            let exploit_templates = ExploitTemplate::from_filename(config.preset_file_path.clone());
            let mut matched_templates = vec![];
            for template in exploit_templates {
                // to match, all function_sigs in the template
                // must exists in all abi.function
                let mut function_sigs = template.function_sigs.clone();
                for (addr, abis) in &artifacts.address_to_abi_object {
                    for abi in abis {
                        for (idx, function_sig) in function_sigs.iter().enumerate() {
                            if abi.function == function_sig.value {
                                println!("matched: {:?} @ {:?}", abi.function, addr);
                                sig_to_addr_abi_map
                                    .insert(function_sig.value, (addr.clone(), abi.clone()));
                                function_sigs.remove(idx);
                                break;
                            }
                        }
                    }
                    if function_sigs.len() == 0 {
                        matched_templates.push(template);
                        break;
                    }
                }
            }

            if matched_templates.len() > 0 {
                (true, matched_templates, sig_to_addr_abi_map)
            } else {
                (false, vec![], HashMap::new())
            }
        } else {
            (false, vec![], HashMap::new())
        };
        println!(
            "has_preset_match: {} {}",
            has_preset_match,
            matched_templates.len()
        );

        state.init_presets(
            has_preset_match,
            matched_templates.clone(),
            sig_to_addr_abi_map,
        );
    }
    let cov_middleware = Rc::new(RefCell::new(Coverage::new(
        artifacts.address_to_sourcemap.clone(),
        artifacts.address_to_name.clone(),
        config.work_dir.clone(),
    )));

    evm_executor.host.add_middlewares(cov_middleware.clone());

    state.add_metadata(instance_map);

    evm_executor.host.initialize(state);

    // now evm executor is ready, we can clone it

    let evm_executor_ref = Rc::new(RefCell::new(evm_executor));

    let meta = state
        .metadata_map_mut()
        .get_mut::<ArtifactInfoMetadata>()
        .unwrap();
    for (addr, build_artifact) in &artifacts.build_artifacts {
        meta.add(*addr, build_artifact.clone());
    }

    for (addr, bytecode) in &mut artifacts.address_to_bytecode {
        unsafe {
            cov_middleware.deref().borrow_mut().on_insert(
                None,
                &mut evm_executor_ref.deref().borrow_mut().host,
                state,
                bytecode,
                *addr,
            );
        }
    }

    let mut feedback = MaxMapFeedback::new(&jmp_observer);
    feedback.init_state(state).expect("Failed to init state");
    // let calibration = CalibrationStage::new(&feedback);
    if config.concolic {
        unsafe { CONCOLIC_TIMEOUT = config.concolic_timeout };
    }

    let mut remote_addr_sourcemaps = ProjectSourceMapTy::new();
    for (addr, build_job_result) in &artifacts.build_artifacts {
        let sourcemap = parse_buildjob_result_sourcemap(build_job_result);
        remote_addr_sourcemaps.insert(*addr, Some(sourcemap));
    }

    // check if we use the remote or local
    let mut srcmap = if !remote_addr_sourcemaps.is_empty() {
        save_builder_source_code(&artifacts.build_artifacts, &config.work_dir);
        remote_addr_sourcemaps
    } else {
        match config.local_files_basedir_pattern {
            Some(pattern) => {
                // we copy the source files to the work dir
                copy_local_source_code(
                    &pattern,
                    &config.work_dir,
                    &artifacts.address_to_sourcemap,
                    &config.base_path,
                );
            }
            None => {
                // no local files, so we won't skip any concolic
            }
        }
        artifacts.address_to_sourcemap.clone()
    };

    modify_concolic_skip(&mut srcmap, config.work_dir.clone());
    let concolic_stage = ConcolicStage::new(
        config.concolic,
        config.concolic_caller,
        evm_executor_ref.clone(),
        srcmap,
        config.concolic_num_threads,
    );
    let mutator: EVMFuzzMutator = FuzzMutator::new(infant_scheduler.clone());

    let std_stage = PowerABIMutationalStage::new(mutator);

    let call_printer_mid = Rc::new(RefCell::new(CallPrinter::new(
        artifacts.address_to_name.clone(),
        artifacts.address_to_sourcemap.clone(),
    )));

    let coverage_obs_stage = CoverageStage::new(
        evm_executor_ref.clone(),
        cov_middleware.clone(),
        call_printer_mid.clone(),
        config.work_dir.clone(),
    );

    let mut stages = tuple_list!(std_stage, concolic_stage, coverage_obs_stage);

    let mut executor = FuzzExecutor::new(evm_executor_ref.clone(), tuple_list!(jmp_observer));

    #[cfg(feature = "deployer_is_attacker")]
    state.add_caller(&deployer);
    let infant_feedback =
        CmpFeedback::new(cmps, infant_scheduler.clone(), evm_executor_ref.clone());
    let infant_result_feedback = DataflowFeedback::new(reads, writes);

    let mut oracles = config.oracle;

    if config.echidna_oracle {
        let echidna_oracle = EchidnaOracle::new(
            artifacts
                .address_to_abi
                .iter()
                .flat_map(|(address, abis)| {
                    abis.iter()
                        .filter(|abi| abi.function_name.starts_with("echidna_") && abi.abi == "()")
                        .map(|abi| (*address, abi.function.to_vec()))
                        .collect_vec()
                })
                .collect_vec(),
            artifacts
                .address_to_abi
                .iter()
                .flat_map(|(_address, abis)| {
                    abis.iter()
                        .filter(|abi| abi.function_name.starts_with("echidna_") && abi.abi == "()")
                        .map(|abi| (abi.function.to_vec(), abi.function_name.clone()))
                        .collect_vec()
                })
                .collect::<HashMap<Vec<u8>, String>>(),
        );
        oracles.push(Rc::new(RefCell::new(echidna_oracle)));
    }

    if config.invariant_oracle {
        let invariant_oracle = InvariantOracle::new(
            artifacts
                .address_to_abi
                .iter()
                .flat_map(|(address, abis)| {
                    abis.iter()
                        .filter(|abi| {
                            abi.function_name.starts_with("invariant_") && abi.abi == "()"
                        })
                        .map(|abi| (*address, abi.function.to_vec()))
                        .collect_vec()
                })
                .collect_vec(),
            artifacts
                .address_to_abi
                .iter()
                .flat_map(|(_address, abis)| {
                    abis.iter()
                        .filter(|abi| {
                            abi.function_name.starts_with("invariant_") && abi.abi == "()"
                        })
                        .map(|abi| (abi.function.to_vec(), abi.function_name.clone()))
                        .collect_vec()
                })
                .collect::<HashMap<Vec<u8>, String>>(),
        );
        oracles.push(Rc::new(RefCell::new(invariant_oracle)));
    }

    if let Some(path) = config.state_comp_oracle {
        let mut file = File::open(path.clone()).expect("Failed to open state comp oracle file");
        let mut buf = String::new();
        file.read_to_string(&mut buf)
            .expect("Failed to read state comp oracle file");

        let evm_state = serde_json::from_str::<EVMState>(buf.as_str())
            .expect("Failed to parse state comp oracle file");

        let oracle = Rc::new(RefCell::new(StateCompOracle::new(
            evm_state,
            config.state_comp_matching.unwrap(),
        )));
        oracles.push(oracle);
    }

    if config.arbitrary_external_call {
        oracles.push(Rc::new(RefCell::new(ArbitraryCallOracle::new(
            artifacts.address_to_sourcemap.clone(),
            artifacts.address_to_name.clone(),
        ))));
    }

    if config.typed_bug {
        oracles.push(Rc::new(RefCell::new(TypedBugOracle::new(
            artifacts.address_to_sourcemap.clone(),
            artifacts.address_to_name.clone(),
        ))));
    }

    state.add_metadata(BugMetadata::new());

    if config.selfdestruct_oracle {
        oracles.push(Rc::new(RefCell::new(SelfdestructOracle::new(
            artifacts.address_to_sourcemap.clone(),
            artifacts.address_to_name.clone(),
        ))));
    }

    if config.reentrancy_oracle {
        oracles.push(Rc::new(RefCell::new(ReentrancyOracle::new(
            artifacts.address_to_sourcemap.clone(),
            artifacts.address_to_name.clone(),
        ))));
    }

    if config.integer_overflow_oracle {
        oracles.push(Rc::new(RefCell::new(IntegerOverflowOracle::new(
            artifacts.address_to_sourcemap.clone(),
            artifacts.address_to_name.clone(),
        ))));
    }

    if let Some(m) = onchain_middleware {
        m.borrow_mut().add_abi(artifacts.address_to_abi.clone());
    }

    let mut producers = config.producers;

    let objective: OracleFeedback<
        '_,
        EVMState,
        revm_primitives::B160,
        Bytecode,
        Bytes,
        revm_primitives::B160,
        revm_primitives::ruint::Uint<256, 4>,
        Vec<u8>,
        EVMInput,
        FuzzState<
            EVMInput,
            EVMState,
            revm_primitives::B160,
            revm_primitives::B160,
            Vec<u8>,
            ConciseEVMInput,
        >,
        ConciseEVMInput,
    > = OracleFeedback::new(&mut oracles, &mut producers, evm_executor_ref.clone());
    let wrapped_feedback = ConcolicFeedbackWrapper::new(Sha3WrappedFeedback::new(
        feedback,
        sha3_taint,
        evm_executor_ref.clone(),
        config.sha3_bypass,
    ));

    let mut fuzzer: ItyFuzzer<_, _, _, _, _, _, _, _, _, _, _, _, _, _, EVMMinimizer> =
        ItyFuzzer::new(
            scheduler,
            infant_scheduler,
            wrapped_feedback,
            infant_feedback,
            infant_result_feedback,
            objective,
            EVMMinimizer::new(evm_executor_ref.clone()),
            config.work_dir,
        );
    match config.replay_file {
        None => {
            fuzzer
                .fuzz_loop(&mut stages, &mut executor, state, &mut mgr)
                .expect("Fuzzing failed");
        }
        Some(files) => {
            unsafe {
                EVAL_COVERAGE = true;
            }

            let printer = Rc::new(RefCell::new(CallPrinter::new(
                artifacts.address_to_name.clone(),
                artifacts.address_to_sourcemap.clone(),
            )));
            evm_executor_ref
                .borrow_mut()
                .host
                .add_middlewares(printer.clone());

            let initial_vm_state = artifacts.initial_state.clone();
            for file in glob(files.as_str()).expect("Failed to read glob pattern") {
                let mut f = File::open(file.expect("glob issue")).expect("Failed to open file");
                let mut transactions = String::new();
                f.read_to_string(&mut transactions)
                    .expect("Failed to read file");

                let mut vm_state = initial_vm_state.clone();

                let mut idx = 0;

                for txn in transactions.split("\n") {
                    idx += 1;
                    // let splitter = txn.split(" ").collect::<Vec<&str>>();
                    if txn.len() < 4 {
                        continue;
                    }
                    println!("============ Execution {} ===============", idx);

                    // [is_step] [caller] [target] [input] [value]
                    let temp = txn.as_bytes();
                    let temp = ConciseEVMInput::deserialize_concise(temp);
                    let (inp, call_until) = temp.to_input(vm_state.clone());
                    printer.borrow_mut().cleanup();

                    unsafe {
                        CALL_UNTIL = call_until;
                    }

                    fuzzer
                        .evaluate_input_events(state, &mut executor, &mut mgr, inp, false)
                        .unwrap();

                    println!("============ Execution result {} =============", idx);
                    println!(
                        "reverted: {:?}",
                        state.get_execution_result().clone().reverted
                    );
                    println!("call trace:\n{}", printer.deref().borrow().get_trace());
                    println!(
                        "output: {:?}",
                        hex::encode(state.get_execution_result().clone().output)
                    );

                    // println!(
                    //     "new_state: {:?}",
                    //     state.get_execution_result().clone().new_state.state
                    // );

                    vm_state = state.get_execution_result().new_state.clone();
                    println!("================================================");
                }
            }

            // dump coverage:
            cov_middleware.borrow_mut().record_instruction_coverage();
            // unsafe {
            //     EVAL_COVERAGE = false;
            //     CALL_UNTIL = u32::MAX;
            // }

            // fuzzer
            //     .fuzz_loop(&mut stages, &mut executor, state, &mut mgr)
            //     .expect("Fuzzing failed");
        }
    }
}
