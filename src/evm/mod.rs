pub mod abi;
pub mod blaz;
pub mod bytecode_analyzer;
pub mod bytecode_iterator;
pub mod concolic;
pub mod config;
pub mod contract_utils;
pub mod corpus_initializer;
pub mod cov_stage;
pub mod feedbacks;
pub mod host;
pub mod input;
pub mod middlewares;
pub mod mutator;
pub mod onchain;
pub mod oracle;
pub mod oracles;
pub mod presets;
pub mod producers;
pub mod srcmap;
pub mod types;
pub mod uniswap;
pub mod vm;

use crate::fuzzers::evm_fuzzer::evm_fuzzer;
use crate::oracle::{Oracle, Producer};
use crate::state::FuzzState;
use blaz::builder::{BuildJob, BuildJobResult};
use blaz::offchain_artifacts::OffChainArtifact;
use blaz::offchain_config::OffchainConfig;
use clap::Parser;
use config::{Config, FuzzerTypes, StorageFetchingMode};
use contract_utils::ContractLoader;
use ethers::types::Transaction;
use input::{ConciseEVMInput, EVMInput};
use onchain::endpoints::{Chain, OnChainConfig};
use onchain::flashloan::DummyPriceOracle;
use oracles::erc20::IERC20OracleFlashloan;
use oracles::v2_pair::PairBalanceOracle;
use producers::erc20::ERC20Producer;
use producers::pair::PairProducer;
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::rc::Rc;
use std::str::FromStr;
use types::{EVMAddress, EVMFuzzState, EVMU256};
use vm::EVMState;

pub fn parse_constructor_args_string(input: String) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();

    if input.is_empty() {
        return map;
    }

    let pairs: Vec<&str> = input.split(';').collect();
    for pair in pairs {
        let key_value: Vec<&str> = pair.split(':').collect();
        if key_value.len() == 2 {
            let values: Vec<String> = key_value[1].split(',').map(|s| s.to_string()).collect();
            map.insert(key_value[0].to_string(), values);
        }
    }

    map
}

#[derive(Deserialize)]
struct Data {
    body: RPCCall,
}

#[derive(Deserialize)]
struct RPCCall {
    method: String,
    params: Option<serde_json::Value>,
}

/// CLI for ItyFuzz for EVM smart contracts
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct EvmArgs {
    /// Glob pattern / address to find contracts
    #[arg(short, long)]
    target: String,

    #[arg(long, default_value = "false")]
    fetch_tx_data: bool,

    #[arg(long, default_value = "http://localhost:5001/data")]
    proxy_address: String,

    #[arg(long, default_value = "")]
    constructor_args: String,

    /// Target type (glob, address) (Default: Automatically infer from target)
    #[arg(long)]
    target_type: Option<String>,

    /// Fuzzer type
    #[arg(long, default_value = "cmp")]
    fuzzer_type: String,

    /// Enable onchain
    #[arg(short, long, default_value = "false")]
    onchain: bool,

    /// Onchain - Chain type (ETH, BSC, POLYGON, MUMBAI)
    #[arg(short, long)]
    chain_type: Option<String>,

    /// Onchain - Block number (Default: 0 / latest)
    #[arg(long)]
    onchain_block_number: Option<u64>,

    /// Onchain Customize - Endpoint URL (Default: inferred from chain-type)
    #[arg(long)]
    onchain_url: Option<String>,

    /// Onchain Customize - Chain ID (Default: inferred from chain-type)
    #[arg(long)]
    onchain_chain_id: Option<u32>,

    /// Onchain Customize - Block explorer URL (Default: inferred from chain-type)
    #[arg(long)]
    onchain_explorer_url: Option<String>,

    /// Onchain Customize - Chain name (used as Moralis handle of chain) (Default: inferred from chain-type)
    #[arg(long)]
    onchain_chain_name: Option<String>,

    /// Onchain Etherscan API Key (Default: None)
    #[arg(long)]
    onchain_etherscan_api_key: Option<String>,

    /// Onchain Local Proxy Address (Default: None)
    #[arg(long)]
    onchain_local_proxy_addr: Option<String>,

    /// Onchain which fetching method to use (All, Dump, OneByOne) (Default: OneByOne)
    #[arg(long, default_value = "onebyone")]
    onchain_storage_fetching: String,

    /// Enable Concolic (Experimental)
    #[arg(long, default_value = "false")]
    concolic: bool,

    /// Support Treating Caller as Symbolically  (Experimental)
    #[arg(long, default_value = "false")]
    concolic_caller: bool,

    /// Time limit for concolic execution (ms) (Default: 1000, 0 for no limit)
    #[arg(long, default_value = "1000")]
    concolic_timeout: u32,

    /// Enable flashloan
    #[arg(short, long, default_value = "false")]
    flashloan: bool,

    /// Flashloan price oracle (onchain/dummy) (Default: DummyPriceOracle)
    #[arg(long, default_value = "dummy")]
    flashloan_price_oracle: String,

    /// Enable ierc20 oracle
    #[arg(short, long, default_value = "false")]
    ierc20_oracle: bool,

    /// Enable pair oracle
    #[arg(short, long, default_value = "false")]
    pair_oracle: bool,

    /// Panic when a typed_bug() is called (Default: false)
    #[arg(long, default_value = "false")]
    panic_on_bug: bool,

    /// Detect selfdestruct (Default: true)
    #[arg(long, default_value = "true")]
    selfdestruct_oracle: bool,

    /// Detect pontential reentrancy vulnerability (Default: falss)
    #[arg(long, default_value = "false")]
    reentrancy_oracle: bool,

    #[arg(long, default_value = "true")]
    arbitrary_external_call_oracle: bool,

    #[arg(long, default_value = "true")]
    echidna_oracle: bool,

    ///Enable oracle for detecting whether bug() / typed_bug() is called
    #[arg(long, default_value = "true")]
    typed_bug_oracle: bool,

    /// Setting any string here will enable state comparison oracle.
    /// This arg holds file path pointing to state comparison oracle's desired state
    #[arg(long, default_value = "")]
    state_comp_oracle: String,

    /// Matching style for state comparison oracle (Select from "Exact", "DesiredContain", "StateContain")
    #[arg(long, default_value = "Exact")]
    state_comp_matching: String,

    /// Replay?
    #[arg(long)]
    replay_file: Option<String>,

    /// Path of work dir, saves corpus, logs, and other stuffs
    #[arg(long, default_value = "work_dir")]
    work_dir: String,

    /// Write contract relationship to files
    #[arg(long, default_value = "false")]
    write_relationship: bool,

    /// Do not quit when a bug is found, continue find new bugs
    #[arg(long, default_value = "false")]
    run_forever: bool,

    /// random seed
    #[arg(long, default_value = "1667840158231589000")]
    seed: u64,

    /// Whether bypass all SHA3 comparisons, this may break original logic of contracts  (Experimental)
    #[arg(long, default_value = "false")]
    sha3_bypass: bool,

    /// Only fuzz contracts with the addresses, separated by comma
    #[arg(long, default_value = "")]
    only_fuzz: String,

    /// Only needed when using combined.json (source map info).
    /// This is the base path when running solc compile (--base-path passed to solc).
    /// Also, please convert it to absolute path if you are not sure.
    #[arg(long, default_value = "")]
    base_path: String,

    /// Spec ID
    #[arg(long, default_value = "Latest")]
    spec_id: String,

    /// Builder URL. If specified, will use this builder to build contracts instead of using
    /// bins and abis.
    #[arg(long, default_value = "")]
    onchain_builder: String,

    /// Replacement config (replacing bytecode) for onchain campaign
    #[arg(long, default_value = "")]
    onchain_replacements_file: String,

    /// Builder Artifacts url. If specified, will use this artifact to derive code coverage.
    #[arg(long, default_value = "")]
    builder_artifacts_url: String,

    /// Builder Artifacts file. If specified, will use this artifact to derive code coverage.
    #[arg(long, default_value = "")]
    builder_artifacts_file: String,

    /// Offchain Config Url. If specified, will deploy based on offchain config file.
    #[arg(long, default_value = "")]
    offchain_config_url: String,

    /// Offchain Config File. If specified, will deploy based on offchain config file.
    #[arg(long, default_value = "")]
    offchain_config_file: String,
}

enum EVMTargetType {
    Glob,
    Address,
    ArtifactAndProxy,
    Config,
}

pub fn evm_main(args: EvmArgs) {
    let mut target_type: EVMTargetType = match args.target_type {
        Some(v) => match v.as_str() {
            "glob" => EVMTargetType::Glob,
            "address" => EVMTargetType::Address,
            _ => {
                panic!("Invalid target type")
            }
        },
        None => {
            if args.target.starts_with("0x") {
                EVMTargetType::Address
            } else {
                EVMTargetType::Glob
            }
        }
    };

    let mut onchain = if args.onchain {
        match args.chain_type {
            Some(chain_str) => {
                let chain = Chain::from_str(&chain_str).expect("Invalid chain type");
                let block_number = args.onchain_block_number.unwrap_or(0);
                Some(OnChainConfig::new(chain, block_number))
            }
            None => Some(OnChainConfig::new_raw(
                args.onchain_url
                    .expect("You need to either specify chain type or chain rpc"),
                args.onchain_chain_id
                    .expect("You need to either specify chain type or chain id"),
                args.onchain_block_number.unwrap_or(0),
                args.onchain_explorer_url
                    .expect("You need to either specify chain type or block explorer url"),
                args.onchain_chain_name
                    .expect("You need to either specify chain type or chain name"),
            )),
        }
    } else {
        None
    };

    let onchain_clone = onchain.clone();

    let etherscan_api_key = match args.onchain_etherscan_api_key {
        Some(v) => v,
        None => std::env::var("ETHERSCAN_API_KEY").unwrap_or_default(),
    };

    if onchain.is_some() && !etherscan_api_key.is_empty() {
        onchain.as_mut().unwrap().etherscan_api_key = etherscan_api_key
            .split(',')
            .map(|s| s.to_string())
            .collect();
    }
    let pair_producer = Rc::new(RefCell::new(PairProducer::new()));
    let erc20_producer = Rc::new(RefCell::new(ERC20Producer::new()));

    let flashloan_oracle = Rc::new(RefCell::new({
        IERC20OracleFlashloan::new(pair_producer.clone(), erc20_producer.clone())
    }));

    // let harness_code = "oracle_harness()";
    // let mut harness_hash: [u8; 4] = [0; 4];
    // set_hash(harness_code, &mut harness_hash);
    // let mut function_oracle =
    //     FunctionHarnessOracle::new_no_condition(EVMAddress::zero(), Vec::from(harness_hash));

    let mut oracles: Vec<
        Rc<
            RefCell<
                dyn Oracle<
                    EVMState,
                    revm_primitives::B160,
                    revm_primitives::Bytecode,
                    bytes::Bytes,
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
                >,
            >,
        >,
    > = vec![];

    let mut producers: Vec<
        Rc<
            RefCell<
                dyn Producer<
                    EVMState,
                    EVMAddress,
                    _,
                    _,
                    EVMAddress,
                    EVMU256,
                    Vec<u8>,
                    EVMInput,
                    EVMFuzzState,
                    ConciseEVMInput,
                >,
            >,
        >,
    > = vec![];

    if args.pair_oracle {
        oracles.push(Rc::new(RefCell::new(PairBalanceOracle::new(
            pair_producer.clone(),
        ))));
    }

    if args.ierc20_oracle {
        oracles.push(flashloan_oracle.clone());
    }

    if args.ierc20_oracle || args.pair_oracle {
        producers.push(pair_producer);
    }

    if args.ierc20_oracle {
        producers.push(erc20_producer);
    }

    let is_onchain = onchain.is_some();
    let mut state: EVMFuzzState = FuzzState::new(args.seed);

    let mut proxy_deploy_codes: Vec<String> = vec![];

    if args.fetch_tx_data {
        let response = reqwest::blocking::get(args.proxy_address)
            .unwrap()
            .text()
            .unwrap();
        let data: Vec<Data> = serde_json::from_str(&response).unwrap();

        for d in data {
            if d.body.method != "eth_sendRawTransaction" {
                continue;
            }

            let tx = d.body.params.unwrap();

            let params: Vec<String> = serde_json::from_value(tx).unwrap();

            let data = params[0].clone();

            let data = if data.starts_with("0x") {
                &data[2..]
            } else {
                &data
            };

            let bytes_data = hex::decode(data).unwrap();

            let transaction: Transaction = rlp::decode(&bytes_data).unwrap();

            let code = hex::encode(transaction.input);

            proxy_deploy_codes.push(code);
        }
    }

    let constructor_args_map = parse_constructor_args_string(args.constructor_args);

    let onchain_replacements = if args.onchain_replacements_file.len() > 0 {
        BuildJobResult::from_multi_file(args.onchain_replacements_file)
    } else {
        HashMap::new()
    };

    let builder = if args.onchain_builder.len() > 1 {
        Some(BuildJob::new(args.onchain_builder, onchain_replacements))
    } else {
        None
    };

    let offchain_artifacts = if args.builder_artifacts_url.len() > 0 {
        target_type = EVMTargetType::ArtifactAndProxy;
        Some(
            OffChainArtifact::from_json_url(args.builder_artifacts_url)
                .expect("failed to parse builder artifacts"),
        )
    } else if args.builder_artifacts_file.len() > 0 {
        target_type = EVMTargetType::ArtifactAndProxy;
        Some(
            OffChainArtifact::from_file(args.builder_artifacts_file)
                .expect("failed to parse builder artifacts"),
        )
    } else {
        None
    };
    let offchain_config = if args.offchain_config_url.len() > 0 {
        target_type = EVMTargetType::Config;
        Some(
            OffchainConfig::from_json_url(args.offchain_config_url)
                .expect("failed to parse offchain config"),
        )
    } else if args.offchain_config_file.len() > 0 {
        target_type = EVMTargetType::Config;
        Some(
            OffchainConfig::from_file(args.offchain_config_file)
                .expect("failed to parse offchain config"),
        )
    } else {
        None
    };

    let config = Config {
        fuzzer_type: FuzzerTypes::from_str(args.fuzzer_type.as_str()).expect("unknown fuzzer"),
        contract_loader: match target_type {
            EVMTargetType::Glob => ContractLoader::from_glob(
                args.target.as_str(),
                &mut state,
                &proxy_deploy_codes,
                &constructor_args_map,
            ),
            EVMTargetType::Config => ContractLoader::from_config(
                &offchain_artifacts.expect("offchain artifacts is required for config target type"),
                &offchain_config.expect("offchain config is required for config target type"),
            ),

            EVMTargetType::ArtifactAndProxy => {
                // ContractLoader::from_artifacts_and_proxy(
                //     &offchain_artifacts.expect("offchain artifacts is required for artifact and proxy target type"),
                //     &proxy_deploy_codes,
                // )
                todo!("Artifact and proxy is not supported yet")
            }
            EVMTargetType::Address => {
                if onchain.is_none() {
                    panic!("Onchain is required for address target type");
                }
                let mut args_target = args.target.clone();

                if args.ierc20_oracle || args.flashloan {
                    const ETH_ADDRESS: &str = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d";
                    const BSC_ADDRESS: &str = "0x10ed43c718714eb63d5aa57b78b54704e256024e";
                    if "bsc" == onchain.as_ref().unwrap().chain_name {
                        if args_target.find(BSC_ADDRESS) == None {
                            args_target.push_str(",");
                            args_target.push_str(BSC_ADDRESS);
                        }
                    } else if "eth" == onchain.as_ref().unwrap().chain_name {
                        if args_target.find(ETH_ADDRESS) == None {
                            args_target.push_str(",");
                            args_target.push_str(ETH_ADDRESS);
                        }
                    }
                }
                let addresses: Vec<EVMAddress> = args_target
                    .split(",")
                    .map(|s| EVMAddress::from_str(s).unwrap())
                    .collect();
                ContractLoader::from_address(
                    &mut onchain.as_mut().unwrap(),
                    HashSet::from_iter(addresses),
                    builder.clone(),
                )
            }
        },
        only_fuzz: if args.only_fuzz.len() > 0 {
            args.only_fuzz
                .split(",")
                .map(|s| EVMAddress::from_str(s).expect("failed to parse only fuzz"))
                .collect()
        } else {
            HashSet::new()
        },
        onchain,
        concolic: args.concolic,
        concolic_caller: args.concolic_caller,
        concolic_timeout: args.concolic_timeout,
        oracle: oracles,
        producers,
        flashloan: args.flashloan,
        price_oracle: match args.flashloan_price_oracle.as_str() {
            "onchain" => {
                Box::new(onchain_clone.expect("onchain unavailable but used for flashloan"))
            }
            _ => Box::new(DummyPriceOracle {}),
        },
        onchain_storage_fetching: if is_onchain {
            Some(
                StorageFetchingMode::from_str(args.onchain_storage_fetching.as_str())
                    .expect("unknown storage fetching mode"),
            )
        } else {
            None
        },
        replay_file: args.replay_file,
        flashloan_oracle,
        selfdestruct_oracle: args.selfdestruct_oracle,
        reentrancy_oracle: args.reentrancy_oracle,
        state_comp_matching: if args.state_comp_oracle.len() > 0 {
            Some(args.state_comp_matching)
        } else {
            None
        },
        state_comp_oracle: if args.state_comp_oracle.len() > 0 {
            Some(args.state_comp_oracle)
        } else {
            None
        },
        work_dir: args.work_dir,
        write_relationship: args.write_relationship,
        run_forever: args.run_forever,
        sha3_bypass: args.sha3_bypass,
        base_path: args.base_path,
        echidna_oracle: args.echidna_oracle,
        panic_on_bug: args.panic_on_bug,
        spec_id: args.spec_id,
        typed_bug: args.typed_bug_oracle,
        selfdestruct_bug: args.selfdestruct_oracle,
        arbitrary_external_call: args.arbitrary_external_call_oracle,
        builder,
        local_files_basedir_pattern: match target_type {
            EVMTargetType::Glob => Some(args.target),
            _ => None,
        },
    };

    match config.fuzzer_type {
        FuzzerTypes::CMP => evm_fuzzer(config, &mut state),
        // FuzzerTypes::BASIC => basic_fuzzer(config)
        _ => {}
    }
    //
    //     Some(v) => {
    //         match v.as_str() {
    //             "cmp" => {
    //                 cmp_fuzzer(&String::from(args.target), args.target_contract);
    //             }
    //             "df" => {
    //                 df_fuzzer(&String::from(args.target), args.target_contract);
    //             }
    //             _ => {
    //                 println!("Fuzzer type not supported");
    //             }
    //         }
    //     },
    //     _ => {
    //         df_fuzzer(&String::from(args.target), args.target_contract);
    //     }
    // }
}
