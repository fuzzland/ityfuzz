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
pub mod minimizer;
pub mod mutator;
pub mod onchain;
pub mod oracle;
pub mod oracles;
pub mod presets;
pub mod producers;
pub mod scheduler;
pub mod solution;
pub mod srcmap;
pub mod types;
pub mod uniswap;
pub mod utils;
pub mod vm;

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fs::OpenOptions,
    io::Write,
    path::Path,
    rc::Rc,
    str::FromStr,
};

use blaz::{
    builder::{BuildJob, BuildJobResult},
    offchain_artifacts::OffChainArtifact,
    offchain_config::OffchainConfig,
};
use clap::Parser;
use config::{Config, StorageFetchingMode};
use contract_utils::ContractLoader;
use ethers::types::Transaction;
use input::{ConciseEVMInput, EVMInput};
use itertools::Itertools;
use num_cpus;
use onchain::endpoints::{Chain, OnChainConfig};
use oracles::{erc20::IERC20OracleFlashloan, v2_pair::PairBalanceOracle};
use producers::erc20::ERC20Producer;
use serde::Deserialize;
use serde_json::json;
use types::{EVMAddress, EVMFuzzState, EVMU256};
use vm::EVMState;

use crate::{
    fuzzers::evm_fuzzer::evm_fuzzer,
    oracle::{Oracle, Producer},
    state::FuzzState,
};

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

    /// Onchain - Chain type (ETH, BSC, POLYGON, MUMBAI)
    #[arg(short, long)]
    chain_type: Option<String>,

    /// Onchain - Block number (Default: 0 / latest)
    #[arg(long, short = 'b')]
    onchain_block_number: Option<u64>,

    /// Onchain Customize - RPC endpoint URL (Default: inferred from
    /// chain-type), Example: https://rpc.ankr.com/eth
    #[arg(long, short = 'u')]
    onchain_url: Option<String>,

    /// Onchain Customize - Chain ID (Default: inferred from chain-type)
    #[arg(long, short = 'i')]
    onchain_chain_id: Option<u32>,

    /// Onchain Customize - Block explorer URL (Default: inferred from
    /// chain-type), Example: https://api.etherscan.io/api
    #[arg(long, short = 'e')]
    onchain_explorer_url: Option<String>,

    /// Onchain Customize - Chain name (used as Moralis handle of chain)
    /// (Default: inferred from chain-type)
    #[arg(long, short = 'n')]
    onchain_chain_name: Option<String>,

    /// Onchain Etherscan API Key (Default: None)
    #[arg(long, short = 'k')]
    onchain_etherscan_api_key: Option<String>,

    /// Onchain which fetching method to use (All, Dump, OneByOne) (Default:
    /// OneByOne)
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

    /// Number of threads for concolic execution (Default: number of cpus)
    #[arg(long, default_value = "0")]
    concolic_num_threads: usize,

    /// Enable flashloan
    #[arg(short, long, default_value = "false")]
    flashloan: bool,

    /// Panic when a typed_bug() is called (Default: false)
    #[arg(long, default_value = "false")]
    panic_on_bug: bool,

    /// Detectors enabled (all, high_confidence, ...). Refer to https://docs.ityfuzz.rs/docs-evm-contract/detecting-common-vulns
    /// (Default: high_confidence)
    #[arg(long, short, default_value = "high_confidence")]
    detectors: String, // <- internally this is known as oracles

    // /// Matching style for state comparison oracle (Select from "Exact",
    // /// "DesiredContain", "StateContain")
    // #[arg(long, default_value = "Exact")]
    // state_comp_matching: String,
    /// Replay?
    #[arg(long, short)]
    replay_file: Option<String>,

    /// Path of work dir, saves corpus, logs, and other stuffs
    #[arg(long, short, default_value = "work_dir")]
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

    /// Whether bypass all SHA3 comparisons, this may break original logic of
    /// contracts  (Experimental)
    #[arg(long, default_value = "false")]
    sha3_bypass: bool,

    /// Only fuzz contracts with the addresses, separated by comma
    #[arg(long, default_value = "")]
    only_fuzz: String,

    /// Only needed when using combined.json (source map info).
    /// This is the base path when running solc compile (--base-path passed to
    /// solc). Also, please convert it to absolute path if you are not sure.
    #[arg(long, default_value = "")]
    base_path: String,

    /// Spec ID
    #[arg(long, default_value = "Latest")]
    spec_id: String,

    /// Builder URL. If specified, will use this builder to build contracts
    /// instead of using bins and abis.
    #[arg(long, default_value = "")]
    onchain_builder: String,

    /// Replacement config (replacing bytecode) for onchain campaign
    #[arg(long, default_value = "")]
    onchain_replacements_file: String,

    /// Builder Artifacts url. If specified, will use this artifact to derive
    /// code coverage.
    #[arg(long, default_value = "")]
    builder_artifacts_url: String,

    /// Builder Artifacts file. If specified, will use this artifact to derive
    /// code coverage.
    #[arg(long, default_value = "")]
    builder_artifacts_file: String,

    /// Offchain Config Url. If specified, will deploy based on offchain config
    /// file.
    #[arg(long, default_value = "")]
    offchain_config_url: String,

    /// Offchain Config File. If specified, will deploy based on offchain config
    /// file.
    #[arg(long, default_value = "")]
    offchain_config_file: String,

    /// Load corpus from directory. If not specified, will use empty corpus.
    #[arg(long, default_value = "")]
    load_corpus: String,

    /// Specify the setup file that deploys all the contract. Fuzzer invokes
    /// setUp() to deploy.
    #[arg(long, default_value = "")]
    setup_file: String,

    /// Forcing a contract to use the given abi. This is useful when the
    /// contract is a complex proxy or decompiler has trouble to detect the abi.
    /// Format: address:abi_file,...
    #[arg(long, default_value = "")]
    force_abi: String,

    /// Preset file. If specified, will load the preset file and match past
    /// exploit template.
    #[cfg(feature = "use_presets")]
    #[arg(long, default_value = "")]
    preset_file_path: String,
}

enum EVMTargetType {
    Glob,
    Address,
    AnvilFork,
    Config,
    Setup,
}

impl EVMTargetType {
    fn as_str(&self) -> &'static str {
        match self {
            EVMTargetType::Glob => "glob",
            EVMTargetType::Address => "address",
            EVMTargetType::AnvilFork => "anvil_fork",
            EVMTargetType::Config => "config",
            EVMTargetType::Setup => "setup",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "glob" => EVMTargetType::Glob,
            "address" => EVMTargetType::Address,
            "anvil_fork" => EVMTargetType::AnvilFork,
            "config" => EVMTargetType::Config,
            "setup" => EVMTargetType::Setup,
            _ => panic!("Invalid target type"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OracleType {
    ERC20,
    Pair,
    Reentrancy,
    ArbitraryCall,
    MathCalculate,
    Echidna,
    StateComparison,
    TypedBug,
    SelfDestruct,
    Invariant,
}

impl OracleType {
    fn as_str(&self) -> &'static str {
        match self {
            OracleType::ERC20 => "erc20",
            OracleType::Pair => "pair",
            OracleType::Reentrancy => "reentrancy",
            OracleType::ArbitraryCall => "arbitrary_call",
            OracleType::MathCalculate => "math_calculate",
            OracleType::Echidna => "echidna",
            OracleType::StateComparison => "state_comparison",
            OracleType::TypedBug => "typed_bug",
            OracleType::SelfDestruct => "selfdestruct",
            OracleType::Invariant => "invariant",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "erc20" => OracleType::ERC20,
            "pair" => OracleType::Pair,
            "reentrancy" => OracleType::Reentrancy,
            "arbitrary_call" => OracleType::ArbitraryCall,
            "math_calculate" => OracleType::MathCalculate,
            "echidna" => OracleType::Echidna,
            "state_comparison" => OracleType::StateComparison,
            "typed_bug" => OracleType::TypedBug,
            "selfdestruct" => OracleType::SelfDestruct,
            "invariant" => OracleType::Invariant,
            _ => panic!("Invalid detector type: {}", s),
        }
    }

    fn from_strs(s: &str) -> Vec<Self> {
        let mut results = Vec::new();

        for detector in s.split(',') {
            let detector = detector.trim();
            if detector.is_empty() {
                continue;
            }

            if detector == "all" {
                return vec![
                    OracleType::ERC20,
                    OracleType::Pair,
                    OracleType::Reentrancy,
                    OracleType::ArbitraryCall,
                    OracleType::MathCalculate,
                    OracleType::Echidna,
                    OracleType::StateComparison,
                    OracleType::TypedBug,
                    OracleType::SelfDestruct,
                ];
            }
            if detector == "high_confidence" {
                return vec![
                    OracleType::ERC20,
                    OracleType::Pair,
                    OracleType::ArbitraryCall,
                    OracleType::Echidna,
                    OracleType::TypedBug,
                    OracleType::SelfDestruct,
                    OracleType::Invariant,
                ];
            }

            results.push(OracleType::from_str(detector));
        }
        results
    }
}

#[allow(clippy::type_complexity)]
pub fn evm_main(args: EvmArgs) {
    let target = args.target.clone();
    let work_dir = args.work_dir.clone();
    let work_path = Path::new(work_dir.as_str());
    if !work_path.exists() {
        std::fs::create_dir(work_path).unwrap();
    }

    let mut target_type: EVMTargetType = match args.target_type {
        Some(v) => EVMTargetType::from_str(v.as_str()),
        None => {
            // infer target type from args
            if args.target.starts_with("0x") {
                EVMTargetType::Address
            } else {
                EVMTargetType::Glob
            }
        }
    };

    let is_onchain = args.chain_type.is_some() || args.onchain_url.is_some();

    let mut onchain = if is_onchain {
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

    solution::init_cli_args(target, work_dir, &onchain);
    let _onchain_clone = onchain.clone();

    let etherscan_api_key = match args.onchain_etherscan_api_key {
        Some(v) => v,
        None => std::env::var("ETHERSCAN_API_KEY").unwrap_or_default(),
    };

    if onchain.is_some() && !etherscan_api_key.is_empty() {
        onchain.as_mut().unwrap().etherscan_api_key = etherscan_api_key.split(',').map(|s| s.to_string()).collect();
    }
    let erc20_producer = Rc::new(RefCell::new(ERC20Producer::new()));

    let flashloan_oracle = Rc::new(RefCell::new(IERC20OracleFlashloan::new(erc20_producer.clone())));

    // let harness_code = "oracle_harness()";
    // let mut harness_hash: [u8; 4] = [0; 4];
    // set_hash(harness_code, &mut harness_hash);
    // let mut function_oracle =
    //     FunctionHarnessOracle::new_no_condition(EVMAddress::zero(),
    // Vec::from(harness_hash));

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

    let oracle_types = OracleType::from_strs(args.detectors.as_str());

    if oracle_types.contains(&OracleType::Pair) {
        oracles.push(Rc::new(RefCell::new(PairBalanceOracle::new())));
    }

    if oracle_types.contains(&OracleType::ERC20) {
        oracles.push(flashloan_oracle.clone());
        producers.push(erc20_producer);
    }

    let is_onchain = onchain.is_some();
    let mut state: EVMFuzzState = FuzzState::new(args.seed);

    let mut proxy_deploy_codes: Vec<String> = vec![];

    if args.fetch_tx_data {
        let response = reqwest::blocking::get(args.proxy_address).unwrap().text().unwrap();
        let data: Vec<Data> = serde_json::from_str(&response).unwrap();

        for d in data {
            if d.body.method != "eth_sendRawTransaction" {
                continue;
            }

            let tx = d.body.params.unwrap();

            let params: Vec<String> = serde_json::from_value(tx).unwrap();

            let data = params[0].clone();

            let data = if let Some(stripped) = data.strip_prefix("0x") {
                stripped
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

    let onchain_replacements = if !args.onchain_replacements_file.is_empty() {
        BuildJobResult::from_multi_file(args.onchain_replacements_file)
    } else {
        HashMap::new()
    };

    let builder = if args.onchain_builder.len() > 1 {
        Some(BuildJob::new(
            args.onchain_builder,
            onchain_replacements,
            args.work_dir.clone(),
        ))
    } else {
        None
    };

    if !args.builder_artifacts_url.is_empty() || !args.builder_artifacts_file.is_empty() {
        if onchain.is_some() {
            target_type = EVMTargetType::AnvilFork;
        } else if !args.setup_file.is_empty() {
            target_type = EVMTargetType::Setup;
        } else if !args.offchain_config_url.is_empty() || !args.offchain_config_file.is_empty() {
            target_type = EVMTargetType::Config;
        } else {
            panic!("Builder artifacts is provided, but missing offchain_config_*, Anvil config, or setup_file");
        }
    }

    let offchain_artifacts = if !args.builder_artifacts_url.is_empty() {
        Some(OffChainArtifact::from_json_url(args.builder_artifacts_url).expect("failed to parse builder artifacts"))
    } else if !args.builder_artifacts_file.is_empty() {
        Some(OffChainArtifact::from_file(args.builder_artifacts_file).expect("failed to parse builder artifacts"))
    } else {
        None
    };
    let offchain_config = if !args.offchain_config_url.is_empty() {
        Some(OffchainConfig::from_json_url(args.offchain_config_url).expect("failed to parse offchain config"))
    } else if !args.offchain_config_file.is_empty() {
        Some(OffchainConfig::from_file(args.offchain_config_file).expect("failed to parse offchain config"))
    } else {
        None
    };

    let force_abis = args
        .force_abi
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|x| {
            let runes = x.split(':').collect_vec();
            assert_eq!(runes.len(), 2, "Invalid force abi format");
            let abi = std::fs::read_to_string(runes[1]).expect("Failed to read abi file");
            (runes[0].to_string(), abi)
        })
        .collect::<HashMap<_, _>>();

    let mut contract_loader = match target_type {
        EVMTargetType::Glob => ContractLoader::from_glob(
            args.target.as_str(),
            &mut state,
            &proxy_deploy_codes,
            &constructor_args_map,
            args.target.clone(),
            Some(args.base_path.clone()),
        ),
        EVMTargetType::Config => ContractLoader::from_config(
            &offchain_artifacts.expect("offchain artifacts is required for config target type"),
            &offchain_config.expect("offchain config is required for config target type"),
        ),
        EVMTargetType::AnvilFork => {
            let addresses: Vec<EVMAddress> = args
                .target
                .split(',')
                .map(|s| EVMAddress::from_str(s).unwrap())
                .collect();
            ContractLoader::from_fork(
                &offchain_artifacts.expect("offchain artifacts is required for config target type"),
                onchain.as_mut().expect("onchain is required to fork anvil"),
                HashSet::from_iter(addresses),
            )
        }
        EVMTargetType::Setup => ContractLoader::from_setup(
            &offchain_artifacts.expect("offchain artifacts is required for config target type"),
            args.setup_file,
            args.work_dir.clone(),
        ),
        EVMTargetType::Address => {
            if onchain.is_none() {
                panic!("Onchain is required for address target type");
            }
            let mut args_target = args.target.clone();

            if oracle_types.contains(&OracleType::ERC20) || args.flashloan {
                const ETH_ADDRESS: &str = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d";
                const BSC_ADDRESS: &str = "0x10ed43c718714eb63d5aa57b78b54704e256024e";
                if "bsc" == onchain.as_ref().unwrap().chain_name {
                    if !args_target.contains(BSC_ADDRESS) {
                        args_target.push(',');
                        args_target.push_str(BSC_ADDRESS);
                    }
                } else if "eth" == onchain.as_ref().unwrap().chain_name && !args_target.contains(ETH_ADDRESS) {
                    args_target.push(',');
                    args_target.push_str(ETH_ADDRESS);
                }
            }
            let addresses: Vec<EVMAddress> = args_target
                .split(',')
                .map(|s| EVMAddress::from_str(s).unwrap())
                .collect();
            ContractLoader::from_address(
                onchain.as_mut().unwrap(),
                HashSet::from_iter(addresses),
                builder.clone(),
            )
        }
    };

    contract_loader.force_abi(force_abis);

    let config = Config {
        contract_loader,
        only_fuzz: if !args.only_fuzz.is_empty() {
            args.only_fuzz
                .split(',')
                .map(|s| EVMAddress::from_str(s).expect("failed to parse only fuzz"))
                .collect()
        } else {
            HashSet::new()
        },
        onchain,
        concolic: args.concolic,
        concolic_caller: args.concolic_caller,
        concolic_timeout: args.concolic_timeout,
        concolic_num_threads: {
            if args.concolic_num_threads == 0 {
                num_cpus::get()
            } else {
                args.concolic_num_threads
            }
        },
        oracle: oracles,
        producers,
        flashloan: args.flashloan,
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
        selfdestruct_oracle: oracle_types.contains(&OracleType::SelfDestruct),
        reentrancy_oracle: oracle_types.contains(&OracleType::Reentrancy),
        work_dir: args.work_dir.clone(),
        write_relationship: args.write_relationship,
        run_forever: args.run_forever,
        sha3_bypass: args.sha3_bypass,
        base_path: args.base_path,
        echidna_oracle: oracle_types.contains(&OracleType::Echidna),
        invariant_oracle: oracle_types.contains(&OracleType::Invariant),
        panic_on_bug: args.panic_on_bug,
        spec_id: args.spec_id,
        typed_bug: oracle_types.contains(&OracleType::TypedBug),
        arbitrary_external_call: oracle_types.contains(&OracleType::ArbitraryCall),
        math_calculate_oracle: oracle_types.contains(&OracleType::MathCalculate),
        builder,
        local_files_basedir_pattern: match target_type {
            EVMTargetType::Glob => Some(args.target),
            _ => None,
        },
        #[cfg(feature = "use_presets")]
        preset_file_path: args.preset_file_path,
        load_corpus: args.load_corpus,
    };

    let mut abis_map: HashMap<String, Vec<Vec<serde_json::Value>>> = HashMap::new();

    for contract_info in config.contract_loader.contracts.clone() {
        let abis: Vec<serde_json::Value> = contract_info
            .abi
            .iter()
            .map(|config| {
                json!({
                    hex::encode(config.function): format!("{}{}", &config.function_name, &config.abi)
                })
            })
            .collect();
        abis_map
            .entry(hex::encode(contract_info.deployed_address))
            .or_default()
            .push(abis);
    }

    let json_str = serde_json::to_string(&abis_map).expect("Failed to serialize ABI map to JSON");

    let work_dir = args.work_dir.clone();

    let abis_json = format!("{}/abis.json", args.work_dir.clone().as_str());

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(abis_json)
        .expect("Failed to open or create abis.json");

    writeln!(file, "{}", json_str).expect("Failed to write abis to abis.json");
    evm_fuzzer(config, &mut state)
}
