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
pub mod tokens;
pub mod types;
pub mod utils;
pub mod vm;

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt,
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
use revm_primitives::B160;
// use revm_primitives::ruint::aliases::B160;
use serde::Deserialize;
use serde_json::json;
use tracing::debug;
use types::{EVMAddress, EVMFuzzState, EVMU256};
use vm::EVMState;

use self::types::EVMQueueExecutor;
use crate::{
    fuzzers::evm_fuzzer::evm_fuzzer,
    oracle::{Oracle, Producer},
    state::FuzzState,
};

pub const PRESET_WETH: &str = "0x4200000000000000000000000000000000000006";

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
#[derive(Parser, Debug, Default, Clone)]
#[command(author, version, about, long_about = None, trailing_var_arg = true, allow_hyphen_values = true)]
pub struct EvmArgs {
    /// Glob pattern / address to find contracts
    #[arg(short, long, default_value = "none")]
    target: String,

    #[arg(long, default_value = "false")]
    fetch_tx_data: bool,

    #[arg(long, default_value = "http://localhost:5001/data")]
    proxy_address: String,

    /// Constructor arguments for the contract, separated by semicolon. Example:
    /// https://docs.ityfuzz.rs/docs-evm-contract/constructor-for-offchain-fuzzing
    #[arg(long, default_value = "")]
    constructor_args: String,

    /// Target type (glob, address, anvil_fork, config, setup)
    /// (Default: Automatically infer from target)
    #[arg(long)]
    target_type: Option<String>,

    /// Onchain - Chain type
    /// (eth,goerli,sepolia,bsc,chapel,polygon,mumbai,fantom,avalanche,optimism,
    /// arbitrum,gnosis,base,celo,zkevm,zkevm_testnet,blast,local)
    #[arg(short = 'p', long)]
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

    /// Onchain which fetching method to use (dump, onebyone) (Default:
    /// onebyone)
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

    /// Only fuzz contracts with the addresses provided, separated by comma
    #[arg(long, default_value = "")]
    only_fuzz: String,

    /// Only needed when using combined.json (source map info).
    /// This is the base path when running solc compile (--base-path passed to
    /// solc). Also, please convert it to absolute path if you are not sure.
    #[arg(long, default_value = "")]
    base_path: String,

    /// Spec ID.
    /// Frontier,Homestead,Tangerine,Spurious,Byzantium,Constantinople,
    /// Petersburg,Istanbul,MuirGlacier,Berlin,London,Merge,Shanghai,Cancun,
    /// Latest
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

    /// Load corpus from crypo. If not specified, will use empty corpus.
    #[arg(long, short = 'l', default_value = None)]
    load_crypo_corpus: Option<String>,

    /// [DEPRECATED] Specify the setup file that deploys all the contract.
    /// Fuzzer invokes setUp() to deploy.
    #[arg(long, default_value = "")]
    setup_file: String,

    /// Specify the deployment script contract that deploys all the contract.
    /// Fuzzer invokes constructor or setUp() of this script to deploy.
    /// For example, if you have contract X in file Y that deploys all the
    /// contracts, you can specify --deployment-script Y:X
    #[arg(long, short = 'm', default_value = "")]
    deployment_script: String,

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

    #[arg(long, default_value = "")]
    base_directory: String,

    /// Command to build the contract. If specified, will use this command to
    /// build contracts instead of using bins and abis.
    #[arg()]
    build_command: Vec<String>,
}

impl fmt::Display for EvmArgs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EvmArgs {{\n")?;
        write!(f, "    target: {},\n", self.target)?;
        write!(f, "    fetch_tx_data: {},\n", self.fetch_tx_data)?;
        write!(f, "    proxy_address: {},\n", self.proxy_address)?;
        write!(f, "    constructor_args: {},\n", self.constructor_args)?;
        write!(f, "    target_type: {:?},\n", self.target_type)?;
        write!(f, "    chain_type: {:?},\n", self.chain_type)?;
        write!(f, "    onchain_block_number: {:?},\n", self.onchain_block_number)?;
        write!(f, "    onchain_url: {:?},\n", self.onchain_url)?;
        write!(f, "    onchain_chain_id: {:?},\n", self.onchain_chain_id)?;
        write!(f, "    onchain_explorer_url: {:?},\n", self.onchain_explorer_url)?;
        write!(f, "    onchain_chain_name: {:?},\n", self.onchain_chain_name)?;
        write!(
            f,
            "    onchain_etherscan_api_key: {:?},\n",
            self.onchain_etherscan_api_key
        )?;
        write!(f, "    onchain_storage_fetching: {},\n", self.onchain_storage_fetching)?;
        write!(f, "    concolic: {},\n", self.concolic)?;
        write!(f, "    concolic_caller: {},\n", self.concolic_caller)?;
        write!(f, "    concolic_timeout: {},\n", self.concolic_timeout)?;
        write!(f, "    concolic_num_threads: {},\n", self.concolic_num_threads)?;
        write!(f, "    flashloan: {},\n", self.flashloan)?;
        write!(f, "    panic_on_bug: {},\n", self.panic_on_bug)?;
        write!(f, "    detectors: {},\n", self.detectors)?;
        write!(f, "    replay_file: {:?},\n", self.replay_file)?;
        write!(f, "    work_dir: {},\n", self.work_dir)?;
        write!(f, "    write_relationship: {},\n", self.write_relationship)?;
        write!(f, "    run_forever: {},\n", self.run_forever)?;
        write!(f, "    seed: {},\n", self.seed)?;
        write!(f, "    sha3_bypass: {},\n", self.sha3_bypass)?;
        write!(f, "    only_fuzz: {},\n", self.only_fuzz)?;
        write!(f, "    base_path: {},\n", self.base_path)?;
        write!(f, "    spec_id: {},\n", self.spec_id)?;
        write!(f, "    onchain_builder: {},\n", self.onchain_builder)?;
        write!(
            f,
            "    onchain_replacements_file: {},\n",
            self.onchain_replacements_file
        )?;
        write!(f, "    builder_artifacts_url: {},\n", self.builder_artifacts_url)?;
        write!(f, "    builder_artifacts_file: {},\n", self.builder_artifacts_file)?;
        write!(f, "    offchain_config_url: {},\n", self.offchain_config_url)?;
        write!(f, "    offchain_config_file: {},\n", self.offchain_config_file)?;
        write!(f, "    load_corpus: {},\n", self.load_corpus)?;
        write!(f, "    setup_file: {},\n", self.setup_file)?;
        write!(f, "    deployment_script: {},\n", self.deployment_script)?;
        write!(f, "    force_abi: {},\n", self.force_abi)?;
        #[cfg(feature = "use_presets")]
        write!(f, "    preset_file_path: {},\n", self.preset_file_path)?;
        write!(f, "    base_directory: {},\n", self.base_directory)?;
        write!(f, "    build_command: {:?},\n", self.build_command)?;
        write!(f, "}}")
    }
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
pub fn evm_main(mut args: EvmArgs) {
    args.setup_file = args.deployment_script;
    let target = args.target.clone();
    if !args.base_directory.is_empty() {
        std::env::set_current_dir(args.base_directory).unwrap();
    }

    let work_dir = args.work_dir.clone();
    let work_path = Path::new(work_dir.as_str());
    let _ = std::fs::create_dir_all(work_path);

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
                    EVMQueueExecutor,
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
                    EVMQueueExecutor,
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

    if !args.builder_artifacts_url.is_empty() || !args.builder_artifacts_file.is_empty() || args.build_command.len() > 0
    {
        if onchain.is_some() {
            target_type = EVMTargetType::AnvilFork;
        } else if !args.setup_file.is_empty() {
            target_type = EVMTargetType::Setup;
        } else if !args.offchain_config_url.is_empty() || !args.offchain_config_file.is_empty() {
            target_type = EVMTargetType::Config;
        } else {
            panic!("Please specify --deployment-script (The contract that deploys the project) or --offchain-config-file (JSON for deploying the project)");
        }
    }

    let offchain_artifacts = if !args.builder_artifacts_url.is_empty() {
        Some(OffChainArtifact::from_json_url(args.builder_artifacts_url).expect("failed to parse builder artifacts"))
    } else if !args.builder_artifacts_file.is_empty() {
        Some(OffChainArtifact::from_file(args.builder_artifacts_file).expect("failed to parse builder artifacts"))
    } else if args.build_command.len() > 0 {
        let command = args.build_command.join(" ");
        Some(OffChainArtifact::from_command(command).expect("Failed to build the project"))
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
            &etherscan_api_key,
        ),
        EVMTargetType::Address => {
            if onchain.is_none() {
                panic!("Onchain is required for address target type");
            }
            let mut args_target = args.target.clone();

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
        etherscan_api_key,
        load_crypo_corpus: args.load_crypo_corpus,
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

    let abis_json = format!("{}/abis.json", args.work_dir.clone().as_str());

    utils::try_write_file(&abis_json, &json_str, true).unwrap();

    evm_fuzzer(config, &mut state)
}

// #[test]
fn test_evm_offchain_setup() {
    let mut args = EvmArgs {
        proxy_address: String::from("http://localhost:5001/data"),
        onchain_storage_fetching: String::from("onebyone"),
        concolic_timeout: 1000,
        detectors: String::from("high_confidence"),
        work_dir: String::from("work_dir"),
        seed: 1667840158231589000,
        spec_id: String::from("Latest"),
        // deployment_script: String::from("test/foundry/invariants/BaseInvariant.t.sol:BaseInvariant"),
        deployment_script: String::from("CounterLibByLibTest"),
        build_command: vec![String::from("forge"), String::from("build")],
        ..Default::default()
    };

    args.setup_file = args.deployment_script;
    if !args.base_directory.is_empty() {
        std::env::set_current_dir(args.base_directory).unwrap();
    }

    let work_dir = args.work_dir.clone();
    let work_path = Path::new(work_dir.as_str());
    let _ = std::fs::create_dir_all(work_path);

    let mut target_type: EVMTargetType = EVMTargetType::Setup;

    let erc20_producer = Rc::new(RefCell::new(ERC20Producer::new()));

    let flashloan_oracle = Rc::new(RefCell::new(IERC20OracleFlashloan::new(erc20_producer.clone())));

    let mut oracles: Vec<
        Rc<
            RefCell<
                dyn Oracle<
                    EVMState,
                    B160,
                    revm_primitives::Bytecode,
                    bytes::Bytes,
                    B160,
                    revm_primitives::ruint::Uint<256, 4>,
                    Vec<u8>,
                    EVMInput,
                    FuzzState<EVMInput, EVMState, B160, B160, Vec<u8>, ConciseEVMInput>,
                    ConciseEVMInput,
                    EVMQueueExecutor,
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
                    EVMQueueExecutor,
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

    let mut state: EVMFuzzState = FuzzState::new(args.seed);

    let builder = None;

    let offchain_artifacts = if !args.builder_artifacts_url.is_empty() {
        Some(OffChainArtifact::from_json_url(args.builder_artifacts_url).expect("failed to parse builder artifacts"))
    } else if !args.builder_artifacts_file.is_empty() {
        Some(OffChainArtifact::from_file(args.builder_artifacts_file).expect("failed to parse builder artifacts"))
    } else if args.build_command.len() > 0 {
        let command = args.build_command.join(" ");
        Some(OffChainArtifact::from_command(command).expect("Failed to build the project"))
    } else {
        None
    };

    let mut contract_loader = ContractLoader::from_setup(
        &offchain_artifacts.expect("offchain artifacts is required for config target type"),
        args.setup_file,
        args.work_dir.clone(),
        "",
    );

    let config = Config {
        contract_loader,
        only_fuzz: HashSet::new(),
        onchain: None,
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
        onchain_storage_fetching: None,
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
        etherscan_api_key: String::from(""),
        load_crypo_corpus: args.load_crypo_corpus,
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

    debug!("work_dir: {:?}", args.work_dir.clone().as_str());
    let abis_json = format!("{}/abis.json", args.work_dir.clone().as_str());

    utils::try_write_file(&abis_json, &json_str, true).unwrap();
    evm_fuzzer(config, &mut state)
}
