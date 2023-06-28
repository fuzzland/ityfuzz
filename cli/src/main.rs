use crate::TargetType::{Address, Glob};
use clap::Parser;
use ityfuzz::evm::config::{Config, FuzzerTypes, StorageFetchingMode};
use ityfuzz::evm::contract_utils::{set_hash, ContractLoader};
use ityfuzz::evm::input::EVMInput;
use ityfuzz::evm::middlewares::middleware::Middleware;
use ityfuzz::evm::onchain::endpoints::{Chain, OnChainConfig};
use ityfuzz::evm::onchain::flashloan::{DummyPriceOracle, Flashloan};
use ityfuzz::evm::oracles::bug::BugOracle;
use ityfuzz::evm::oracles::selfdestruct::SelfdestructOracle;
use ityfuzz::evm::oracles::erc20::IERC20OracleFlashloan;
use ityfuzz::evm::oracles::v2_pair::PairBalanceOracle;
use ityfuzz::evm::producers::erc20::ERC20Producer;
use ityfuzz::evm::producers::pair::PairProducer;
use ityfuzz::evm::types::{EVMAddress, EVMFuzzState, EVMU256};
use ityfuzz::evm::vm::EVMState;
use ityfuzz::fuzzers::evm_fuzzer::evm_fuzzer;
use ityfuzz::oracle::{Oracle, Producer};
use ityfuzz::state::FuzzState;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::str::FromStr;
use std::env;
use ityfuzz::evm::host::PANIC_ON_BUG;
use ityfuzz::evm::host::PANIC_ON_TYPEDBUG;
use ityfuzz::evm::oracles::typed_bug::TypedBugOracle;

pub fn init_sentry() {
    let _guard = sentry::init(("https://96f3517bd77346ea835d28f956a84b9d@o4504503751344128.ingest.sentry.io/4504503752523776", sentry::ClientOptions {
        release: sentry::release_name!(),
        ..Default::default()
    }));
    if let Ok(value) = env::var("NO_TELEMETRY") {
        if value == "1" {
            println!("Telemetry is disabled.");
            unsafe {
                ityfuzz::telemetry::TELEMETRY_ENABLED = false;
            }
        }
    }
}

/// CLI for ItyFuzz
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Glob pattern / address to find contracts
    #[arg(short, long)]
    target: String,

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

    /// Enable Concolic
    #[arg(long, default_value = "false")]
    concolic: bool,

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

    // Enable oracle for detecting whether bug() is called
    #[arg(long, default_value = "true")]
    bug_oracle: bool,

    #[arg(long, default_value = "false")]
    panic_on_bug: bool,

    #[arg(long, default_value = "true")]
    selfdestruct_oracle: bool,
  
    ///Enable oracle for detecting whether typed_bug() is called
    #[arg(long, default_value = "true")]
    typed_bug_oracle: bool,

    #[arg(long, default_value = "false")]
    panic_on_typedbug: bool,

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

    // random seed
    #[arg(long, default_value = "1667840158231589000")]
    seed: u64,
}

enum TargetType {
    Glob,
    Address,
}

fn main() {
    init_sentry();
    let args = Args::parse();
    ityfuzz::telemetry::report_campaign(args.onchain, args.target.clone());
    let target_type: TargetType = match args.target_type {
        Some(v) => match v.as_str() {
            "glob" => Glob,
            "address" => Address,
            _ => {
                panic!("Invalid target type")
            }
        },
        None => {
            if args.target.starts_with("0x") {
                Address
            } else {
                Glob
            }
        }
    };

    let mut onchain = if args.onchain {
        match args.chain_type {
            Some(chain_str) => {
                let chain = Chain::from_str(&chain_str).expect("Invalid chain type");
                let block_number = args.onchain_block_number.unwrap();
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

    if onchain.is_some() && args.onchain_etherscan_api_key.is_some() {
        onchain
            .as_mut()
            .unwrap()
            .etherscan_api_key
            .push(args.onchain_etherscan_api_key.unwrap());
    }
    let pair_producer = Rc::new(RefCell::new(PairProducer::new()));
    let erc20_producer = Rc::new(RefCell::new(ERC20Producer::new()));

    let mut flashloan_oracle = Rc::new(RefCell::new({
        IERC20OracleFlashloan::new(pair_producer.clone(), erc20_producer.clone())
    }));

    // let harness_code = "oracle_harness()";
    // let mut harness_hash: [u8; 4] = [0; 4];
    // set_hash(harness_code, &mut harness_hash);
    // let mut function_oracle =
    //     FunctionHarnessOracle::new_no_condition(EVMAddress::zero(), Vec::from(harness_hash));

    let mut oracles: Vec<
        Rc<RefCell<dyn Oracle<EVMState, EVMAddress, _, _, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState>>>,
    > = vec![];

    let mut producers: Vec<
        Rc<
            RefCell<
                dyn Producer<EVMState, EVMAddress, _, _, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState>,
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

    if args.bug_oracle {
        oracles.push(Rc::new(RefCell::new(BugOracle::new())));

        if args.panic_on_bug {
            unsafe {
                PANIC_ON_BUG = true;
            }
        }
    }
    if args.selfdestruct_oracle {
        oracles.push(Rc::new(RefCell::new(SelfdestructOracle::new())));
    }

    if args.typed_bug_oracle {
        oracles.push(Rc::new(RefCell::new(TypedBugOracle::new())));

        if args.panic_on_typedbug {
            unsafe {
                PANIC_ON_TYPEDBUG = true;
            }
        }
    }

    if args.ierc20_oracle || args.pair_oracle {
        producers.push(pair_producer);
    }

    if args.ierc20_oracle {
        producers.push(erc20_producer);
    }

    let is_onchain = onchain.is_some();
    let mut state: EVMFuzzState = FuzzState::new(args.seed);

    let config = Config {
        fuzzer_type: FuzzerTypes::from_str(args.fuzzer_type.as_str()).expect("unknown fuzzer"),
        contract_info: match target_type {
            Glob => ContractLoader::from_glob(args.target.as_str(), &mut state).contracts,
            Address => {
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
                )
                .contracts
            }
        },
        onchain,
        concolic: args.concolic,
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
        selfdestruct_oracle:args.selfdestruct_oracle,
        work_dir: args.work_dir,
        write_relationship: args.write_relationship,
        run_forever: args.run_forever,
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
