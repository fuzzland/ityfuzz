mod licensing;

use std::cell::RefCell;
use crate::TargetType::{Address, Glob};
use clap::Parser;
use ityfuzz::evm::config::{Config, FuzzerTypes, StorageFetchingMode};
use ityfuzz::evm::contract_utils::{set_hash, ContractLoader};
use ityfuzz::evm::input::EVMInput;
use ityfuzz::evm::middleware::Middleware;
use ityfuzz::evm::onchain::endpoints::{Chain, OnChainConfig};
use ityfuzz::evm::onchain::flashloan::{DummyPriceOracle, Flashloan};
use ityfuzz::evm::oracle::{FunctionHarnessOracle, IERC20OracleFlashloan};
use ityfuzz::evm::types::EVMFuzzState;
use ityfuzz::evm::vm::EVMState;
use ityfuzz::fuzzers::cmp_fuzzer::cmp_fuzzer;
use ityfuzz::oracle::Oracle;
use ityfuzz::state::FuzzState;
use primitive_types::{H160, U256};
use std::path::PathBuf;
use std::rc::Rc;
use std::str::FromStr;

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

    /// target single contract (Default: None)
    #[arg(long)]
    target_contract: Option<String>,

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
    #[arg(short, long, default_value = "false")]
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

    /// Debug?
    #[arg(long)]
    debug_file: Option<String>,
}

enum TargetType {
    Glob,
    Address,
}

fn main() {
    licensing::init_license();
    let args = Args::parse();
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

    let is_local_proxy = args.onchain_local_proxy_addr.is_some();

    let mut onchain = if args.onchain {
        match args.chain_type {
            Some(chain_str) => {
                let chain = Chain::from_str(&chain_str).expect("Invalid chain type");
                let block_number = args.onchain_block_number.unwrap();
                if is_local_proxy {
                    Some(OnChainConfig::new_local_proxy(
                        chain,
                        block_number,
                        args.onchain_local_proxy_addr.unwrap(),
                    ))
                } else {
                    Some(OnChainConfig::new(chain, block_number))
                }
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
                is_local_proxy,
                if is_local_proxy {
                    args.onchain_local_proxy_addr.unwrap()
                } else {
                    "".to_string()
                },
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

    let mut flashloan_oracle = Rc::new(RefCell::new(IERC20OracleFlashloan::new()));
    // let harness_code = "oracle_harness()";
    // let mut harness_hash: [u8; 4] = [0; 4];
    // set_hash(harness_code, &mut harness_hash);
    // let mut function_oracle =
    //     FunctionHarnessOracle::new_no_condition(H160::zero(), Vec::from(harness_hash));

    let mut oracles: Vec<
        Rc<RefCell<dyn Oracle<EVMState, H160, _, _, H160, U256, Vec<u8>, EVMInput, EVMFuzzState>>>,
    > = vec![];
    if args.ierc20_oracle {
        oracles.push(flashloan_oracle.clone());
    }

    let is_onchain = onchain.is_some();

    let config = Config {
        fuzzer_type: FuzzerTypes::from_str(args.fuzzer_type.as_str()).expect("unknown fuzzer"),
        contract_info: match target_type {
            Glob => {
                if args.target_contract.is_none() {
                    ContractLoader::from_glob(args.target.as_str()).contracts
                } else {
                    ContractLoader::from_glob_target(
                        args.target.as_str(),
                        args.target_contract.unwrap().as_str(),
                    )
                    .contracts
                }
            }
            Address => {
                if onchain.is_none() {
                    panic!("Onchain is required for address target type");
                }
                ContractLoader::from_address(
                    &mut onchain.as_mut().unwrap(),
                    args.target.split(",").map(|s| H160::from_str(s).unwrap()).collect(),
                )
                .contracts
            }
        },
        onchain,
        concolic: args.concolic,
        oracle: oracles,
        flashloan: args.flashloan,
        price_oracle: match args.flashloan_price_oracle.as_str() {
            "onchain" => Box::new(onchain_clone.expect("onchain unavailable but used for flashloan")),
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
        debug_file: args.debug_file,
        flashloan_oracle
    };

    match config.fuzzer_type {
        FuzzerTypes::CMP => cmp_fuzzer(config),
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
