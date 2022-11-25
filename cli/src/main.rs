use crate::TargetType::{Address, Glob};
use clap::Parser;
use ityfuzz::config::{Config, FuzzerTypes};
use ityfuzz::contract_utils::{set_hash, ContractLoader};
use ityfuzz::fuzzers::basic_fuzzer;
use ityfuzz::fuzzers::cmp_fuzzer::cmp_fuzzer;
use ityfuzz::fuzzers::df_fuzzer::df_fuzzer;
use ityfuzz::input::VMInput;
use ityfuzz::middleware::Middleware;
use ityfuzz::onchain::endpoints::{Chain, OnChainConfig};
use ityfuzz::onchain::flashloan::Flashloan;
use ityfuzz::oracle::{FunctionHarnessOracle, IERC20OracleFlashloan, Oracle};
use ityfuzz::state::FuzzState;
use primitive_types::H160;
use std::path::PathBuf;
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

    /// Enable flashloan
    #[arg(short, long, default_value = "false")]
    flashloan: bool,

    /// Enable ierc20 oracle
    #[arg(short, long, default_value = "false")]
    ierc20_oracle: bool,
}

enum TargetType {
    Glob,
    Address,
}

fn main() {
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
            if H160::from_str(&args.target).is_ok() {
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

    if onchain.is_some() && args.onchain_etherscan_api_key.is_some() {
        onchain
            .as_mut()
            .unwrap()
            .etherscan_api_key
            .push(args.onchain_etherscan_api_key.unwrap());
    }

    let mut flashloan_oracle = IERC20OracleFlashloan::new();
    let harness_code = "oracle_harness()";
    let mut harness_hash: [u8; 4] = [0; 4];
    set_hash(harness_code, &mut harness_hash);
    let mut function_oracle =
        FunctionHarnessOracle::new_no_condition(H160::zero(), Vec::from(harness_hash));

    let mut oracles: Vec<Box<dyn Oracle<VMInput, FuzzState>>> = vec![];
    if args.ierc20_oracle {
        oracles.push(Box::new(flashloan_oracle));
    }

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
                    vec![H160::from_str(args.target.as_str()).unwrap()],
                )
                .contracts
            }
        },
        onchain,
        oracle: oracles,
        flashloan: if args.flashloan {
            Some(Flashloan::new())
        } else {
            None
        },
    };

    match config.fuzzer_type {
        FuzzerTypes::CMP => cmp_fuzzer(config),
        FuzzerTypes::DATAFLOW => df_fuzzer(config),
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
