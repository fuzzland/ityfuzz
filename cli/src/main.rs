use crate::TargetType::{Address, Glob};
use clap::Parser;
use ityfuzz::config::{Config, FuzzerTypes};
use ityfuzz::contract_utils::ContractLoader;
use ityfuzz::fuzzers::basic_fuzzer;
use ityfuzz::fuzzers::cmp_fuzzer::cmp_fuzzer;
use ityfuzz::fuzzers::df_fuzzer::df_fuzzer;
use ityfuzz::onchain::endpoints::OnChainConfig;
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

    /// Target type (glob, address)
    #[arg(long)]
    target_type: Option<String>,

    /// target single contract -- Optional
    #[arg(long)]
    target_contract: Option<String>,

    /// Fuzzer type -- Optional
    #[arg(short, long)]
    fuzzer_type: Option<String>,

    /// Enable onchain
    #[arg(short, long)]
    onchain: Option<bool>,

    /// Onchain endpoint URL
    #[arg(long)]
    onchain_url: Option<String>,

    /// Onchain chain ID
    #[arg(long)]
    onchain_chain_id: Option<u32>,

    /// Onchain block number
    #[arg(long)]
    onchain_block_number: Option<u64>,
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
        },
    };

    let onchain = if args.onchain.is_some() && args.onchain.unwrap() {
        Some(OnChainConfig::new(
            args.onchain_url
                .unwrap_or("https://bsc-dataseed1.binance.org/".to_string()),
            args.onchain_chain_id.unwrap_or(56),
            args.onchain_block_number.unwrap_or(0),
        ))
    } else {
        None
    };

    let config = Config {
        fuzzer_type: FuzzerTypes::from_str(args.fuzzer_type.unwrap_or("cmp".to_string()).as_str())
            .expect("unknown fuzzer"),
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
                    &onchain.as_ref().unwrap(),
                    vec![H160::from_str(args.target.as_str()).unwrap()],
                )
                .contracts
            }
        },
        onchain,
        oracle: None,
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
