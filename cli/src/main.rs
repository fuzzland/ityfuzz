use clap::Parser;
use ityfuzz::fuzzers::basic_fuzzer;
use ityfuzz::fuzzers::cmp_fuzzer::cmp_fuzzer;
use std::path::PathBuf;
use ityfuzz::fuzzers::df_fuzzer::df_fuzzer;

/// CLI for ItyFuzz
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Glob pattern to find contracts
    #[arg(short, long)]
    contract_glob: String,
    // target single contract -- Optional
    #[arg(short, long)]
    target_contract: Option<String>,

    // Fuzzer type -- Optional
    #[arg(short, long)]
    fuzzer_type: Option<String>,
}

fn main() {
    let args = Args::parse();
    // basic_fuzzer::basic_fuzzer(
    //     PathBuf::from("./tmp/corpus"),
    //     PathBuf::from("./tmp/objective"),
    //     PathBuf::from("./tmp/log"),
    //     &String::from(args.contract_glob),
    // );
    match args.fuzzer_type {
        Some(v) => {
            match v.as_str() {
                "cmp" => {
                    cmp_fuzzer(&String::from(args.contract_glob), args.target_contract);
                }
                "df" => {
                    df_fuzzer(&String::from(args.contract_glob), args.target_contract);
                }
                _ => {
                    println!("Fuzzer type not supported");
                }
            }
        },
        _ => {
            df_fuzzer(&String::from(args.contract_glob), args.target_contract);
        }
    }
}
