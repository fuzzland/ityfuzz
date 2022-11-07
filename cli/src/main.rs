use clap::Parser;
use ityfuzz::fuzzers::basic_fuzzer;
use ityfuzz::fuzzers::cmp_fuzzer::cmp_fuzzer;
use std::path::PathBuf;

/// CLI for ItyFuzz
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Glob pattern to find contracts
    #[arg(short, long)]
    contract_glob: String,
    target_contract: Option<String>,
}

fn main() {
    let args = Args::parse();
    // basic_fuzzer::basic_fuzzer(
    //     PathBuf::from("./tmp/corpus"),
    //     PathBuf::from("./tmp/objective"),
    //     PathBuf::from("./tmp/log"),
    //     &String::from(args.contract_glob),
    // );
    cmp_fuzzer(&String::from(args.contract_glob), args.target_contract);
}
