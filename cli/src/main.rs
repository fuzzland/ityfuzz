mod evm;
mod r#move;

use clap::Parser;
use ethers::types::Transaction;
use hex::{decode, encode};
use ityfuzz::evm::config::{Config, FuzzerTypes, StorageFetchingMode};
use ityfuzz::evm::contract_utils::{set_hash, ContractLoader};
use ityfuzz::evm::host::PANIC_ON_BUG;
use ityfuzz::evm::input::{ConciseEVMInput, EVMInput};
use ityfuzz::evm::middlewares::middleware::Middleware;
use ityfuzz::evm::onchain::endpoints::{Chain, OnChainConfig};
use ityfuzz::evm::onchain::flashloan::{DummyPriceOracle, Flashloan};
use ityfuzz::evm::oracles::echidna::EchidnaOracle;
use ityfuzz::evm::oracles::erc20::IERC20OracleFlashloan;
use ityfuzz::evm::oracles::function::FunctionHarnessOracle;
use ityfuzz::evm::oracles::selfdestruct::SelfdestructOracle;
use ityfuzz::evm::oracles::typed_bug::TypedBugOracle;
use ityfuzz::evm::oracles::v2_pair::PairBalanceOracle;
use ityfuzz::evm::producers::erc20::ERC20Producer;
use ityfuzz::evm::producers::pair::PairProducer;
use ityfuzz::evm::types::{EVMAddress, EVMFuzzState, EVMU256};
use ityfuzz::evm::vm::EVMState;
use ityfuzz::fuzzers::evm_fuzzer::evm_fuzzer;
use ityfuzz::oracle::{Oracle, Producer};
use ityfuzz::r#const;
use ityfuzz::state::FuzzState;
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::rc::Rc;
use std::str::FromStr;
use crate::evm::{evm_main, EvmArgs};
use crate::r#move::{move_main, MoveArgs};
use clap::Subcommand;

pub fn init_sentry() {
    let _guard = sentry::init(("https://96f3517bd77346ea835d28f956a84b9d@o4504503751344128.ingest.sentry.io/4504503752523776", sentry::ClientOptions {
        release: sentry::release_name!(),
        ..Default::default()
    }));
}

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    EVM(EvmArgs),
    MOVE(MoveArgs)
}

fn main() {
    init_sentry();
    let args = Cli::parse();
    match args.command {
        Commands::EVM(args) => {
            evm_main(args);
        }
        Commands::MOVE(args) => {
            move_main(args);
        }
    }

}
