use clap::Parser;
use hex::{decode, encode};
use ityfuzz::fuzzers::move_fuzzer::{MoveFuzzConfig, move_fuzzer};
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

/// CLI for ItyFuzz for Move smart contracts
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct MoveArgs {
    /// Glob pattern / address to find contracts
    #[arg(short, long)]
    target: String,

    /// Seed for the RNG
    #[arg(short, long)]
    seed: u64,
}

pub fn move_main(args: MoveArgs) {
    move_fuzzer(&MoveFuzzConfig {
        target: args.target,
        work_dir: "./work_dir".to_string(),
        seed: args.seed,
    });

}
