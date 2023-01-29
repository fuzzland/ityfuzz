extern crate core;

mod abi;
mod concolic;
mod contract_utils;
mod corpus;
mod evm;
mod executor;
mod feedback;
mod fuzzer;
mod fuzzers;
mod infant_state_stage;
mod input;
mod mutation_utils;
mod mutator;
mod oracle;
mod rand;
mod state;
mod state_input;
mod types;

use std::fmt::{Debug, Formatter};
use std::ops::Deref;
use std::path::Path;
use std::{str::FromStr, time::Instant};

use bytes::Bytes;
use libafl::{inputs, Error};
use primitive_types::H160;
use revm::{db::CacheDB, Bytecode, TransactTo};

use libafl::executors::{Executor, ExitKind};
use libafl::inputs::Input;
use serde::{Deserialize, Serialize};

use crate::evm::{EVMExecutor, VMState};

#[cfg(test)]
mod tests {
    use super::*;
    use revm::AccountInfo;

    #[test]
    fn it_works() {}
}
