extern crate core;

pub mod abi;
pub mod concolic;
pub mod contract_utils;
pub mod corpus;
pub mod evm;
pub mod executor;
pub mod feedback;
pub mod fuzzer;
pub mod fuzzers;
pub mod input;
pub mod mutation_utils;
pub mod mutator;
pub mod oracle;
pub mod rand;
pub mod state;
pub mod state_input;
pub mod types;

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
