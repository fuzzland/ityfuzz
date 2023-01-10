mod evm;
mod rand;
mod types;
mod executor;
mod input;
mod abi;
mod mutator;
mod state;

use std::{str::FromStr, time::Instant};
use std::fmt::{Debug, Formatter};
use std::ops::Deref;
use std::path::Path;

use bytes::Bytes;
use libafl::{Error, inputs};
use primitive_types::H160;
use revm::{db::CacheDB, Bytecode, TransactTo};

use libafl::executors::{Executor, ExitKind};
use libafl::inputs::Input;
use serde::{Deserialize, Serialize};


use crate::evm::{EVMExecutor, VMState};





#[cfg(test)]
mod tests {
    use revm::AccountInfo;
    use super::*;

    #[test]
    fn it_works() {

    }
}
