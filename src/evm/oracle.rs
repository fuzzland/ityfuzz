/// Dummy oracle for testing
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT};
use std::collections::{HashMap, HashSet};

use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256};

use crate::evm::vm::EVMState;

use crate::oracle::{Oracle, OracleCtx};
use crate::state::HasExecutionResult;

use bytes::Bytes;
use libafl::impl_serdeany;

use crate::evm::uniswap::{liquidate_all_token, TokenContext};
use revm_primitives::Bytecode;
use serde::{Deserialize, Serialize};
use crate::evm::middlewares::call_printer::CallPrinterResult;
use crate::evm::srcmap::parser::SourceMapLocation;
use crate::fuzzer::ORACLE_OUTPUT;

pub struct NoOracle {}

impl Oracle<EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState, ConciseEVMInput>
    for NoOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        vec![]
    }
}

pub fn dummy_precondition(_ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
    99
}


pub struct EVMBugResult {
    pub bug_type: String,
    pub bug_info: String,
    pub input: ConciseEVMInput,
    pub issue_source: Option<String>,
    pub sourcemap: Option<SourceMapLocation>,
    pub bug_idx: u64,
}


impl EVMBugResult {
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({
            "bug_type": self.bug_type,
            "bug_info": self.bug_info,
            "input": self.input,
            "sourcemap": self.sourcemap,
            "issue_source": self.issue_source,
            "bug_idx": self.bug_idx,
        })
    }

    pub fn new(bug_type: String, bug_idx: u64, bug_info: String, input: ConciseEVMInput,  sourcemap: Option<SourceMapLocation>, issue_source: Option<String>) -> Self {
        Self {
            bug_type,
            bug_info,
            input,
            sourcemap,
            issue_source,
            bug_idx,
        }
    }

    pub fn new_simple(bug_type: String, bug_idx: u64, bug_info: String, input: ConciseEVMInput) -> Self {
        Self {
            bug_type,
            bug_info,
            input,
            issue_source: None,
            sourcemap: None,
            bug_idx,
        }
    }

    pub fn push_to_output(&self) {
        unsafe {
            ORACLE_OUTPUT.push(self.to_value());
        }
    }
}

