/// Dummy oracle for testing
use crate::evm::input::ConciseEVMInput;
use crate::{evm::srcmap::RawSourceMapInfo, fuzzer::ORACLE_OUTPUT};

pub struct EVMBugResult {
    pub bug_type: String,
    pub bug_info: String,
    pub input: ConciseEVMInput,
    pub issue_source: Option<String>,
    pub sourcemap: Option<RawSourceMapInfo>,
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

    pub fn new(
        bug_type: String,
        bug_idx: u64,
        bug_info: String,
        input: ConciseEVMInput,
        sourcemap: Option<RawSourceMapInfo>,
        issue_source: Option<String>,
    ) -> Self {
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
