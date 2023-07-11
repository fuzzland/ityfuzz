//! Tracer for representing VMInput and VMState with less memory footprint
//! and can be serialized and converted to string.

use libafl::corpus::Corpus;

use libafl::prelude::HasCorpus;
use primitive_types::U256;
use std::fmt::Debug;

use crate::evm::abi::BoxedABI;
use crate::generic_vm::vm_executor::ExecutionResult;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::{ConciseSerde, VMInputT};
use crate::state::HasInfantStateState;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use crate::evm::types::EVMU256;
use crate::state_input::StagedVMState;

/// Represent a basic transaction using less memory.
/// It can be serialized and converted to string.
#[derive(Serialize, Deserialize, Clone)]
pub struct BasicTxn<Addr> {
    pub caller: Addr,
    pub contract: Addr,
    pub data: Option<String>,
    #[cfg(feature = "evm")]
    #[serde(skip_serializing)]
    pub data_abi: Option<BoxedABI>,
    #[cfg(feature = "evm")]
    pub value: Option<EVMU256>,
    #[cfg(feature = "full_trace")]
    pub flashloan: String,
    pub direct_data: Vec<u8>,
    pub layer: usize,
    pub additional_info: Option<Vec<u8>>,
}

impl<Addr> Debug for BasicTxn<Addr>
where
    Addr: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut binding = f.debug_struct("BasicTxn");
        let mut ff = binding
            .field("caller", &self.caller)
            .field("contract", &self.contract)
            .field("data", &self.data)
            .field("additional_info", &hex::encode(self.additional_info.as_ref().unwrap_or(&vec![])));
        {
            ff = ff.field("direct_data", &hex::encode(self.direct_data.as_slice()));
        }
        #[cfg(feature = "full_trace")]
        {
            ff.field("flashloan", &self.flashloan).finish()
        }

        #[cfg(not(feature = "full_trace"))]
        {
            ff.finish()
        }
    }
}

// /// Turn an input (VMInput + VMState) to a basic transaction
// /// Includes additional info from execution results
// pub fn build_basic_txn<Loc, Addr, VS, I, Out>(
//     v: &I,
//     res: &ExecutionResult<Loc, Addr, VS, Out, CI>,
// ) -> BasicTxn<Addr>
// where
//     I: VMInputT<VS, Loc, Addr, CI>,
//     VS: VMStateT,
//     Addr: Debug + Serialize + DeserializeOwned + Clone,
//     Loc: Debug + Serialize + DeserializeOwned + Clone,
//     Out: Default,
// {
//     BasicTxn {
//         caller: v.get_caller(),
//         contract: v.get_contract(),
//         data: v.pretty_txn(),
//         #[cfg(feature = "evm")]
//         value: v.get_txn_value_temp(),
//         #[cfg(feature = "evm")]
//         data_abi: v.get_data_abi(),
//         #[cfg(feature = "full_trace")]
//         flashloan: res.new_state.state.get_flashloan(),
//         direct_data: v.get_direct_data(),
//         layer: v.get_state().get_post_execution_len(),
//         additional_info: if res.additional_info.is_none() {
//             None
//         } else {
//             res.additional_info.clone()
//         },
//     }
// }

// /// [Deprecated]: Turn an input (VMInput + VMState) to a basic transaction
// pub fn build_basic_txn_from_input<Loc, Addr, VS, I>(v: &I) -> BasicTxn<Addr>
// where
//     I: VMInputT<VS, Loc, Addr, CI>,
//     VS: VMStateT,
//     Addr: Debug + Serialize + DeserializeOwned + Clone,
//     Loc: Debug + Serialize + DeserializeOwned + Clone,
// {
//     BasicTxn {
//         caller: v.get_caller(),
//         contract: v.get_contract(),
//         data: v.pretty_txn(),
//         #[cfg(feature = "evm")]
//         value: v.get_txn_value_temp(),
//         #[cfg(feature = "evm")]
//         data_abi: v.get_data_abi(),
//         #[cfg(feature = "full_trace")]
//         flashloan: "".to_string(),
//         direct_data: v.get_direct_data(),
//         layer: v.get_state().get_post_execution_len(),
//         additional_info: None,
//     }
// }

/// Represent a trace of transactions with starting VMState ID (from_idx).
/// If VMState ID is None, it means that the trace is from the initial state.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxnTrace<Loc, Addr, CI> {
    pub transactions: Vec<CI>,  // Transactions
    pub from_idx: Option<usize>,  // Starting VMState ID
    pub phantom: std::marker::PhantomData<(Loc, Addr)>,
}

impl<Loc, Addr, CI> TxnTrace<Loc, Addr, CI>
where CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde {
    /// Create a new TxnTrace
    pub(crate) fn new() -> Self {
        Self {
            transactions: Vec::new(),
            from_idx: None,
            phantom: Default::default(),
        }
    }

    // /// Add a transaction to the trace
    // pub fn add_txn(&mut self, layer: u8, description: String, txn: Vec<u8>) {
    //     self.transactions.push((layer, description, txn));
    // }
    //
    /// Add a transaction to the trace
    pub fn add_input(&mut self, input: CI) {
        self.transactions.push(input);
    }

    /// Convert the trace to a human-readable string
    pub fn to_string<VS, S>(&self, state: &mut S) -> String
    where
        S: HasInfantStateState<Loc, Addr, VS, CI>,
        VS: VMStateT,
        Addr: Debug + Serialize + DeserializeOwned + Clone,
        Loc: Debug + Serialize + DeserializeOwned + Clone,
    {
        // If from_idx is None, it means that the trace is from the initial state
        if self.from_idx.is_none() {
            return String::from("Begin\n");
        }
        let current_idx = self.from_idx.unwrap();
        let corpus_item = state.get_infant_state_state().corpus().get(current_idx);
        // This happens when full_trace feature is not enabled, the corpus item may be discarded
        if corpus_item.is_err() {
            return String::from("Corpus returning error\n");
        }
        let testcase = corpus_item.unwrap().clone().into_inner();
        let testcase_input = testcase.input();
        if testcase_input.is_none() {
            return String::from("[REDACTED]\n");
        }

        // Try to reconstruct transactions leading to the current VMState recursively
        let mut s = Self::to_string(&testcase_input.as_ref().unwrap().trace.clone(), state);

        // Dump the current transaction
        for concise_input in &self.transactions {
            s.push_str(format!("{}\n", concise_input.serialize_string()).as_str());
        }
        s
    }

    /// Serialize the trace so that it can be replayed by using --replay-file option
    pub fn to_file_str<VS, S>(&self, state: &mut S) -> String
        where
            S: HasInfantStateState<Loc, Addr, VS, CI>,
            VS: VMStateT,
            Addr: Debug + Serialize + DeserializeOwned + Clone,
            Loc: Debug + Serialize + DeserializeOwned + Clone,
    {
        // If from_idx is None, it means that the trace is from the initial state
        if self.from_idx.is_none() {
            return String::from("");
        }
        let current_idx = self.from_idx.unwrap();
        let corpus_item = state.get_infant_state_state().corpus().get(current_idx);
        // This happens when full_trace feature is not enabled, the corpus item may be discarded
        if corpus_item.is_err() {
            return String::from("Corpus returning error\n");
        }
        let testcase = corpus_item.unwrap().clone().into_inner();
        let testcase_input = testcase.input();
        if testcase_input.is_none() {
            return String::from("[REDACTED]\n");
        }

        // Try to reconstruct transactions leading to the current VMState recursively
        let mut s = Self::to_file_str(&testcase_input.as_ref().unwrap().trace.clone(), state);

        // Dump the current transaction
        for concise_input in &self.transactions {
            // get liquidation percentage (EVM Specific)
            s.push_str(format!("{}\n", hex::encode(concise_input.serialize_concise())).as_str());
        }
        s
    }
}
impl<Loc, Addr, CI> Default for TxnTrace<Loc, Addr, CI> {
    fn default() -> Self {
        todo!("Default for TxnTrace")
    }
}
