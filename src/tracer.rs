//! Tracer for representing VMInput and VMState with less memory footprint
//! and can be serialized and converted to string.

use std::fmt::Debug;

use libafl::{corpus::Corpus, prelude::HasCorpus};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    evm::utils::prettify_concise_inputs,
    generic_vm::vm_state::VMStateT,
    input::ConciseSerde,
    state::HasInfantStateState,
};

/// Represent a trace of transactions with starting VMState ID (from_idx).
/// If VMState ID is None, it means that the trace is from the initial state.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxnTrace<Loc, Addr, CI> {
    pub transactions: Vec<CI>,   // Transactions
    pub from_idx: Option<usize>, // Starting VMState ID
    pub derived_time: u64,       // Times spent on deriving this trace
    pub phantom: std::marker::PhantomData<(Loc, Addr)>,
}

impl<Loc, Addr, CI> TxnTrace<Loc, Addr, CI>
where
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Create a new TxnTrace
    pub(crate) fn new() -> Self {
        Self {
            transactions: Vec::new(),
            from_idx: None,
            derived_time: 0,
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
        let inputs = self.get_concise_inputs(state);
        if inputs.is_empty() {
            return String::from("[REDACTED]\n");
        }

        prettify_concise_inputs(&inputs)
    }

    /// Serialize the trace so that it can be replayed by using --replay-file
    /// option
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
        let corpus_item = state.get_infant_state_state().corpus().get(current_idx.into());
        // This happens when full_trace feature is not enabled, the corpus item may be
        // discarded
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
            s.push_str(format!("{}\n", String::from_utf8(concise_input.serialize_concise()).unwrap()).as_str());
        }
        s
    }

    pub fn get_concise_inputs<VS, S>(&self, state: &mut S) -> Vec<CI>
    where
        S: HasInfantStateState<Loc, Addr, VS, CI>,
        VS: VMStateT,
        Addr: Debug + Serialize + DeserializeOwned + Clone,
        Loc: Debug + Serialize + DeserializeOwned + Clone,
    {
        // If from_idx is None, it means that the trace is from the initial state
        if self.from_idx.is_none() {
            return self.transactions.clone();
        }

        let current_idx = self.from_idx.unwrap();
        let corpus_item = state.get_infant_state_state().corpus().get(current_idx.into());
        // This happens when full_trace feature is not enabled, the corpus item may be
        // discarded
        if corpus_item.is_err() {
            return Vec::new();
        }
        let testcase = corpus_item.unwrap().clone().into_inner();
        let testcase_input = testcase.input();
        if testcase_input.is_none() {
            return Vec::new();
        }

        // Try to reconstruct transactions leading to the current VMState recursively
        let mut res = Self::get_concise_inputs(&testcase_input.as_ref().unwrap().trace.clone(), state);

        res.append(&mut self.transactions.clone());
        res
    }
}
impl<Loc, Addr, CI> Default for TxnTrace<Loc, Addr, CI>
where
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn default() -> Self {
        Self::new()
    }
}
