use libafl::corpus::Corpus;

use libafl::prelude::HasCorpus;
use primitive_types::U256;
use std::fmt::Debug;

use crate::evm::abi::BoxedABI;
use crate::generic_vm::vm_executor::ExecutionResult;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::HasInfantStateState;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct BasicTxn<Addr> {
    pub caller: Addr,
    pub contract: Addr,
    pub data: Option<String>,
    #[cfg(feature = "evm")]
    #[serde(skip_serializing)]
    pub data_abi: Option<BoxedABI>,
    #[cfg(feature = "evm")]
    pub value: Option<U256>,
    #[cfg(feature = "full_trace")]
    pub flashloan: String,
    #[cfg(feature = "debug")]
    pub direct_data: Vec<u8>,
    pub layer: usize,
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
            .field("data", &self.data);
        #[cfg(feature = "debug")]
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

pub fn build_basic_txn<Loc, Addr, VS, I, Out>(
    v: &I,
    res: &ExecutionResult<Loc, Addr, VS, Out>,
) -> BasicTxn<Addr>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: VMStateT,
    Addr: Debug + Serialize + DeserializeOwned + Clone,
    Loc: Debug + Serialize + DeserializeOwned + Clone,
    Out: Default,
{
    BasicTxn {
        caller: v.get_caller(),
        contract: v.get_contract(),
        data: v.pretty_txn(),
        #[cfg(feature = "evm")]
        value: v.get_txn_value_temp(),
        #[cfg(feature = "evm")]
        data_abi: v.get_data_abi(),
        #[cfg(feature = "full_trace")]
        flashloan: res.new_state.state.get_flashloan(),
        #[cfg(feature = "debug")]
        direct_data: v.get_direct_data(),
        layer: v.get_state().get_post_execution_len(),
    }
}

pub fn build_basic_txn_from_input<Loc, Addr, VS, I>(v: &I) -> BasicTxn<Addr>
where
    I: VMInputT<VS, Loc, Addr>,
    VS: VMStateT,
    Addr: Debug + Serialize + DeserializeOwned + Clone,
    Loc: Debug + Serialize + DeserializeOwned + Clone,
{
    BasicTxn {
        caller: v.get_caller(),
        contract: v.get_contract(),
        data: v.pretty_txn(),
        #[cfg(feature = "evm")]
        value: v.get_txn_value_temp(),
        #[cfg(feature = "evm")]
        data_abi: v.get_data_abi(),
        #[cfg(feature = "full_trace")]
        flashloan: "".to_string(),
        #[cfg(feature = "debug")]
        direct_data: v.get_direct_data(),
        layer: v.get_state().get_post_execution_len(),
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxnTrace<Loc, Addr> {
    pub transactions: Vec<BasicTxn<Addr>>,
    pub from_idx: Option<usize>,
    pub is_initial: bool,
    pub phantom: std::marker::PhantomData<(Loc, Addr)>,
}

impl<Loc, Addr> TxnTrace<Loc, Addr> {
    pub(crate) fn new() -> Self {
        Self {
            transactions: Vec::new(),
            from_idx: None,
            is_initial: false,
            phantom: Default::default(),
        }
    }

    pub fn add_txn(&mut self, txn: BasicTxn<Addr>) {
        self.transactions.push(txn);
    }

    pub fn to_string<VS, S>(&self, state: &mut S) -> String
    where
        S: HasInfantStateState<Loc, Addr, VS>,
        VS: VMStateT,
        Addr: Debug + Serialize + DeserializeOwned + Clone,
        Loc: Debug + Serialize + DeserializeOwned + Clone,
    {
        if self.from_idx.is_none() {
            return String::from("Begin\n");
        }
        let current_idx = self.from_idx.unwrap();
        let corpus_item = state.get_infant_state_state().corpus().get(current_idx);
        if corpus_item.is_err() {
            return String::from("Corpus returning error\n");
        }
        let testcase = corpus_item.unwrap().clone().into_inner();
        let testcase_input = testcase.input();
        if testcase_input.is_none() {
            return String::from("[REDACTED]\n");
        }

        let mut s = Self::to_string(&testcase_input.as_ref().unwrap().trace.clone(), state);
        for t in &self.transactions {
            for _i in 0..t.layer {
                s.push_str(" == ");
            }
            s.push_str(format!("{}\n", serde_json::to_string(t).unwrap()).as_str());
            s.push_str("\n");
        }
        s
    }
}
impl<Loc, Addr> Default for TxnTrace<Loc, Addr> {
    fn default() -> Self {
        Self::new()
    }
}
