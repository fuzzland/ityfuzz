use crate::evm::vm::EVMState;
use bytes::Bytes;
use libafl::corpus::Corpus;
use libafl::inputs::Input;
use libafl::prelude::HasCorpus;
use primitive_types::H160;
use std::fmt::Debug;

use crate::evm::abi::BoxedABI;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::HasInfantStateState;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;

#[derive(Serialize, Deserialize, Clone)]
pub struct BasicTxn<Addr> {
    pub caller: Addr,
    pub contract: Addr,
    pub data: Option<String>,
    pub txn_value: usize,
}

impl<Addr> Debug for BasicTxn<Addr>
where Addr: Debug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicTxn")
            .field("caller", &self.caller)
            .field("contract", &self.contract)
            .field("data", &self.data)
            .field("txn_value", &self.txn_value)
            .finish()
    }
}

pub fn build_basic_txn<Loc, Addr, VS, I>(v: &I) -> BasicTxn<Addr>
    where
    I: VMInputT<VS, Loc, Addr>,
    VS: VMStateT,
    Addr: Debug + Serialize + DeserializeOwned + Clone,
    Loc: Debug  + Serialize + DeserializeOwned + Clone,
{
    BasicTxn {
        caller: v.get_caller(),
        contract: v.get_contract(),
        data: None, //v.get_abi_cloned(),
        txn_value: v.get_txn_value().unwrap_or(0),
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxnTrace<Loc, Addr>
where
{
    pub transactions: Vec<BasicTxn<Addr>>,
    pub from_idx: usize,
    pub phantom: std::marker::PhantomData<(Loc, Addr)>,
}

impl<Loc, Addr> TxnTrace<Loc, Addr> {
    pub(crate) fn new() -> Self {
        Self {
            transactions: Vec::new(),
            from_idx: 0,
            phantom: Default::default()
        }
    }

    pub fn to_string<VS, S>(trace: &TxnTrace<Loc, Addr>, state: &mut S) -> String
    where
        S: HasInfantStateState<Loc, Addr, VS>,
        VS: VMStateT,
        Addr: Debug + Serialize + DeserializeOwned + Clone,
        Loc: Debug + Serialize + DeserializeOwned + Clone,
    {
        if trace.from_idx == 0 {
            return String::from("Begin\n");
        }
        let mut current_idx = trace.from_idx;
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
        for t in &trace.transactions {
            s.push_str(format!("{:?}\n", t).as_str());
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
