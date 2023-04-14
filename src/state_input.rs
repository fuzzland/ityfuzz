use libafl::corpus::Corpus;
use libafl::inputs::Input;
use libafl::prelude::HasCorpus;
use std::fmt::Debug;

use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::HasInfantStateState;
use crate::tracer::TxnTrace;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct StagedVMState<Loc, Addr, VS>
where
    VS: Default + VMStateT,
    Addr: Debug,
    Loc: Debug,
{
    #[serde(deserialize_with = "VS::deserialize")]
    pub state: VS,
    pub stage: Vec<u64>,
    pub initialized: bool,
    pub trace: TxnTrace<Loc, Addr>,
}

impl<Loc, Addr, VS> StagedVMState<Loc, Addr, VS>
where
    VS: Default + VMStateT,
    Addr: Debug,
    Loc: Debug,
{
    pub fn new_with_state(state: VS) -> Self {
        Self {
            state,
            stage: vec![],
            initialized: true,
            trace: TxnTrace::new(),
        }
    }

    pub fn new_uninitialized() -> Self {
        Self {
            state: Default::default(),
            stage: vec![],
            initialized: false,
            trace: TxnTrace::new(),
        }
    }

    pub fn update_stage(&mut self, stage: Vec<u64>) {
        self.stage = stage;
        self.initialized = true;
    }
}

impl<Loc, Addr, VS> Input for StagedVMState<Loc, Addr, VS>
where
    VS: Default + VMStateT,
    Addr: Debug + Serialize + DeserializeOwned + Clone,
    Loc: Debug + Serialize + DeserializeOwned + Clone,
{
    fn generate_name(&self, idx: usize) -> String {
        format!("input-{}.state", idx)
    }
}
