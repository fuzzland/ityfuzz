use std::fmt::Debug;

/// Implements wrappers around VMState that can be stored in a corpus.
use libafl::inputs::Input;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{generic_vm::vm_state::VMStateT, input::ConciseSerde, tracer::TxnTrace};

/// StagedVMState is a wrapper around a VMState that can be stored in a corpus.
/// It also has stage field that is used to store the stage of the oracle
/// execution on such a VMState.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct StagedVMState<Loc, Addr, VS, CI>
where
    VS: Default + VMStateT,
    Addr: Debug,
    Loc: Debug,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    #[serde(deserialize_with = "VS::deserialize")]
    pub state: VS, // VM state
    pub stage: Vec<u64>, // Stages of each oracle execution
    pub initialized: bool, /* Whether the VMState is initialized, uninitialized VMState will be initialized during
                          * mutation */
    #[serde(deserialize_with = "TxnTrace::deserialize")]
    pub trace: TxnTrace<Loc, Addr, CI>, // Trace building up such a VMState
}

impl<Loc, Addr, VS, CI> StagedVMState<Loc, Addr, VS, CI>
where
    VS: Default + VMStateT,
    Addr: Debug,
    Loc: Debug,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Create a new StagedVMState with a given VMState
    pub fn new_with_state(state: VS) -> Self {
        Self {
            state,
            stage: vec![],
            initialized: true,
            trace: TxnTrace::new(),
        }
    }

    /// Create a new uninitialized StagedVMState
    pub fn new_uninitialized() -> Self {
        Self {
            state: Default::default(),
            stage: vec![],
            initialized: false,
            trace: TxnTrace::new(),
        }
    }
}

impl<Loc, Addr, VS, CI> Input for StagedVMState<Loc, Addr, VS, CI>
where
    VS: Default + VMStateT,
    Addr: Debug + Serialize + DeserializeOwned + Clone,
    Loc: Debug + Serialize + DeserializeOwned + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn generate_name(&self, idx: usize) -> String {
        format!("input-{}.state", idx)
    }
}
