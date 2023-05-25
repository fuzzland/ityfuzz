/// Implements wrappers around VMState that can be stored in a corpus.

use libafl::inputs::Input;

use std::fmt::Debug;

use crate::generic_vm::vm_state::VMStateT;

use crate::tracer::TxnTrace;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};


/// StagedVMState is a wrapper around a VMState that can be stored in a corpus.
/// It also has stage field that is used to store the stage of the oracle execution on such a VMState.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct StagedVMState<Loc, Addr, VS>
where
    VS: Default + VMStateT,
    Addr: Debug,
    Loc: Debug,
{
    #[serde(deserialize_with = "VS::deserialize")]
    pub state: VS,  // VM state
    pub stage: Vec<u64>,  // Stages of each oracle execution
    pub initialized: bool,  // Whether the VMState is initialized, uninitialized VMState will be initialized during mutation
    pub trace: TxnTrace<Loc, Addr>,  // Trace building up such a VMState
}

impl<Loc, Addr, VS> StagedVMState<Loc, Addr, VS>
where
    VS: Default + VMStateT,
    Addr: Debug,
    Loc: Debug,
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
