use crate::evm::abi::{AEmpty, AUnknown, BoxedABI};
use crate::evm::vm::EVMState;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasItyState};
use crate::state_input::StagedVMState;
use bytes::Bytes;
use libafl::bolts::HasLen;
use libafl::inputs::Input;
use libafl::mutators::MutationResult;
use libafl::prelude::{HasMaxSize, HasRand, State};
use primitive_types::H160;
use serde::{Deserialize, Serialize};
use serde_traitobject::Any;
use crate::evm::types::EVMStagedVMState;

pub trait EVMInputT {
    fn to_bytes(&self) -> Vec<u8>;
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EVMInput {
    pub caller: H160,
    pub contract: H160,
    pub data: Option<BoxedABI>,
    pub sstate: StagedVMState<H160, H160, EVMState>,
    pub sstate_idx: usize,
    pub txn_value: Option<usize>,
    pub step: bool,

    #[cfg(test)]
    pub direct_data: Bytes,
}

impl HasLen for EVMInput {
    fn len(&self) -> usize {
        match self.data {
            Some(ref d) => d.get_bytes().len(),
            None => 0,
        }
    }
}

impl std::fmt::Debug for EVMInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VMInput")
            .field("caller", &self.caller)
            .field("contract", &self.contract)
            // .field("data", &self.data)
            .field("state", &self.sstate)
            .field("state_idx", &self.sstate_idx)
            .field("txn_value", &self.txn_value)
            .field("step", &self.step)
            .finish()
    }
}

impl EVMInputT for EVMInput {
    fn to_bytes(&self) -> Vec<u8> {
        match self.data {
            Some(ref d) => d.get_bytes(),
            None => vec![],
        }
    }
}

impl VMInputT<EVMState, H160, H160> for EVMInput {
    fn mutate<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: State + HasRand + HasMaxSize + HasItyState<H160, H160, EVMState> + HasCaller<H160>,
    {
        let vm_slots = if let Some(s) = self.get_state().get(&self.get_contract()) {
            Some(s.clone())
        } else {
            None
        };
        match self.data {
            Some(ref mut data) => data.mutate_with_vm_slots(state, vm_slots),
            None => MutationResult::Skipped,
        }
    }

    fn get_caller_mut(&mut self) -> &mut H160 {
        &mut self.caller
    }

    fn get_caller(&self) -> H160 {
        self.caller.clone()
    }

    fn set_caller(&mut self, caller: H160) {
        self.caller = caller;
    }

    fn get_contract(&self) -> H160 {
        self.contract.clone()
    }

    fn get_state(&self) -> &EVMState {
        &self.sstate.state
    }

    fn set_staged_state(&mut self, state: EVMStagedVMState, idx: usize) {
        self.sstate = state;
        self.sstate_idx = idx;
    }

    fn get_state_idx(&self) -> usize {
        self.sstate_idx
    }

    fn get_staged_state(&self) -> &EVMStagedVMState {
        &self.sstate
    }

    fn get_txn_value(&self) -> Option<usize> {
        self.txn_value
    }

    fn set_txn_value(&mut self, v: usize) {
        self.txn_value = Some(v);
    }

    fn set_as_post_exec(&mut self, out_size: usize) {
        self.data = Some(BoxedABI::new(Box::new(AUnknown {
            concrete_type: BoxedABI::new(Box::new(AEmpty {})),
            size: out_size,
        })));
    }

    fn is_step(&self) -> bool {
        self.step
    }

    fn set_step(&mut self, gate: bool) {
        self.step = gate;
    }

    fn to_string(&self) -> String {
        let current_txn = match self.data {
            Some(ref d) => d.to_string(),
            None => String::new(),
        };
        format!("{:?}", self.sstate) + &current_txn
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    #[cfg(test)]
    fn get_direct_data(&self) -> Vec<u8> {
        self.direct_data.to_vec()
    }
}

impl Input for EVMInput {
    fn generate_name(&self, idx: usize) -> String {
        format!("input-{:06}.bin", idx)
    }

    // fn to_file<P>(&self, path: P) -> Result<(), libafl::Error>
    //     where
    //         P: AsRef<std::path::Path>, {

    // }

    fn wrapped_as_testcase(&mut self) {
        // todo!()
    }
}
