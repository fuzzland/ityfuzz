use crate::abi::{ABILossyType, ADynamic, BoxedABI, A256};
use std::fmt::Debug;
use std::ops::{Deref, DerefMut};

use crate::state_input::StagedVMState;
use crate::{evm, VMState};
use bytes::Bytes;
use libafl::inputs::Input;
use libafl::mutators::Mutator;
use libafl::prelude::{HasLen, HasMaxSize, HasRand, MutationResult, Rand, State};

use crate::mutation_utils::VMStateHintedMutator;
use crate::state::HasItyState;
use primitive_types::H160;
use serde::{Deserialize, Serialize};
use serde_traitobject::Any;

// ST: Should VMInputT be the generic type for both inputs?
pub trait VMInputT:
    Input
    + Debug
    + Clone
    + serde_traitobject::Serialize
    + serde_traitobject::Deserialize
    + From<VMInput>
{
    fn to_bytes(&self) -> Bytes;
    fn mutate<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: State + HasRand + HasMaxSize + HasItyState;
    fn get_caller_mut(&mut self) -> &mut H160;
    fn get_caller(&self) -> H160;
    fn set_caller(&mut self, caller: H160);
    fn get_contract_mut(&mut self) -> &mut H160;
    fn get_contract(&self) -> H160;
    fn get_state(&self) -> &evm::VMState;
    fn set_staged_state(&mut self, state: StagedVMState, idx: usize);
    fn get_state_idx(&self) -> usize;
    fn get_staged_state(&self) -> &StagedVMState;
    fn get_txn_value(&self) -> Option<usize>;
    fn set_txn_value(&mut self, v: usize);
    fn get_abi_cloned(&self) -> Option<BoxedABI>;
    fn set_abi(&mut self, abi: BoxedABI);
    fn is_step(&self) -> bool;
    fn set_step(&mut self, gate: bool);
    fn to_string(&self) -> String;
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VMInput {
    pub caller: H160,
    pub contract: H160,
    pub data: Option<BoxedABI>,
    pub sstate: StagedVMState,
    pub sstate_idx: usize,
    pub txn_value: Option<usize>,
    pub step: bool,
}

impl HasLen for VMInput {
    fn len(&self) -> usize {
        match self.data {
            Some(ref d) => d.get_bytes().len(),
            None => 0,
        }
    }
}

impl std::fmt::Debug for VMInput {
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

impl VMInputT for VMInput {
    fn to_bytes(&self) -> Bytes {
        match self.data {
            Some(ref d) => d.get_bytes(),
            None => Bytes::new(),
        }
    }

    fn mutate<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: State + HasRand + HasMaxSize + HasItyState,
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

    fn get_contract_mut(&mut self) -> &mut H160 {
        &mut self.contract
    }

    fn get_contract(&self) -> H160 {
        self.contract.clone()
    }

    fn get_state(&self) -> &VMState {
        &self.sstate.state
    }

    fn set_staged_state(&mut self, state: StagedVMState, idx: usize) {
        self.sstate = state;
        self.sstate_idx = idx;
    }

    fn get_state_idx(&self) -> usize {
        self.sstate_idx
    }

    fn get_staged_state(&self) -> &StagedVMState {
        &self.sstate
    }

    fn get_txn_value(&self) -> Option<usize> {
        self.txn_value
    }

    fn set_txn_value(&mut self, v: usize) {
        self.txn_value = Some(v);
    }

    fn get_abi_cloned(&self) -> Option<BoxedABI> {
        self.data.clone()
    }

    fn set_abi(&mut self, abi: BoxedABI) {
        self.data = Some(abi);
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
}

impl Input for VMInput {
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
