/// Defines trait for VM inputs that are sent to any smart contract VM

use std::any;
use std::fmt::Debug;

use crate::state_input::StagedVMState;
use libafl::inputs::Input;

use libafl::prelude::{HasMaxSize, HasRand, MutationResult, State};
use libafl::state::HasMetadata;

use crate::evm::abi::BoxedABI;

use crate::generic_vm::vm_state::VMStateT;
use crate::state::{HasCaller, HasItyState};
use primitive_types::U256;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// A trait for VM inputs that are sent to any smart contract VM
pub trait VMInputT<VS, Loc, Addr>:
    Input + Debug + Clone + serde_traitobject::Serialize + serde_traitobject::Deserialize
where
    VS: Default + VMStateT,
    Addr: Debug + Clone + Serialize + DeserializeOwned,
    Loc: Debug + Clone + Serialize + DeserializeOwned,
{
    /// Mutate the input
    fn mutate<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: State
            + HasRand
            + HasMaxSize
            + HasItyState<Loc, Addr, VS>
            + HasCaller<Addr>
            + HasMetadata;
    /// Get the caller address of the input (the address that sent the transaction)
    fn get_caller_mut(&mut self) -> &mut Addr;
    /// Get the caller address of the input
    fn get_caller(&self) -> Addr;
    /// Set the caller address of the input
    fn set_caller(&mut self, caller: Addr);

    /// Get the contract address of the input (the address of the contract that is being called)
    fn get_contract(&self) -> Addr;

    /// Get the VM state of the input (the state of the VM before the transaction is executed)
    fn get_state(&self) -> &VS;
    /// Get the VM state of the input
    fn get_state_mut(&mut self) -> &mut VS;
    /// Set the staged VM state of the input
    fn set_staged_state(&mut self, state: StagedVMState<Loc, Addr, VS>, idx: usize);

    /// Get the ID of the VM state in the infant state corpus
    fn get_state_idx(&self) -> usize;

    /// Get the staged VM state of the input
    fn get_staged_state(&self) -> &StagedVMState<Loc, Addr, VS>;

    /// Set to have post execution (incomplete execution)
    fn set_as_post_exec(&mut self, out_size: usize);

    /// Is the execution a step to finish incomplete execution
    fn is_step(&self) -> bool;

    /// Set the execution to be a step to finish incomplete execution
    fn set_step(&mut self, gate: bool);

    /// Get a pretty string of the transaction
    fn pretty_txn(&self) -> Option<String>;

    /// Used for downcasting
    fn as_any(&self) -> &dyn any::Any;

    /// Determine whether a input is better than another
    fn fav_factor(&self) -> f64;


    ///// EVM Specific!! ////
    // TODO: Move these to a separate trait

    /// Get the ABI of the input
    #[cfg(feature = "evm")]
    fn get_data_abi(&self) -> Option<BoxedABI>;

    /// Get the mutable ABI of the input
    #[cfg(feature = "evm")]
    fn get_data_abi_mut(&mut self) -> &mut Option<BoxedABI>;

    /// Get the value of the transaction
    #[cfg(feature = "evm")]
    fn get_txn_value_temp(&self) -> Option<U256>;

    /// Used for EVM debug / replaying, get the encoded input
    fn get_direct_data(&self) -> Vec<u8>;
}
