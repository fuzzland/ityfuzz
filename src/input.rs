use std::fmt::Debug;
/// Defines trait for VM inputs that are sent to any smart contract VM
use std::{any, collections::HashMap};

use libafl::{
    inputs::Input,
    prelude::{HasMaxSize, HasRand, MutationResult, State},
    state::HasMetadata,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    evm::{abi::BoxedABI, types::EVMU256},
    generic_vm::{
        vm_executor::ExecutionResult,
        vm_state::{SwapInfo, VMStateT},
    },
    state::{HasCaller, HasItyState},
    state_input::StagedVMState,
};

/// A trait for VM inputs that are sent to any smart contract VM
pub trait VMInputT<VS, Loc, Addr, CI>:
    Input + Debug + Clone + serde_traitobject::Serialize + serde_traitobject::Deserialize
where
    VS: Default + VMStateT,
    Addr: Debug + Clone + Serialize + DeserializeOwned,
    Loc: Debug + Clone + Serialize + DeserializeOwned,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Mutate the input
    fn mutate<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: State + HasRand + HasMaxSize + HasItyState<Loc, Addr, VS, CI> + HasCaller<Addr> + HasMetadata;
    /// Get the caller address of the input (the address that sent the
    /// transaction)
    fn get_caller_mut(&mut self) -> &mut Addr;
    /// Get the caller address of the input
    fn get_caller(&self) -> Addr;
    /// Set the caller address of the input
    fn set_caller(&mut self, caller: Addr);
    /// Set the origin
    fn set_origin(&mut self, origin: Addr);
    /// Get the origin
    fn get_origin(&self) -> Addr;

    /// Get the contract address of the input (the address of the contract that
    /// is being called)
    fn get_contract(&self) -> Addr;

    /// Get the VM state of the input (the state of the VM before the
    /// transaction is executed)
    fn get_state(&self) -> &VS;
    /// Get the VM state of the input
    fn get_state_mut(&mut self) -> &mut VS;
    /// Set the staged VM state of the input
    fn set_staged_state(&mut self, state: StagedVMState<Loc, Addr, VS, CI>, idx: usize);

    /// Get the ID of the VM state in the infant state corpus
    fn get_state_idx(&self) -> usize;

    /// Get the staged VM state of the input
    fn get_staged_state(&self) -> &StagedVMState<Loc, Addr, VS, CI>;

    /// Set to have post execution (incomplete execution)
    fn set_as_post_exec(&mut self, out_size: usize);

    /// Is the execution a step to finish incomplete execution
    fn is_step(&self) -> bool;

    /// Set the execution to be a step to finish incomplete execution
    fn set_step(&mut self, gate: bool);

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
    fn get_txn_value_temp(&self) -> Option<EVMU256>;

    /// Used for EVM debug / replaying, get the encoded input
    fn get_direct_data(&self) -> Vec<u8>;

    /// Compressed representation of the input
    fn get_concise<Out>(&self, exec_res: &ExecutionResult<Loc, Addr, VS, Out, CI>) -> CI
    where
        Out: Default + Into<Vec<u8>> + Clone;
}

pub trait ConciseSerde {
    fn serialize_concise(&self) -> Vec<u8>;
    fn deserialize_concise(data: &[u8]) -> Self;
    fn serialize_string(&self) -> String;

    fn sender(&self) -> String {
        String::from("")
    }
    // Get the indentation of the input
    fn indent(&self) -> String {
        String::from("")
    }
    fn is_step(&self) -> bool {
        false
    }
}

/// SolutionTx for generating a test file.
pub trait SolutionTx {
    fn caller(&self) -> String {
        String::from("")
    }
    fn contract(&self) -> String {
        String::from("")
    }
    fn fn_signature(&self) -> String {
        String::from("")
    }
    fn fn_selector(&self) -> String {
        String::from("")
    }
    fn fn_args(&self) -> String {
        String::from("")
    }
    fn value(&self) -> String {
        String::from("")
    }
    fn is_borrow(&self) -> bool {
        false
    }
    fn liq_percent(&self) -> u8 {
        0
    }
    fn swap_data(&self) -> HashMap<String, SwapInfo> {
        HashMap::new()
    }
    fn calldata(&self) -> String {
        String::from("")
    }
}
