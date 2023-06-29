/// Mutator for EVM inputs
use crate::evm::input::EVMInputT;

use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, InfantStateState};
use libafl::inputs::Input;
use libafl::mutators::MutationResult;
use libafl::prelude::{HasMaxSize, HasRand, Mutator, Rand, State};
use libafl::schedulers::Scheduler;
use libafl::state::HasMetadata;
use libafl::Error;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::evm::input::EVMInputTy::Borrow;
use std::fmt::Debug;
use revm_interpreter::Interpreter;
use crate::evm::types::{convert_u256_to_h160, EVMAddress};

use crate::state::HasItyState;
use crate::state_input::StagedVMState;

/// [`AccessPattern`] records the access pattern of the input during execution. This helps
/// to determine what is needed to be fuzzed. For instance, we don't need to mutate caller
/// if the execution never uses it.
///
/// Each mutant should report to its parent's access pattern
/// if a new corpus item is added, it should inherit the access pattern of its source
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessPattern {
    pub caller: bool,       // or origin
    pub balance: Vec<EVMAddress>, // balance queried for accounts
    pub call_value: bool,
    pub gas_price: bool,
    pub number: bool,
    pub coinbase: bool,
    pub timestamp: bool,
    pub prevrandao: bool,
    pub gas_limit: bool,
    pub chain_id: bool,
    pub basefee: bool,
}

impl AccessPattern {
    /// Create a new access pattern with all fields set to false
    pub fn new() -> Self {
        Self {
            balance: vec![],
            caller: false,
            call_value: false,
            gas_price: false,
            number: false,
            coinbase: false,
            timestamp: false,
            prevrandao: false,
            gas_limit: false,
            chain_id: false,
            basefee: false,
        }
    }

    /// Record access pattern of current opcode executed by the interpreter
    pub fn decode_instruction(&mut self, interp: &Interpreter) {
        match unsafe { *interp.instruction_pointer } {
            0x31 => self
                .balance
                .push(convert_u256_to_h160(interp.stack.peek(0).unwrap())),
            0x33 => self.caller = true,
            0x34 => {
                // prevent initial check of dispatch to fallback
                if interp.program_counter() > 0xb {
                    self.call_value = true;
                }
            }
            0x3a => self.gas_price = true,
            0x43 => self.number = true,
            0x41 => self.coinbase = true,
            0x42 => self.timestamp = true,
            0x44 => self.prevrandao = true,
            0x45 => self.gas_limit = true,
            0x46 => self.chain_id = true,
            0x48 => self.basefee = true,
            _ => {}
        }
    }
}

/// [`FuzzMutator`] is a mutator that mutates the input based on the ABI and access pattern
pub struct FuzzMutator<'a, VS, Loc, Addr, SC>
where
    VS: Default + VMStateT,
    SC: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    /// Scheduler for selecting the next VM state to use if we decide to mutate the VM state of
    /// the input
    pub infant_scheduler: &'a SC,
    pub phantom: std::marker::PhantomData<(VS, Loc, Addr)>,
}

impl<'a, VS, Loc, Addr, SC> FuzzMutator<'a, VS, Loc, Addr, SC>
where
    VS: Default + VMStateT,
    SC: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    /// Create a new [`FuzzMutator`] with the given scheduler
    pub fn new(infant_scheduler: &'a SC) -> Self {
        Self {
            infant_scheduler,
            phantom: Default::default(),
        }
    }
}

impl<'a, VS, Loc, Addr, I, S, SC> Mutator<I, S> for FuzzMutator<'a, VS, Loc, Addr, SC>
where
    I: VMInputT<VS, Loc, Addr> + Input + EVMInputT,
    S: State + HasRand + HasMaxSize + HasItyState<Loc, Addr, VS> + HasCaller<Addr> + HasMetadata,
    SC: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    VS: Default + VMStateT,
    Addr: PartialEq + Debug + Serialize + DeserializeOwned + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    /// Mutate the input
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // if the VM state of the input is not initialized, swap it with a state initialized
        if !input.get_staged_state().initialized {
            let concrete = state.get_infant_state(self.infant_scheduler).unwrap();
            input.set_staged_state(concrete.1, concrete.0);
        }

        // determine whether we should conduct havoc
        // (a sequence of mutations in batch vs single mutation)
        let should_havoc = state.rand_mut().below(100) < 60;

        // determine how many times we should mutate the input
        let havoc_times = if should_havoc {
            state.rand_mut().below(10) + 1
        } else {
            1
        };

        // mutate the input once
        let mut mutator = || -> MutationResult {
            // if the input is a step input (resume execution from a control leak)
            // we should not mutate the VM state, but only mutate the bytes
            if input.is_step() {
                return input.mutate(state);
            }

            // if the input is to borrow token, we should mutate the randomness
            // (use to select the paths to buy token), VM state, and bytes
            #[cfg(feature = "flashloan_v2")]
            if input.get_input_type() == Borrow {
                let rand_u8 = state.rand_mut().below(255) as u8;
                return match state.rand_mut().below(3) {
                    0 => {
                        // mutate the randomness
                        input.set_randomness(vec![rand_u8; 1]);
                        MutationResult::Mutated
                    }
                    1 => {
                        // mutate the VM state
                        let old_idx = input.get_state_idx();
                        let (idx, new_state) =
                            state.get_infant_state(self.infant_scheduler).unwrap();
                        if idx == old_idx {
                            return MutationResult::Skipped;
                        }
                        input.set_staged_state(new_state, idx);
                        MutationResult::Mutated
                    }
                    // mutate the bytes
                    _ => input.mutate(state),
                };
            }

            // potentially set the input to be a step input  (resume execution from a control leak)
            if input.get_staged_state().state.has_post_execution() && !input.is_step() {
                if state.rand_mut().below(100) < 60 as u64 {
                    input.set_step(true);
                    // todo(@shou): move args into
                    input.set_as_post_exec(
                        input.get_state().get_post_execution_needed_len() as usize
                    );
                    for _ in 0..havoc_times - 1 {
                        input.mutate(state);
                    }
                    return MutationResult::Mutated;
                }
            }

            // mutate the bytes or VM state or liquidation percent (percentage of token to liquidate)
            // by default
            match state.rand_mut().below(100) {
                0..=5 => {
                    // cross over infant state
                    let old_idx = input.get_state_idx();
                    let (idx, new_state) = state.get_infant_state(self.infant_scheduler).unwrap();
                    if idx == old_idx {
                        return MutationResult::Skipped;
                    }
                    input.set_staged_state(new_state, idx);
                    MutationResult::Mutated
                }
                #[cfg(feature = "flashloan_v2")]
                6..=10 => {
                    let prev_percent = input.get_liquidation_percent();
                    input.set_liquidation_percent(if state.rand_mut().below(100) < 80 {
                        10
                    } else {
                        0
                    } as u8);
                    if prev_percent != input.get_liquidation_percent() {
                        MutationResult::Mutated
                    } else {
                        MutationResult::Skipped
                    }
                }
                11 => {
                    let rand_u8 = state.rand_mut().below(255) as u8;
                    input.set_randomness(vec![rand_u8; 1]);
                    MutationResult::Mutated
                }
                _ => input.mutate(state),
            }
        };

        let mut res = MutationResult::Skipped;
        let mut tries = 0;

        // try to mutate the input for [`havoc_times`] times with 20 retries if
        // the input is not mutated
        while res != MutationResult::Mutated && tries < 20 {
            for _ in 0..havoc_times {
                if mutator() == MutationResult::Mutated {
                    res = MutationResult::Mutated;
                }
            }
            tries += 1;
        }
        Ok(res)
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _stage_idx: i32,
        _corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        // todo!()
        Ok(())
    }
}
