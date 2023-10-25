/// Mutator for EVM inputs
use crate::evm::input::EVMInputT;

use crate::generic_vm::vm_state::VMStateT;
use crate::input::{ConciseSerde, VMInputT};
use crate::state::{HasCaller, InfantStateState};
use libafl::inputs::Input;
use libafl::mutators::MutationResult;
use libafl::prelude::{HasMaxSize, HasRand, Mutator, State};
use libafl::schedulers::Scheduler;
use libafl::state::HasMetadata;
use libafl::Error;
use libafl_bolts::prelude::Rand;
use libafl_bolts::Named;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::evm::abi::ABIAddressToInstanceMap;
#[cfg(feature = "flashloan_v2")]
use crate::evm::input::EVMInputTy::Borrow;
use crate::evm::types::{convert_u256_to_h160, EVMAddress, EVMU256};
use crate::evm::vm::{Constraint, EVMStateT};
use revm_interpreter::Interpreter;
use std::fmt::Debug;

use crate::state::HasItyState;

/// [`AccessPattern`] records the access pattern of the input during execution. This helps
/// to determine what is needed to be fuzzed. For instance, we don't need to mutate caller
/// if the execution never uses it.
///
/// Each mutant should report to its parent's access pattern
/// if a new corpus item is added, it should inherit the access pattern of its source
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AccessPattern {
    pub caller: bool,             // or origin
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
pub struct FuzzMutator<VS, Loc, Addr, SC, CI>
where
    VS: Default + VMStateT,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Scheduler for selecting the next VM state to use if we decide to mutate the VM state of
    /// the input
    pub infant_scheduler: SC,
    pub phantom: std::marker::PhantomData<(VS, Loc, Addr, CI)>,
}

impl<VS, Loc, Addr, SC, CI> FuzzMutator<VS, Loc, Addr, SC, CI>
where
    VS: Default + VMStateT,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Create a new [`FuzzMutator`] with the given scheduler
    pub fn new(infant_scheduler: SC) -> Self {
        Self {
            infant_scheduler,
            phantom: Default::default(),
        }
    }

    fn ensures_constraint<I, S>(
        input: &mut I,
        state: &mut S,
        new_vm_state: &VS,
        constraints: Vec<Constraint>
    ) -> bool
    where
        I: VMInputT<VS, Loc, Addr, CI> + Input + EVMInputT,
        S: State
            + HasRand
            + HasMaxSize
            + HasItyState<Loc, Addr, VS, CI>
            + HasCaller<Addr>
            + HasMetadata,
    {
        // precheck
        for constraint in &constraints {
            match constraint {
                Constraint::MustStepNow => {
                    #[cfg(feature = "flashloan_v2")]
                    {
                        if input.get_input_type() == Borrow {
                            return false;
                        }
                    }
                }
                Constraint::Contract(_) => {
                    #[cfg(feature = "flashloan_v2")]
                    {
                        if input.get_input_type() == Borrow {
                            return false;
                        }
                    }
                }
                _ => {}
            }
        }

        for constraint in constraints {
            match constraint {
                Constraint::Caller(caller) => {
                    input.set_caller_evm(caller);
                }
                Constraint::Value(value) => {
                    input.set_txn_value(value);
                }
                Constraint::Contract(target) => {
                    let rand_int = state.rand_mut().next();
                    let always_none = state.rand_mut().next() % 30 == 0;
                    let abis = state
                        .metadata_map()
                        .get::<ABIAddressToInstanceMap>()
                        .expect("ABIAddressToInstanceMap not found");
                    let abi = match abis.map.get(&target) {
                        Some(abi) => {
                            if !abi.is_empty() && !always_none {
                                Some((*abi)[rand_int as usize % abi.len()].clone())
                            } else {
                                None
                            }
                        }
                        None => None,
                    };
                    input.set_contract_and_abi(target, abi);
                }
                Constraint::NoLiquidation => {
                    #[cfg(feature = "flashloan_v2")]
                    {
                        input.set_liquidation_percent(0);
                    }
                }
                Constraint::MustStepNow => {
                    input.set_step(true);
                    // todo(@shou): move args into
                    // debug!("vm state: {:?}", input.get_state());
                    input.set_as_post_exec(new_vm_state.get_post_execution_needed_len());
                    input.mutate(state);
                }
            }
        }
        return true;
    }
}

impl<VS, Loc, Addr, SC, CI> Named for FuzzMutator<VS, Loc, Addr, SC, CI>
where
    VS: Default + VMStateT,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn name(&self) -> &str {
        "FuzzMutator"
    }
}

impl<VS, Loc, Addr, I, S, SC, CI> Mutator<I, S> for FuzzMutator<VS, Loc, Addr, SC, CI>
where
    I: VMInputT<VS, Loc, Addr, CI> + Input + EVMInputT,
    S: State
        + HasRand
        + HasMaxSize
        + HasItyState<Loc, Addr, VS, CI>
        + HasCaller<Addr>
        + HasMetadata,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    VS: Default + VMStateT + EVMStateT,
    Addr: PartialEq + Debug + Serialize + DeserializeOwned + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
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
            let concrete = state.get_infant_state(&mut self.infant_scheduler).unwrap();
            input.set_staged_state(concrete.1, concrete.0);
        }

        // determine whether we should conduct havoc
        // (a sequence of mutations in batch vs single mutation)
        // let mut amount_of_args = input.get_data_abi().map(|abi| abi.b.get_size()).unwrap_or(0) / 32 + 1;
        // if amount_of_args > 6 {
        //     amount_of_args = 6;
        // }
        let should_havoc = state.rand_mut().below(100) < 60; // (amount_of_args * 10) as u64;

        // determine how many times we should mutate the input
        let havoc_times = if should_havoc {
            state.rand_mut().below(10) + 1
        } else {
            1
        };

        let mut mutated = false;

        {
            if !input.is_step() && state.rand_mut().below(100) < 20_u64 {
                let old_idx = input.get_state_idx();
                let (idx, new_state) =
                    state.get_infant_state(&mut self.infant_scheduler).unwrap();
                if idx != old_idx {
                    if !state.has_caller(&input.get_caller()) {
                        input.set_caller(state.get_rand_caller());
                    }

                    if Self::ensures_constraint(input, state, &new_state.state, new_state.state.get_constraints()) {
                        mutated = true;
                        input.set_staged_state(new_state, idx);
                    }
                }
            }

            if input.get_staged_state().state.has_post_execution()
                    && !input.is_step()
                    && state.rand_mut().below(100) < 60_u64
            {


                macro_rules! turn_to_step {
                    () => {
                        input.set_step(true);
                        // todo(@shou): move args into
                        input.set_as_post_exec(input.get_state().get_post_execution_needed_len());
                        for _ in 0..havoc_times - 1 {
                            input.mutate(state);
                        }
                        mutated = true;
                    };
                }
                #[cfg(feature = "flashloan_v2")]
                {
                    if input.get_input_type() != Borrow {
                        turn_to_step!();
                    }
                }

                #[cfg(not(feature = "flashloan_v2"))]
                {
                    turn_to_step!();
                }

                return Ok(MutationResult::Mutated);
            }
        }



        // mutate the input once
        let mut mutator = || -> MutationResult {
            // if the input is a step input (resume execution from a control leak)
            // we should not mutate the VM state, but only mutate the bytes
            if input.is_step() {
                let res = match state.rand_mut().below(100) {
                    #[cfg(feature = "flashloan_v2")]
                    0..=5 => {
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
                    _ => input.mutate(state),
                };
                input.set_txn_value(EVMU256::ZERO);
                return res;
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
                    // mutate the bytes
                    _ => input.mutate(state),
                };
            }

            // mutate the bytes or VM state or liquidation percent (percentage of token to liquidate)
            // by default
            match state.rand_mut().below(100) {
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

        let mut res = if mutated {
            MutationResult::Mutated
        } else {
            MutationResult::Skipped
        };
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
}
