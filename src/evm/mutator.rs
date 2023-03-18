use crate::evm::mutation_utils::VMStateHintedMutator;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, InfantStateState};
use libafl::inputs::Input;
use libafl::mutators::MutationResult;
use libafl::prelude::{HasMaxSize, HasRand, Mutator, Rand, State};
use libafl::schedulers::Scheduler;
use libafl::Error;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::ops::Add;

use crate::state::HasItyState;
use crate::state_input::StagedVMState;

pub struct FuzzMutator<'a, VS, Loc, Addr, SC>
where
    VS: Default + VMStateT,
    SC: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
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
    pub fn new(infant_scheduler: &'a SC) -> Self {
        Self {
            infant_scheduler,
            phantom: Default::default(),
        }
    }
}

impl<'a, VS, Loc, Addr, I, S, SC> Mutator<I, S> for FuzzMutator<'a, VS, Loc, Addr, SC>
where
    I: VMInputT<VS, Loc, Addr> + Input,
    S: State + HasRand + HasMaxSize + HasItyState<Loc, Addr, VS> + HasCaller<Addr>,
    SC: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    VS: Default + VMStateT,
    Addr: PartialEq + Debug + Serialize + DeserializeOwned + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if !input.get_staged_state().initialized {
            let concrete = state.get_infant_state(self.infant_scheduler).unwrap();
            input.set_staged_state(concrete.1, concrete.0);
        }
        let should_havoc = state.rand_mut().below(100) < 60;
        let havoc_times = if should_havoc {
            state.rand_mut().below(10) + 1
        } else {
            1
        };
        let mut mutator = || -> MutationResult {
            if input.is_step() {
                return input.mutate(state);
            }
            match state.rand_mut().below(100) {
                1..=5 => {
                    // mutate the caller
                    let caller = state.get_rand_caller();
                    if caller == input.get_caller() {
                        return MutationResult::Skipped;
                    }
                    input.set_caller(caller);
                    MutationResult::Mutated
                }
                6..=10 => {
                    // cross over infant state
                    // we need power schedule here for infant states
                    let old_idx = input.get_state_idx();
                    let (idx, new_state) = state.get_infant_state(self.infant_scheduler).unwrap();
                    if idx == old_idx {
                        return MutationResult::Skipped;
                    }
                    input.set_staged_state(new_state, idx);
                    MutationResult::Mutated
                }
                11..=15 => match input.get_txn_value() {
                    Some(_) => {
                        input.set_txn_value(state.rand_mut().next() as usize);
                        MutationResult::Mutated
                    }
                    None => MutationResult::Skipped,
                },
                16..=20 => {
                    // make it a step forward to pop one post execution
                    // todo(@shou): fix the sizing of return
                    if input.get_staged_state().state.has_post_execution() && !input.is_step() {
                        input.set_step(true);
                        // todo(@shou): move args into
                        input.set_as_post_exec(
                            input.get_state().get_post_execution_needed_len() as usize
                        );
                        MutationResult::Mutated
                    } else {
                        MutationResult::Skipped
                    }
                }
                _ => input.mutate(state),
            }
        };

        let mut res = MutationResult::Skipped;
        let mut tries = 0;
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
