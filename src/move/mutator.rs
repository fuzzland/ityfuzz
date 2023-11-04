use std::fmt::Debug;

use libafl::{
    inputs::Input,
    mutators::{MutationResult, Mutator},
    prelude::{HasMaxSize, HasMetadata, HasRand, Scheduler, State},
    Error,
};
use libafl_bolts::{prelude::Rand, Named};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    generic_vm::vm_state::VMStateT,
    input::{ConciseSerde, VMInputT},
    r#move::{input::MoveFunctionInputT, vm_state::MoveVMStateT},
    state::{HasCaller, HasItyState, InfantStateState},
};

pub struct MoveFuzzMutator<VS, Loc, Addr, SC, CI>
where
    VS: Default + VMStateT,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    pub infant_scheduler: SC,
    pub phantom: std::marker::PhantomData<(VS, Loc, Addr, CI)>,
}

impl<VS, Loc, Addr, SC, CI> MoveFuzzMutator<VS, Loc, Addr, SC, CI>
where
    VS: Default + VMStateT,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    pub fn new(infant_scheduler: SC) -> Self {
        Self {
            infant_scheduler,
            phantom: Default::default(),
        }
    }
}

impl<VS, Loc, Addr, SC, CI> Named for MoveFuzzMutator<VS, Loc, Addr, SC, CI>
where
    VS: Default + VMStateT,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn name(&self) -> &str {
        "MoveFuzzMutator"
    }
}

impl<VS, Loc, Addr, I, S, SC, CI> Mutator<I, S> for MoveFuzzMutator<VS, Loc, Addr, SC, CI>
where
    I: VMInputT<VS, Loc, Addr, CI> + Input + MoveFunctionInputT,
    S: State + HasRand + HasMaxSize + HasItyState<Loc, Addr, VS, CI> + HasCaller<Addr> + HasMetadata,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    VS: Default + VMStateT + MoveVMStateT,
    Addr: PartialEq + Debug + Serialize + DeserializeOwned + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn mutate(&mut self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<MutationResult, Error> {
        // If the state is not initialized, initialize it
        if !input.get_staged_state().initialized {
            let concrete = state.get_infant_state(&mut self.infant_scheduler).unwrap();
            input.set_staged_state(concrete.1, concrete.0);
        }

        let should_havoc = state.rand_mut().below(100) < 60;
        let havoc_times = if should_havoc {
            state.rand_mut().below(10) + 1
        } else {
            1
        };

        let mut mutator = || -> MutationResult {
            match state.rand_mut().below(100) {
                0..=5 => {
                    // cross over infant state
                    // we need power schedule here for infant states
                    let old_idx = input.get_state_idx();
                    let (idx, new_state) = state.get_infant_state(&mut self.infant_scheduler).unwrap();
                    if idx == old_idx {
                        return MutationResult::Skipped;
                    }
                    if !input.ensure_deps(&new_state.state) {
                        return MutationResult::Skipped;
                    }
                    input.set_staged_state(new_state, idx);
                    // slash all structs in input right now and replace with those inside new state
                    input.slash(state);
                    input.set_resolved();
                    MutationResult::Mutated
                }
                _ => {
                    // debug!("mutating input");
                    if input.get_resolved() {
                        input.mutate(state)
                    } else {
                        MutationResult::Skipped
                    }
                }
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
}
