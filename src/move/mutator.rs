use std::fmt::Debug;
use libafl::Error;
use libafl::inputs::Input;
use libafl::mutators::{MutationResult, Mutator};
use libafl::prelude::{HasMaxSize, HasMetadata, HasRand, Rand, Scheduler, State};
use serde::de::DeserializeOwned;
use serde::Serialize;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::r#move::input::MoveFunctionInputT;
use crate::r#move::vm_state::MoveVMStateT;
use crate::state::{HasCaller, HasItyState, InfantStateState};
use crate::state_input::StagedVMState;

pub struct MoveFuzzMutator<'a, VS, Loc, Addr, SC>
    where
        VS: Default + VMStateT,
        SC: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
        Addr: Serialize + DeserializeOwned + Debug + Clone,
        Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    pub infant_scheduler: &'a SC,
    pub phantom: std::marker::PhantomData<(VS, Loc, Addr)>,
}

impl<'a, VS, Loc, Addr, SC> MoveFuzzMutator<'a, VS, Loc, Addr, SC>
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

impl<'a, VS, Loc, Addr, I, S, SC> Mutator<I, S> for MoveFuzzMutator<'a, VS, Loc, Addr, SC>
    where
        I: VMInputT<VS, Loc, Addr> + Input + MoveFunctionInputT,
        S: State + HasRand + HasMaxSize + HasItyState<Loc, Addr, VS> + HasCaller<Addr> + HasMetadata,
        SC: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
        VS: Default + VMStateT + MoveVMStateT,
        Addr: PartialEq + Debug + Serialize + DeserializeOwned + Clone,
        Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // If the state is not initialized, initialize it
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
            match state.rand_mut().below(100) {
                0..=5 => {
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
