use std::collections::HashSet;
use itertools::Itertools;
use libafl::corpus::{Corpus, Testcase};
use libafl::{Error, impl_serdeany};
use libafl::inputs::Input;
use libafl::prelude::{HasCorpus, HasMetadata, HasRand, Rand, Scheduler};
use move_vm_types::loaded_data::runtime_types::Type;
use revm_primitives::HashMap;
use serde::{Deserialize, Serialize};
use crate::r#move::input::{ConciseMoveInput, MoveFunctionInput, MoveFunctionInputT};
use crate::r#move::types::{MoveAddress, MoveFuzzState, MoveInfantStateState, MoveLoc, MoveStagedVMState};
use crate::r#move::vm_state::MoveVMState;
use crate::scheduler::{HasReportCorpus, HasVote, SortedDroppingScheduler, VoteData};
use crate::state::InfantStateState;

// A scheduler that ensures that all dependencies of a test case are available
// before executing it.
#[derive(Clone, Debug, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct TypeWithAmount {
    pub ty: Type,
    pub amount: usize,
}

impl TypeWithAmount {
    pub fn new(ty: Type, amount: usize) -> Self {
        Self { ty, amount }
    }

    pub fn satisfied_by(&self, other: &TypeWithAmount) -> bool {
        self.amount <= other.amount
    }

    pub fn max(&mut self, other: &TypeWithAmount) {
        self.amount = std::cmp::max(self.amount, other.amount);
    }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoveSchedulerMeta {
    // managed by MoveTestcaseScheduler
    pub current_idx: usize,
    pub current_working_states: HashSet<usize>,
    pub testcase_to_deps: HashMap<usize, HashSet<TypeWithAmount>>,

    // managed by MoveVMStateScheduler

    pub state_to_deps: HashMap<usize, HashSet<TypeWithAmount>>,
    // type -> [amount, [idx]]
    pub available_types: HashMap<Type, Vec<(usize, HashSet<usize>)>>,
    pub all_states: HashSet<usize>
}


impl_serdeany!(MoveSchedulerMeta);

impl MoveSchedulerMeta {
    pub fn new() -> Self {
        Self {
            current_idx: 0,
            current_working_states: HashSet::new(),
            testcase_to_deps: HashMap::new(),
            state_to_deps: Default::default(),
            available_types: Default::default(),
            all_states: Default::default(),
        }
    }

    pub fn add_type(&mut self, new_ta: TypeWithAmount, idx: usize) {
        let entry = self.available_types.entry(new_ta.ty).or_insert(vec![]);
        for (amount, idxs) in entry.iter_mut() {
            if *amount == new_ta.amount {
                idxs.insert(idx);
                return;
            }
        }
        entry.push((new_ta.amount, HashSet::from([idx])));
    }

    pub fn remove_type(&mut self, idx: usize) {
        for ta in self.state_to_deps.get(&idx).expect("Missing state").iter() {
            let entry = self.available_types.get_mut(&ta.ty).expect("Missing type");
            for (amount, idxs) in entry {
                if *amount == ta.amount {
                    idxs.remove(&idx);
                    return;
                }
            }
        }
    }

    /// Check whether a set of (type, amount) can be satisitied, return idxs of states
    pub fn satisfying_states(&self, tas: &Vec<TypeWithAmount>) -> HashSet<usize> {
        let mut idx_to_intersect = vec![];
        for ta in tas {
            let entry = match self.available_types.get(&ta.ty) {
                Some(entry) => entry,
                None => return HashSet::new(),
            };

            let mut all_idxs = HashSet::new();
            for (amount, idxs) in entry {
                if *amount >= ta.amount {
                    all_idxs.extend(idxs);
                }
            }
            idx_to_intersect.push(all_idxs);
        }

        // now, intersect all idxs
        let mut idxs = idx_to_intersect[0].clone();
        for idx in idx_to_intersect.iter().skip(1) {
            idxs = idxs.intersection(idx).map(|x| *x).collect();
        }
        idxs
    }
}


pub struct MoveTestcaseScheduler<SC> {
    pub inner: SC,
}


impl<SC> MoveTestcaseScheduler<SC> {
}


impl<SC> Scheduler<MoveFunctionInput, MoveFuzzState> for MoveTestcaseScheduler<SC>
    where SC: Scheduler<MoveFunctionInput, MoveFuzzState>
{
    fn on_add(&self, _state: &mut MoveFuzzState, _idx: usize) -> Result<(), Error> {
        let tc = _state.corpus().get(_idx).expect("Missing testcase");
        let input = tc.borrow().input().clone().expect("Missing input");
        let meta = _state.infant_states_state.metadata_mut().get_mut::<MoveSchedulerMeta>().expect("Missing metadata");
        meta.testcase_to_deps
            .insert(
                _idx,
                input._deps
                    .iter()
                    .map(|(ty, amount)| TypeWithAmount::new(ty.clone(), *amount))
                    .collect::<HashSet<_>>()
            );
        self.inner.on_add(_state, _idx)
    }

    fn next(&self, state: &mut MoveFuzzState) -> Result<usize, Error> {
        let mut next_idx = self.inner.next(state)?;
        loop {
            let tc = state.corpus().get(next_idx).expect("Missing testcase");
            let input = tc.borrow().input().clone().expect("Missing input");
            let mut meta = state.infant_states_state.metadata_mut().get_mut::<MoveSchedulerMeta>().expect("Missing metadata");
            if input._deps.len() == 0 {
                meta.current_working_states = meta.all_states.clone();
                break;
            } else {
                let tas = input._deps
                    .iter()
                    .map(|(ty, amount)| TypeWithAmount::new(ty.clone(), *amount))
                    .collect::<Vec<_>>();

                let satisfying_states = meta.satisfying_states(&tas);
                if satisfying_states.len() > 0 {
                    meta.current_working_states = satisfying_states;
                    break;
                }
                next_idx = self.inner.next(state)?;
            }
        }
        let mut meta = state
            .infant_states_state
            .metadata_mut()
            .get_mut::<MoveSchedulerMeta>()
            .expect("Missing metadata");
        meta.current_idx = next_idx;
        Ok(next_idx)
    }
}


pub struct MoveVMStateScheduler {
    pub inner: SortedDroppingScheduler<MoveStagedVMState, MoveInfantStateState>
}

impl HasVote<MoveStagedVMState, MoveInfantStateState> for MoveVMStateScheduler {
    fn vote(&self, state: &mut MoveInfantStateState, idx: usize, amount: usize) {
        self.inner.vote(state, idx, amount)
    }
}

impl HasReportCorpus<MoveInfantStateState> for MoveVMStateScheduler {
    fn report_corpus(&self, state: &mut MoveInfantStateState, state_idx: usize) {
        self.inner.report_corpus(state, state_idx)
    }

    fn sponsor_state(&self, state: &mut MoveInfantStateState, state_idx: usize, amt: usize) {
        self.inner.sponsor_state(state, state_idx, amt)
    }
}


impl Scheduler<MoveStagedVMState, MoveInfantStateState> for MoveVMStateScheduler {
    fn on_add(&self, state: &mut MoveInfantStateState, idx: usize) -> Result<(), Error> {
        let interesting_types = state.corpus().get(idx).expect("Missing infant state")
            .borrow()
            .input()
            .clone()
            .expect("Missing input")
            .state
            .values
            .iter()
            .map(|(ty, amount)| TypeWithAmount::new(ty.clone(), amount.iter().map(|(_, amt)| amt).sum::<usize>()))
            .collect_vec();
        let mut meta = state.metadata_mut().get_mut::<MoveSchedulerMeta>().expect("Missing metadata");
        meta.all_states.insert(idx);
        let entry = meta.state_to_deps.entry(idx).or_insert(Default::default());
        interesting_types.iter().for_each(
            |v| {
                entry.insert(v.clone());
            }
        );

        for ta in interesting_types{
            meta.add_type(ta, idx);
        }


        let res = self.inner.on_add(state, idx);
        {
            let votes_meta = state.metadata_mut().get_mut::<VoteData>().expect("Missing metadata");
            if votes_meta.to_remove.len() > 0 {
                let to_remove = votes_meta.to_remove.clone();
                votes_meta.to_remove.clear();
                for idx in to_remove {
                    self.on_remove(state, idx, &None).expect("Failed to remove");
                }
            }
        }
        res
    }

    fn on_remove(&self, state: &mut MoveInfantStateState, idx: usize, _testcase: &Option<Testcase<MoveStagedVMState>>) -> Result<(), Error> {
        let mut meta = state.metadata_mut().get_mut::<MoveSchedulerMeta>().expect("Missing metadata");
        meta.remove_type(idx);
        meta.state_to_deps.remove(&idx);
        meta.all_states.remove(&idx);
        meta.current_working_states.remove(&idx);

        Ok(())
    }

    fn next(&self, state: &mut MoveInfantStateState) -> Result<usize, Error> {
        let mut sample_idx = HashSet::new();
        {
            let mut meta = state.metadata_mut().get_mut::<MoveSchedulerMeta>().expect("Missing metadata");
            sample_idx = meta.current_working_states.clone();
        }

        let mut total_votes = 0;
        let mut sample_list = vec![];
        {
            let mut sampling_meta = state.metadata().get::<VoteData>().unwrap();
            for idx in sample_idx {
                let (votes, visits) = sampling_meta.votes_and_visits.get(&idx).unwrap();
                sample_list.push((idx, (*votes, *visits)));
                total_votes += *votes;
            }
        }

        let mut s: f64 = 0.0; // sum of votes so far
        let mut idx = usize::MAX;
        let threshold = (state.rand_mut().below(1000) as f64 / 1000.0)
            * total_votes as f64;

        for (sample_idx, (votes, _)) in &sample_list {
            s += *votes as f64;
            if s > threshold {
                idx = *sample_idx;
                break;
            }
        }

        if idx == usize::MAX {  // if we didn't find an input, just use the last one
            idx = sample_list.last().unwrap().0;
        }

        {
            let sampling_meta = state.metadata_mut().get_mut::<VoteData>().unwrap();
            sampling_meta.votes_and_visits.get_mut(&idx).unwrap().1 += 1;
            sampling_meta.visits_total += 1;
        }

        Ok(idx)
    }
}


