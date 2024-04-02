use std::collections::HashSet;

use itertools::Itertools;
use libafl::{
    corpus::{Corpus, Testcase},
    prelude::{CorpusId, HasCorpus, HasMetadata, HasRand, UsesInput},
    schedulers::{RemovableScheduler, Scheduler},
    state::UsesState,
    Error,
};
use libafl_bolts::{impl_serdeany, prelude::Rand};
use move_vm_types::loaded_data::runtime_types::Type;
use revm_primitives::HashMap;
use serde::{Deserialize, Serialize};

use crate::{
    r#move::types::{MoveFuzzState, MoveInfantStateState},
    scheduler::{HasReportCorpus, HasVote, SortedDroppingScheduler, VoteData},
};

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
    pub all_states: HashSet<usize>,
}

impl_serdeany!(MoveSchedulerMeta);

impl Default for MoveSchedulerMeta {
    fn default() -> Self {
        Self::new()
    }
}

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
        let entry = self.available_types.entry(new_ta.ty).or_default();
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

    /// Check whether a set of (type, amount) can be satisitied, return idxs of
    /// states
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
            idxs = idxs.intersection(idx).copied().collect();
        }
        idxs
    }
}

#[derive(Debug, Clone)]
pub struct MoveTestcaseScheduler<SC> {
    pub inner: SC,
}

impl<SC> MoveTestcaseScheduler<SC> {}

impl<SC> UsesState for MoveTestcaseScheduler<SC>
where
    SC: UsesState,
{
    type State = SC::State;
}

impl<SC> Scheduler for MoveTestcaseScheduler<SC>
where
    SC: Scheduler<State = MoveFuzzState>,
{
    fn on_add(&mut self, _state: &mut Self::State, _idx: CorpusId) -> Result<(), Error> {
        let tc = _state.corpus().get(_idx).expect("Missing testcase");
        let input = tc.borrow().input().clone().expect("Missing input");
        let meta = _state
            .infant_states_state
            .metadata_map_mut()
            .get_mut::<MoveSchedulerMeta>()
            .expect("Missing metadata");
        meta.testcase_to_deps.insert(
            _idx.into(),
            input
                ._deps
                .iter()
                .map(|(ty, amount)| TypeWithAmount::new(ty.clone(), *amount))
                .collect::<HashSet<_>>(),
        );
        self.inner.on_add(_state, _idx)
    }

    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error> {
        let mut next_idx = self.inner.next(state)?;
        let mut retries = 0;
        loop {
            retries += 1;
            if retries > 10000 {
                panic!("All functions depend on structs that are not available to be forged by the fuzzer. ");
            }
            let tc = state.corpus().get(next_idx).expect("Missing testcase");
            let input = tc.borrow().input().clone().expect("Missing input");
            let meta = state
                .infant_states_state
                .metadata_map_mut()
                .get_mut::<MoveSchedulerMeta>()
                .expect("Missing metadata");
            if input._deps.is_empty() {
                meta.current_working_states = meta.all_states.clone();
                break;
            } else {
                let tas = input
                    ._deps
                    .iter()
                    .map(|(ty, amount)| TypeWithAmount::new(ty.clone(), *amount))
                    .collect::<Vec<_>>();

                let satisfying_states = meta.satisfying_states(&tas);
                if !satisfying_states.is_empty() {
                    meta.current_working_states = satisfying_states;
                    break;
                }
                next_idx = self.inner.next(state)?;
            }
        }
        let meta = state
            .infant_states_state
            .metadata_map_mut()
            .get_mut::<MoveSchedulerMeta>()
            .expect("Missing metadata");
        meta.current_idx = next_idx.into();
        Ok(next_idx)
    }
}

impl<SC> RemovableScheduler for MoveTestcaseScheduler<SC> where SC: Scheduler<State = MoveFuzzState> {}

#[derive(Debug, Clone)]
pub struct MoveVMStateScheduler {
    pub inner: SortedDroppingScheduler<MoveInfantStateState>,
}

impl HasVote<MoveInfantStateState> for MoveVMStateScheduler {
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

impl UsesState for MoveVMStateScheduler {
    type State = MoveInfantStateState;
}

impl Scheduler for MoveVMStateScheduler {
    fn on_add(&mut self, state: &mut Self::State, idx: CorpusId) -> Result<(), Error> {
        let interesting_types = state
            .corpus()
            .get(idx)
            .expect("Missing infant state")
            .borrow()
            .input()
            .clone()
            .expect("Missing input")
            .state
            .values
            .iter()
            .map(|(ty, amount)| TypeWithAmount::new(ty.clone(), amount.iter().map(|(_, amt)| amt).sum::<usize>()))
            .collect_vec();
        let meta = state
            .metadata_map_mut()
            .get_mut::<MoveSchedulerMeta>()
            .expect("Missing metadata");
        meta.all_states.insert(idx.into());
        let entry = meta.state_to_deps.entry(idx.into()).or_insert(Default::default());
        interesting_types.iter().for_each(|v| {
            entry.insert(v.clone());
        });

        for ta in interesting_types {
            meta.add_type(ta, idx.into());
        }

        let res = self.inner.on_add(state, idx);
        {
            let votes_meta = state
                .metadata_map_mut()
                .get_mut::<VoteData>()
                .expect("Missing metadata");
            if !votes_meta.to_remove.is_empty() {
                let to_remove = votes_meta.to_remove.clone();
                votes_meta.to_remove.clear();
                for idx in to_remove {
                    self.on_remove(state, idx.into(), &None).expect("Failed to remove");
                }
            }
        }
        res
    }

    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error> {
        let meta = state
            .metadata_map_mut()
            .get_mut::<MoveSchedulerMeta>()
            .expect("Missing metadata");
        let sample_idx = meta.current_working_states.clone();

        let mut total_votes = 0;
        let mut sample_list = vec![];
        {
            let sampling_meta = state.metadata_map().get::<VoteData>().unwrap();
            for idx in sample_idx {
                let (votes, visits) = sampling_meta.votes_and_visits.get(&idx).unwrap();
                sample_list.push((idx, (*votes, *visits)));
                total_votes += *votes;
            }
        }

        let mut s: f64 = 0.0; // sum of votes so far
        let mut idx = usize::MAX;
        let threshold = (state.rand_mut().below(1000) as f64 / 1000.0) * total_votes as f64;

        for (sample_idx, (votes, _)) in &sample_list {
            s += *votes as f64;
            if s > threshold {
                idx = *sample_idx;
                break;
            }
        }

        if idx == usize::MAX {
            // if we didn't find an input, just use the last one
            idx = sample_list.last().unwrap().0;
        }

        {
            let sampling_meta = state.metadata_map_mut().get_mut::<VoteData>().unwrap();
            sampling_meta.votes_and_visits.get_mut(&idx).unwrap().1 += 1;
            sampling_meta.visits_total += 1;
        }

        Ok(idx.into())
    }
}

impl RemovableScheduler for MoveVMStateScheduler
where
    Self::State: UsesInput,
{
    fn on_remove(
        &mut self,
        state: &mut Self::State,
        idx: CorpusId,
        _testcase: &Option<Testcase<<Self::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        let idx = usize::from(idx);
        let meta = state
            .metadata_map_mut()
            .get_mut::<MoveSchedulerMeta>()
            .expect("Missing metadata");
        meta.remove_type(idx);
        meta.state_to_deps.remove(&idx);
        meta.all_states.remove(&idx);
        meta.current_working_states.remove(&idx);

        Ok(())
    }
}
