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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoveSchedulerMeta {
    // managed by MoveTestcaseScheduler
    pub current_idx: usize,
    pub current_deps: HashSet<Type>,
    pub testcase_to_deps: HashMap<usize, HashSet<Type>>,

    // managed by MoveVMStateScheduler
    pub deps_state_idx: HashMap<Type, HashSet<usize>>,
    pub state_idx_to_deps: HashMap<usize, HashSet<Type>>,
    pub unavailable_types: HashSet<Type>,
}

impl_serdeany!(MoveSchedulerMeta);

impl MoveSchedulerMeta {
    pub fn new() -> Self {
        Self {
            current_idx: 0,
            current_deps: HashSet::new(),
            testcase_to_deps: HashMap::new(),
            deps_state_idx: HashMap::new(),
            state_idx_to_deps: HashMap::new(),
            unavailable_types: HashSet::new(),
        }
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
        if !input._resolved {
            input._deps.iter().for_each(
                |(ty, amount)| {
                    meta.unavailable_types.insert(ty.clone());
                }
            )
        }
        meta.testcase_to_deps.insert(_idx, input._deps.keys().cloned().collect::<HashSet<_>>());
        self.inner.on_add(_state, _idx)
    }

    fn next(&self, state: &mut MoveFuzzState) -> Result<usize, Error> {
        let mut next_idx = self.inner.next(state)?;
        loop {
            let tc = state.corpus().get(next_idx).expect("Missing testcase");
            let input = tc.borrow().input().clone().expect("Missing input");
            {
                let mut meta = state.infant_states_state.metadata_mut().get_mut::<MoveSchedulerMeta>().expect("Missing metadata");
                if input._deps.iter().all(
                    |(ty, amount)| {
                        if meta.unavailable_types.contains(ty) {
                            return false;
                        }
                        true
                    }) {
                    break;
                }
                next_idx = self.inner.next(state)?;
            }
        }
        let mut meta = state.infant_states_state.metadata_mut().get_mut::<MoveSchedulerMeta>().expect("Missing metadata");
        meta.current_idx = next_idx;
        meta.current_deps = meta.testcase_to_deps.get(&next_idx).expect("Missing deps").clone();
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
            .keys()
            .cloned()
            .collect_vec();
        let mut meta = state.metadata_mut().get_mut::<MoveSchedulerMeta>().expect("Missing metadata");
        interesting_types.iter().for_each(
            |v| {
                meta.deps_state_idx.entry(v.clone()).or_insert(Default::default()).insert(idx);
                meta.unavailable_types.remove(v);
            }
        );
        let entry = meta.state_idx_to_deps.entry(idx).or_insert(Default::default());
        interesting_types.iter().for_each(
            |v| {
                entry.insert(v.clone());
            }
        );
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
        // println!("Removing state: {:?}", idx);
        meta.state_idx_to_deps.get(&idx).expect("Missing state idx").iter().for_each(
            |v| {
                let all_idx = meta.deps_state_idx.get_mut(v).expect("Missing deps");
                all_idx.remove(&idx);
                if all_idx.is_empty() {
                    meta.unavailable_types.insert(v.clone());
                }
            }
        );
        meta.state_idx_to_deps.remove(&idx);
        // self.inner.on_remove(state, idx, _testcase)
        Ok(())
    }

    fn next(&self, state: &mut MoveInfantStateState) -> Result<usize, Error> {

        let mut sample_idx = vec![];
        {
            let mut meta = state.metadata_mut().get_mut::<MoveSchedulerMeta>().expect("Missing metadata");

            // println!("now we need to find a state with deps: {:?}", meta.current_deps);
            if meta.current_deps.len() == 0 {
                return self.inner.next(state);
            }
            for (idx, tys) in &meta.state_idx_to_deps {
                if tys.is_superset(&meta.current_deps) {
                    sample_idx.push(*idx);
                }
            }
        }

        let mut total_votes = 0;
        let mut sample_list = vec![];
        {
            let mut sampling_meta = state.metadata().get::<VoteData>().unwrap();
            for idx in sample_idx {
                // println!("idx: {}", idx);
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


