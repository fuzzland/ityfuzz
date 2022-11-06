use libafl::corpus::Corpus;
use libafl::corpus::Testcase;
use libafl::prelude::{HasMetadata, HasRand, Input, Rand};
use libafl::schedulers::Scheduler;
use libafl::state::HasCorpus;
use libafl::{impl_serdeany, Error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
pub trait HasVote<I, S>
where
    S: HasCorpus<I> + HasRand + HasMetadata,
    I: Input,
{
    fn vote(&self, state: &mut S, idx: usize);
}

pub const DROP_THRESHOLD: usize = 1000;
pub const PRUNE_AMT: usize = 500;
pub const VISIT_IGNORE_THRESHOLD: usize = 2;
pub const AMPLIFIER: usize = 10000;
#[derive(Debug, Clone)]
pub struct SortedDroppingScheduler<I, S> {
    phantom: std::marker::PhantomData<(I, S)>,
}

impl<I, S> SortedDroppingScheduler<I, S> {
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct VoteData {
    pub votes_and_visits: HashMap<usize, (usize, usize)>,
    pub visits_total: usize,
}

impl_serdeany!(VoteData);

impl<I, S> Scheduler<I, S> for SortedDroppingScheduler<I, S>
where
    S: HasCorpus<I> + HasRand + HasMetadata,
    I: Input,
{
    fn on_add(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        if !state.has_metadata::<VoteData>() {
            state.metadata_mut().insert(VoteData {
                votes_and_visits: HashMap::new(),
                visits_total: 1,
            });
        }

        {
            let mut data = state.metadata_mut().get_mut::<VoteData>().unwrap();
            data.votes_and_visits.insert(idx, (0, 1));
            data.visits_total += 1;
        }

        // this is costly, but we have to do it to keep the corpus not increasing indefinitely
        let mut to_remove: Vec<usize> = vec![];
        {
            let corpus_size = state.corpus().count();
            let corpus_mut = state.corpus_mut();
            let data = state.metadata().get::<VoteData>().unwrap();
            if corpus_size > DROP_THRESHOLD {
                // get top 100 entries sorted by votes (descending)
                let mut sorted: Vec<_> = data.votes_and_visits.iter().collect();
                sorted.sort_by(|(idx_1, (votes1, visits1)), (idx_2, (votes2, visits2))| {
                    let score_1 = (*votes1 as f64) / (*visits1 as f64);
                    let score_2 = (*votes2 as f64) / (*visits2 as f64);
                    score_1.partial_cmp(&score_2).unwrap()
                });

                for i in sorted.iter().take(PRUNE_AMT) {
                    to_remove.push(*i.0);
                }

                to_remove.iter().for_each(|x| {
                    self.on_remove(state, *x, &None);
                    state.corpus_mut().remove(*x).expect("failed to remove");
                });
            }
        }
        Ok(())
    }

    fn on_remove(
        &self,
        state: &mut S,
        idx: usize,
        _testcase: &Option<Testcase<I>>,
    ) -> Result<(), Error> {
        let mut data = state.metadata_mut().get_mut::<VoteData>().unwrap();
        data.visits_total -= data.votes_and_visits.get(&idx).unwrap().1;
        data.votes_and_visits.remove(&idx);
        Ok(())
    }

    fn next(&self, state: &mut S) -> Result<usize, Error> {
        let corpus_size = state.corpus().count();
        let threshold = (state.rand_mut().below(1000) as f64 / 1000.0)
            * state.metadata().get::<VoteData>().unwrap().visits_total as f64;
        let mut data = state.metadata_mut().get_mut::<VoteData>().unwrap();
        if corpus_size == 0 {
            Err(Error::empty("No entries in corpus".to_owned()))
        } else {
            // get idx from votes_and_visits with lowest visits using a linear search
            let mut min_visits = std::usize::MAX;
            let mut min_idx = 0;
            for (idx, (_, visits)) in data.votes_and_visits.iter() {
                if *visits < min_visits {
                    min_visits = *visits;
                    min_idx = *idx;
                }
            }
            data.votes_and_visits.get_mut(&min_idx).unwrap().1 += 1;
            data.visits_total += 1;
            Ok(min_idx)
        }
    }
}

impl<I, S> HasVote<I, S> for SortedDroppingScheduler<I, S>
where
    S: HasCorpus<I> + HasRand + HasMetadata,
    I: Input,
{
    fn vote(&self, state: &mut S, idx: usize) {
        let mut data = state.metadata_mut().get_mut::<VoteData>().unwrap();
        let (votes, visits) = data
            .votes_and_visits
            .get_mut(&idx)
            .expect("scheduler metadata malformed");
        *votes += 1;
    }
}
