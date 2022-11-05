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
pub const VISIT_IGNORE_THRESHOLD: usize = 10;
pub const AMPLIFIER: usize = 10000;
#[derive(Debug, Clone)]
pub struct SortedDroppingScheduler {}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct VoteData {
    pub votes_and_visits: HashMap<usize, (usize, usize)>,
    pub visits_total: usize,
}

impl_serdeany!(VoteData);

impl<I, S> Scheduler<I, S> for SortedDroppingScheduler
where
    S: HasCorpus<I> + HasRand + HasMetadata,
    I: Input,
{
    fn on_add(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        if state.has_metadata::<VoteData>() {
            state.metadata_mut().insert(VoteData {
                votes_and_visits: HashMap::new(),
                visits_total: 0,
            });
        }

        {
            let mut data = state.metadata_mut().get_mut::<VoteData>().unwrap();
            data.votes_and_visits.insert(idx, (0, 1));
            data.visits_total += 1;
        }

        // this is costly, but we have to do it to keep the corpus not increasing indefinitely
        // todo(shou): merge visits and votes and check overhead vs effectiveness
        let mut to_remove: Vec<usize> = vec![];
        {
            let corpus_size = state.corpus().count();
            let corpus_mut = state.corpus_mut();
            let data = state.metadata().get::<VoteData>().unwrap();
            if corpus_size > DROP_THRESHOLD {
                // get top 100 entries sorted by votes (descending)
                let mut sorted: Vec<_> = data
                    .votes_and_visits
                    .iter()
                    .filter(|x| (x.1).1 > VISIT_IGNORE_THRESHOLD)
                    .collect();
                // sorted.sort_by(|a, b| (&(*a.1.0 / self.visits[a.0])).cmp(&(*b.1 / self.visits[b.0])));

                for i in sorted.iter().take(PRUNE_AMT) {
                    // corpus_mut.remove(*i.0);
                    // self.on_remove(state, *i.0, &None);
                    to_remove.push(*i.0);
                }
            }
        }
        {
            to_remove.iter().for_each(|x| {
                state.corpus_mut().remove(*x).expect("failed to remove");
                self.on_remove(state, *x, &None);
            });
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
        let data = state.metadata().get::<VoteData>().unwrap().clone();
        if corpus_size == 0 {
            Err(Error::empty("No entries in corpus".to_owned()))
        } else {
            // O(n) prob sampling - let's treat it as sorting :)
            let threshold =
                (state.rand_mut().below(1000) as f64 / 1000.0) * data.visits_total as f64;
            let mut k: usize = 0;
            for (idx, (_, visits)) in data.votes_and_visits.iter() {
                k += *visits;
                if k as f64 > threshold {
                    return Ok(*idx);
                }
            }
            Ok(*data.votes_and_visits.keys().last().unwrap())
        }
    }
}

impl<I, S> HasVote<I, S> for SortedDroppingScheduler
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
