use crate::config::DEBUG_PRINT_PERCENT;
use libafl::corpus::Corpus;
use libafl::corpus::Testcase;
use libafl::prelude::{HasMetadata, HasRand, Input, Rand};
use libafl::schedulers::Scheduler;
use libafl::state::HasCorpus;
use libafl::{impl_serdeany, Error};
use rand::random;
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Deref;

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
    pub sorted_votes: Vec<usize>,
    pub visits_total: usize,
    pub votes_total: usize,
}

impl_serdeany!(VoteData);

impl<I, S> Scheduler<I, S> for SortedDroppingScheduler<I, S>
where
    S: HasCorpus<I> + HasRand + HasMetadata,
    I: Input + Debug,
{
    fn on_add(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        if !state.has_metadata::<VoteData>() {
            state.metadata_mut().insert(VoteData {
                votes_and_visits: HashMap::new(),
                sorted_votes: vec![],
                visits_total: 1,
                votes_total: 1,
            });
        }

        {
            let mut data = state.metadata_mut().get_mut::<VoteData>().unwrap();
            data.votes_and_visits.insert(idx, (3, 1));
            data.visits_total += 1;
            data.votes_total += 3;
            data.sorted_votes.push(idx);
        }

        // this is costly, but we have to do it to keep the corpus not increasing indefinitely
        let mut to_remove: Vec<usize> = vec![];
        {
            let corpus_size = state.corpus().count();
            let _corpus_mut = state.corpus_mut();
            let data = state.metadata().get::<VoteData>().unwrap();
            if corpus_size > DROP_THRESHOLD {
                // get top 100 entries sorted by votes (descending)
                let mut sorted: Vec<_> = data.votes_and_visits.iter().collect();
                sorted.sort_by(|(_idx_1, (votes1, visits1)), (_idx_2, (votes2, visits2))| {
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
        data.votes_total -= data.votes_and_visits.get(&idx).unwrap().0;
        data.visits_total -= data.votes_and_visits.get(&idx).unwrap().1;
        data.votes_and_visits.remove(&idx);
        data.sorted_votes.retain(|x| *x != idx);
        Ok(())
    }

    fn next(&self, state: &mut S) -> Result<usize, Error> {
        let corpus_size = state.corpus().count();

        #[cfg(feature = "print_corpus")]
        {
            let data = state.metadata().get::<VoteData>().unwrap();
            if random::<usize>() % DEBUG_PRINT_PERCENT == 0 {
                println!(
                    "======================= corpus size: {} =======================",
                    corpus_size
                );
                for idx in &data.sorted_votes {
                    let (votes, visits) = data.votes_and_visits.get(&idx).unwrap();
                    let inp = state.corpus().get(*idx).unwrap().clone();
                    match inp.into_inner().input() {
                        Some(x) => {
                            println!(
                                "idx: {}, votes: {}, visits: {}: {:?}",
                                idx, votes, visits, x
                            );
                        }
                        _ => {}
                    }
                }
                println!("======================= corpus  =======================");
            }
        }

        let threshold = (state.rand_mut().below(1000) as f64 / 1000.0)
            * state.metadata().get::<VoteData>().unwrap().votes_total as f64;

        let mut data = state.metadata_mut().get_mut::<VoteData>().unwrap();
        if corpus_size == 0 {
            Err(Error::empty("No entries in corpus".to_owned()))
        } else {
            // probablistic sampling from votes and visits (weighted by votes)
            let mut idx = *data.sorted_votes.last().unwrap();

            let mut s: f64 = 0.0;
            for i in data.sorted_votes.clone() {
                s += data.votes_and_visits.get(&i).unwrap().0 as f64;
                if s > threshold {
                    idx = i;
                    break;
                }
            }

            data.votes_and_visits.get_mut(&idx).unwrap().1 += 1;
            data.visits_total += 1;
            Ok(idx)
        }
    }
}

impl<I, S> HasVote<I, S> for SortedDroppingScheduler<I, S>
where
    S: HasCorpus<I> + HasRand + HasMetadata,
    I: Input,
{
    fn vote(&self, state: &mut S, idx: usize) {
        let data = state.metadata_mut().get_mut::<VoteData>().unwrap();
        let increment = 1;
        {
            data.votes_total += increment;
        }

        {
            let v = data.votes_and_visits.get_mut(&idx);
            if v.is_some() {
                let (votes, _visits) = v.expect("scheduler metadata malformed");
                *votes += increment;
                println!("Voted for {}", idx);
            } else {
                println!("scheduler metadata malformed");
            }
        }

        // resort the sorted_votes vector with respect to votes and visits
        {
            data.sorted_votes.sort_by(|x, y| {
                let (votes_x, _) = data.votes_and_visits.get(x).unwrap();
                let (votes_y, _) = data.votes_and_visits.get(y).unwrap();
                votes_y.cmp(votes_x)
            });
        }
    }
}
