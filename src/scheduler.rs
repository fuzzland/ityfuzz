/// Corpus schedulers for ItyFuzz
/// Used to determine which input / VMState to fuzz next

use libafl::corpus::Corpus;
use libafl::corpus::Testcase;
use libafl::prelude::{HasMetadata, HasRand, Input, Rand};
use libafl::schedulers::Scheduler;
use libafl::state::HasCorpus;
use libafl::{impl_serdeany, Error};

use serde::{Deserialize, Serialize};

use rand::random;
use std::collections::HashMap;
use std::fmt::Debug;

/// A trait providing functions necessary for voting mechanisms
pub trait HasVote<I, S>
where
    S: HasCorpus<I> + HasRand + HasMetadata,
    I: Input,
{
    fn vote(&self, state: &mut S, idx: usize);
}

/// The maximum number of inputs (or VMState) to keep in the corpus before pruning
pub const DROP_THRESHOLD: usize = 500;
/// The number of inputs (or VMState) to prune each time the corpus is pruned
pub const PRUNE_AMT: usize = 250;
/// If inputs (or VMState) has not been visited this many times, it will be ignored during pruning
pub const VISIT_IGNORE_THRESHOLD: usize = 2;

/// A scheduler that drops inputs (or VMState) based on a voting mechanism
#[derive(Debug, Clone)]
pub struct SortedDroppingScheduler<I, S> {
    phantom: std::marker::PhantomData<(I, S)>,
}

impl<I, S> SortedDroppingScheduler<I, S> {
    /// Create a new SortedDroppingScheduler
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }
}

/// Metadata for [`SortedDroppingScheduler`] that is stored in the state
/// Contains the votes and visits for each input (or VMState)
#[derive(Serialize, Deserialize, Clone, Debug)]
struct VoteData {
    /// Map of input (or VMState) index to (votes, visits)
    pub votes_and_visits: HashMap<usize, (usize, usize)>,
    /// Sorted list of votes, cached for performance
    pub sorted_votes: Vec<usize>,
    /// Total number of visits, cached for performance
    pub visits_total: usize,
    /// Total number of votes, cached for performance
    pub votes_total: usize,
}

impl_serdeany!(VoteData);


/// The number of inputs (or VMState) already removed from the corpus
#[cfg(feature = "full_trace")]
pub static mut REMOVED_CORPUS: usize = 0;

impl<I, S> Scheduler<I, S> for SortedDroppingScheduler<I, S>
where
    S: HasCorpus<I> + HasRand + HasMetadata,
    I: Input + Debug,
{
    /// Hooks called every time an input (or VMState) is added to the corpus
    /// Set up the metadata for the input (or VMState)
    fn on_add(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        // Initialize metadata if it doesn't exist
        if !state.has_metadata::<VoteData>() {
            state.metadata_mut().insert(VoteData {
                votes_and_visits: HashMap::new(),
                sorted_votes: vec![],
                visits_total: 1,
                votes_total: 1,
            });
        }

        // Setup metadata for the input (or VMState)
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
            let mut corpus_size = state.corpus().count();
            let _corpus_mut = state.corpus_mut();
            let data = state.metadata().get::<VoteData>().unwrap();
            #[cfg(feature = "full_trace")]
            {
                corpus_size -= unsafe { REMOVED_CORPUS };
            }

            // If the corpus is too large (> [`DROP_THRESHOLD`]), prune it
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

                // Remove inputs (or VMState) from metadata and corpus
                to_remove.iter().for_each(|x| {
                    self.on_remove(state, *x, &None);
                    #[cfg(feature = "full_trace")]
                    {
                        unsafe {
                            REMOVED_CORPUS += 1;
                        }
                    }
                    #[cfg(not(feature = "full_trace"))]
                    {
                        state.corpus_mut().remove(*x).expect("failed to remove");
                    }
                });
            }
        }
        Ok(())
    }

    /// Hooks called every time an input (or VMState) is removed from the corpus
    /// Update the metadata caches for the input (or VMState)
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

    /// Selects next input (or VMState) to run
    fn next(&self, state: &mut S) -> Result<usize, Error> {
        // Debugging prints
        #[cfg(feature = "print_infant_corpus")]
        {
            let corpus_size = state.corpus().count();
            let data = state.metadata().get::<VoteData>().unwrap();
            use crate::r#const::DEBUG_PRINT_PERCENT;
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

        // Conduct a probabilistic sampling from votes and visits (weighted by votes)
        let threshold = (state.rand_mut().below(1000) as f64 / 1000.0)
            * state.metadata().get::<VoteData>().unwrap().votes_total as f64;
        let mut data = state.metadata_mut().get_mut::<VoteData>().unwrap();
        let mut idx = usize::MAX;

        let mut s: f64 = 0.0; // sum of votes so far

        for i in &data.sorted_votes {
            s += data.votes_and_visits.get(&i).unwrap().0 as f64;
            if s > threshold {
                idx = *i;
                break;
            }
        }

        if idx == usize::MAX {  // if we didn't find an input, just use the last one
            idx = *data.sorted_votes.last().unwrap();
        }

        // Update metadata
        {
            data.votes_and_visits.get_mut(&idx).unwrap().1 += 1;
            data.visits_total += 1;
        }

        Ok(idx)
    }
}

impl<I, S> HasVote<I, S> for SortedDroppingScheduler<I, S>
where
    S: HasCorpus<I> + HasRand + HasMetadata,
    I: Input,
{
    /// Vote for an input (or VMState)
    fn vote(&self, state: &mut S, idx: usize) {
        let data = state.metadata_mut().get_mut::<VoteData>().unwrap();

        // increment votes for the input (or VMState)
        let mut increment = 3; //data.votes_total / data.votes_and_visits.len();
        if increment < 1 {
            increment = 1;
        }
        data.votes_total += increment;
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
