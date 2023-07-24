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
use revm_primitives::HashSet;
use serde::de::DeserializeOwned;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::ConciseSerde;
use crate::state::HasParent;

/// A trait providing functions necessary for voting mechanisms
pub trait HasVote<I, S>
where
    S: HasCorpus<I> + HasRand + HasMetadata,
    I: Input,
{
    fn vote(&self, state: &mut S, idx: usize, amount: usize);
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
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Node {
    parent: usize, // 0 for root node
    ref_count: usize,
    pending_delete: bool,
    never_delete: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct DependencyTree {
    nodes: HashMap<usize, Node>,
}

impl DependencyTree {
    pub fn add_node(&mut self, idx: usize, parent: usize) {
        self.nodes.insert(idx, Node {
            parent,
            ref_count: 1,
            pending_delete: false,
            never_delete: false,
        });
        let mut parent = parent;
        while parent != 0 {
            let node = self.nodes.get_mut(&parent).unwrap();
            node.ref_count += 1;
            parent = node.parent;
        }
    }

    pub fn remove_node(&mut self, idx: usize) {
        let mut node = self.nodes.get_mut(&idx).unwrap();
        node.ref_count -= 1;
        node.pending_delete = true;
        let mut parent = node.parent;
        while parent != 0 {
            let node = self.nodes.get_mut(&parent).unwrap();
            node.ref_count -= 1;
            parent = node.parent;
        }
    }

    pub fn mark_never_delete(&mut self, idx: usize) {
        let mut node = self.nodes.get_mut(&idx).unwrap();
        node.never_delete = true;
        let mut parent = node.parent;
        while parent != 0 {
            let node = self.nodes.get_mut(&parent).unwrap();
            node.never_delete = true;
            parent = node.parent;
        }
    }

    pub fn garbage_collection(&mut self) -> Vec<usize> {
        let mut to_remove = vec![];
        for (idx, node) in self.nodes.iter() {
            if node.ref_count == 0 && node.pending_delete && !node.never_delete {
                to_remove.push(*idx);
            }
        }
        for idx in &to_remove {
            self.nodes.remove(idx);
        }
        to_remove
    }

    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
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
    /// Garbage collection: Dependencies Graph
    pub deps: DependencyTree,
}

pub trait HasReportCorpus<S>
    where S: HasMetadata {
    fn report_corpus(&self, state: &mut S, state_idx: usize);
}

impl<I, S> HasReportCorpus<S> for SortedDroppingScheduler<I, S>
    where
        S: HasCorpus<I> + HasRand + HasMetadata + HasParent,
        I: Input + Debug,
{
    fn report_corpus(&self, state: &mut S, state_idx: usize) {
        self.vote(state, state_idx, 3);
        let mut data = state.metadata_mut().get_mut::<VoteData>().unwrap();
        data.deps.mark_never_delete(state_idx);
    }
}



impl_serdeany!(VoteData);

/// The number of inputs (or VMState) already removed from the corpus
#[cfg(feature = "full_trace")]
pub static mut REMOVED_CORPUS: usize = 0;

impl<I, S> Scheduler<I, S> for SortedDroppingScheduler<I, S>
where
    S: HasCorpus<I> + HasRand + HasMetadata + HasParent,
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
                deps: DependencyTree::new(),
            });
        }

        // Setup metadata for the input (or VMState)
        {
            let parent_idx = state.get_parent_idx();
            let mut data = state.metadata_mut().get_mut::<VoteData>().unwrap();
            data.votes_and_visits.insert(idx, (3, 1));
            data.visits_total += 1;
            data.votes_total += 3;
            data.sorted_votes.push(idx);

            #[cfg(feature = "full_trace")]
            {
                data.deps.add_node(idx, parent_idx);
            }
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
                        state.metadata_mut().get_mut::<VoteData>().unwrap().deps.remove_node(*x);
                        unsafe {
                            REMOVED_CORPUS += 1;
                        }
                    }
                    #[cfg(not(feature = "full_trace"))]
                    {
                        state.corpus_mut().remove(*x).expect("failed to remove");
                    }
                });
                #[cfg(feature = "full_trace")]
                {
                    for idx in state.metadata_mut().get_mut::<VoteData>().unwrap().deps.garbage_collection() {
                        state.corpus_mut().remove(idx).expect("failed to remove");
                    }
                }
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
    fn vote(&self, state: &mut S, idx: usize, increment: usize) {
        let data = state.metadata_mut().get_mut::<VoteData>().unwrap();

        // increment votes for the input (or VMState)
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_tree() {
        let mut tree = DependencyTree::new();
        tree.add_node(1, 0);
        tree.add_node(2, 1);
        tree.add_node(3, 1);
        tree.add_node(4, 0);

        tree.remove_node(2);
        tree.remove_node(3);
        tree.garbage_collection();
        assert!(tree.nodes.contains_key(&1));
        assert!(tree.nodes.contains_key(&4));
        assert!(!tree.nodes.contains_key(&2));
        assert!(!tree.nodes.contains_key(&3));
    }
}