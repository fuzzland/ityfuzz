/// Corpus schedulers for ItyFuzz
/// Used to determine which input / VMState to fuzz next

use libafl::corpus::Corpus;
use libafl::corpus::Testcase;
use libafl::prelude::{HasMetadata, HasRand, Input, UsesInput, HasTestcase, CorpusId};
use libafl::schedulers::TestcaseScore;
use libafl::schedulers::{Scheduler, RemovableScheduler};
use libafl::stages::PowerMutationalStage;
use libafl::state::HasCorpus;
use libafl::Error;
use libafl::state::UsesState;
use libafl_bolts::{impl_serdeany, prelude::Rand};

use serde::{Deserialize, Serialize};

use rand::random;
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use revm_primitives::HashSet;
use serde::de::DeserializeOwned;
use crate::evm::abi::FUNCTION_SIG;
use crate::evm::blaz::builder::ArtifactInfoMetadata;
use crate::evm::blaz::builder::BuildJobResult;
use crate::evm::corpus_initializer::EVMInitializationArtifacts;
use crate::evm::input::EVMInput;
use crate::evm::input::EVMInputT;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::ConciseSerde;
use crate::input::VMInputT;
use crate::state::HasParent;
use tracing::{debug, info};

/// A trait providing functions necessary for voting mechanisms
pub trait HasVote<S>
where
    S: HasCorpus + HasRand + HasMetadata,
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
pub struct SortedDroppingScheduler<S> {
    phantom: std::marker::PhantomData<S>,
}

impl<S> SortedDroppingScheduler<S> {
    /// Create a new SortedDroppingScheduler
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }
}

impl<S> UsesState for SortedDroppingScheduler<S>
where
    S: UsesInput,
{
    type State = S;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Node {
    parent: usize, // 0 for root node
    ref_count: usize,
    pending_delete: bool,
    never_delete: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DependencyTree {
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
pub struct VoteData {
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
    /// To remove, for Move schedulers
    pub to_remove: Vec<usize>,
}

pub trait HasReportCorpus<S>
    where S: HasMetadata {
    fn report_corpus(&self, state: &mut S, state_idx: usize);
    fn sponsor_state(&self, state: &mut S, state_idx: usize, amt: usize);
}

impl<S> HasReportCorpus<S> for SortedDroppingScheduler<S>
where
    S: HasCorpus + HasRand + HasMetadata + HasParent,
{
    fn report_corpus(&self, state: &mut S, state_idx: usize) {
        self.vote(state, state_idx, 3);
        let mut data = state.metadata_map_mut().get_mut::<VoteData>().unwrap();

        #[cfg(feature = "full_trace")]
        data.deps.mark_never_delete(state_idx);
    }

    fn sponsor_state(&self, state: &mut S, state_idx: usize, amt: usize) {
        self.vote(state, state_idx, amt);
    }
}



impl_serdeany!(VoteData);

/// The number of inputs (or VMState) already removed from the corpus
#[cfg(feature = "full_trace")]
pub static mut REMOVED_CORPUS: usize = 0;

impl<S> Scheduler for SortedDroppingScheduler<S>
where
    S: HasCorpus + HasTestcase + HasRand + HasMetadata + HasParent,
{
    /// Hooks called every time an input (or VMState) is added to the corpus
    /// Set up the metadata for the input (or VMState)
    fn on_add(&mut self, state: &mut Self::State, idx: CorpusId) -> Result<(), Error> {
        let idx = usize::from(idx);

        // Initialize metadata if it doesn't exist
        if !state.has_metadata::<VoteData>() {
            state.metadata_map_mut().insert(VoteData {
                votes_and_visits: HashMap::new(),
                sorted_votes: vec![],
                visits_total: 1,
                votes_total: 1,
                deps: DependencyTree::new(),
                to_remove: vec![],
            });
        }

        // Setup metadata for the input (or VMState)
        {
            let parent_idx = state.get_parent_idx();
            let mut data = state.metadata_map_mut().get_mut::<VoteData>().unwrap();
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
            let data = state.metadata_map().get::<VoteData>().unwrap();
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
                    // Ignore the artifacts (*i.0 < 3) and the currently executing corpus (*i.0 == idx).
                    if *i.0 >= 3 && *i.0 != idx {
                        to_remove.push(*i.0);
                    }
                }

                // Remove inputs (or VMState) from metadata and corpus
                to_remove.iter().for_each(|x| {
                    self.on_remove(state, (*x).into(), &None);
                    #[cfg(feature = "full_trace")]
                    {
                        state.metadata_map_mut().get_mut::<VoteData>().unwrap().deps.remove_node(*x);
                        unsafe {
                            REMOVED_CORPUS += 1;
                        }
                    }
                    #[cfg(not(feature = "full_trace"))]
                    {
                        state.corpus_mut().remove((*x).into()).expect("failed to remove");
                    }
                });
                state.metadata_map_mut().get_mut::<VoteData>().unwrap().to_remove = to_remove;
                #[cfg(feature = "full_trace")]
                {
                    for idx in state.metadata_map_mut().get_mut::<VoteData>().unwrap().deps.garbage_collection() {
                        state.corpus_mut().remove(idx.into()).expect("failed to remove");
                    }
                }
            }
        }
        Ok(())
    }

    /// Selects next input (or VMState) to run
    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error> {
        // Debugging prints
        #[cfg(feature = "print_infant_corpus")]
        {
            let corpus_size = state.corpus().count();
            let data = state.metadata_map().get::<VoteData>().unwrap();
            use crate::r#const::DEBUG_PRINT_PERCENT;
            if random::<usize>() % DEBUG_PRINT_PERCENT == 0 {
                info!(
                    "======================= corpus size: {} =======================",
                    corpus_size
                );
                for idx in &data.sorted_votes {
                    let (votes, visits) = data.votes_and_visits.get(&idx).unwrap();
                    let inp = state.corpus().get((*idx).into()).unwrap().clone();
                    match inp.into_inner().input() {
                        Some(x) => {
                            info!(
                                "idx: {}, votes: {}, visits: {}: {:?}",
                                idx, votes, visits, x
                            );
                        }
                        _ => {}
                    }
                }
                info!("======================= corpus  =======================");
            }
        }

        // Conduct a probabilistic sampling from votes and visits (weighted by votes)
        let threshold = (state.rand_mut().below(1000) as f64 / 1000.0)
            * state.metadata_map().get::<VoteData>().unwrap().votes_total as f64;
        let mut data = state.metadata_map_mut().get_mut::<VoteData>().unwrap();
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

        Ok(idx.into())
    }
}

impl<S> RemovableScheduler for SortedDroppingScheduler<S>
where
    S: HasCorpus + HasTestcase + HasRand + HasMetadata + HasParent,
{
    /// Hooks called every time an input (or VMState) is removed from the corpus
    /// Update the metadata caches for the input (or VMState)
    fn on_remove(
        &mut self,
        state: &mut Self::State,
        idx: CorpusId,
        _testcase: &Option<Testcase<<Self::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        let idx = usize::from(idx);
        let data = state.metadata_map_mut().get_mut::<VoteData>().unwrap();
        data.votes_total -= data.votes_and_visits.get(&idx).unwrap().0;
        data.visits_total -= data.votes_and_visits.get(&idx).unwrap().1;
        data.votes_and_visits.remove(&idx);
        data.sorted_votes.retain(|x| *x != idx);
        Ok(())
    }
}

impl<S> HasVote<S> for SortedDroppingScheduler<S>
where
    S: HasCorpus + HasRand + HasMetadata,
{
    /// Vote for an input (or VMState)
    fn vote(&self, state: &mut S, idx: usize, increment: usize) {
        let data = state.metadata_map_mut().get_mut::<VoteData>().unwrap();

        // increment votes for the input (or VMState)
        data.votes_total += increment;
        {
            let v = data.votes_and_visits.get_mut(&idx);
            if v.is_some() {
                let (votes, _visits) = v.expect("scheduler metadata malformed");
                *votes += increment;
                debug!("Voted for {}", idx);
            } else {
                debug!("scheduler metadata malformed");
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

/// The Metadata for each testcase used in ABI power schedules.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct PowerABITestcaseMetadata {
    /// Number of lines in source code, initialized in on_add
    lines: usize,
}

impl PowerABITestcaseMetadata {
    /// Create new [`struct@SchedulerTestcaseMetadata`]
    #[must_use]
    pub fn new(lines: usize) -> Self {
        Self { lines: lines }
    }
}

impl_serdeany!(PowerABITestcaseMetadata);

#[derive(Debug, Clone)]
pub struct PowerABIScheduler<S> {
    phantom: PhantomData<S>,
}

impl<S> PowerABIScheduler<S> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }

    fn add_abi_metadata(
        &mut self,
        testcase: &mut Testcase<EVMInput>,
        artifact: &BuildJobResult,
    ) -> Result<(), Error> {
        let input = testcase.input().clone().unwrap();
        let tc_func = match input.get_data_abi() {
            Some(abi) => abi.function,
            None => {
                testcase.add_metadata(PowerABITestcaseMetadata::new(1));
                return Ok(()); // Some EVMInput don't have abi, like borrow
            }
        };
        let tc_func_name = unsafe { FUNCTION_SIG.get(&tc_func).expect(format!(
            "function signature {} @ {:?} not found in FUNCTION_SIG",
            hex::encode(tc_func), input.get_contract()
        ).as_str()) };
        let tc_func_slug = {
            let amount_args = tc_func_name.matches(',').count() + {
                if tc_func_name.contains("()") {
                    0
                } else {
                    1
                }
            };
            let name = tc_func_name.split('(').next().unwrap();
            format!("{}:{}", name, amount_args)
        };
        for (_filename, ast) in artifact.asts.iter() {
            let contracts = ast["contracts"].as_array().unwrap();
            for contract in contracts {
                let funcs = contract["functions"].as_array().unwrap();
                for func in funcs {
                    let func_slug = {
                        let arg_len = func["args"].as_array().unwrap().len();
                        let name = func["name"].as_str().unwrap();
                        format!("{}:{}", name, arg_len)
                    };

                    if tc_func_slug == func_slug {
                        let func_source = func["source"].as_str().unwrap();
                        let num_lines = func_source.matches('\n').count() + 1;
                        if num_lines <= 1 {
                            break; // not true function implementation, break to find in next contract
                        }
                        testcase.add_metadata(PowerABITestcaseMetadata::new(num_lines));
                        return Ok(());
                    }
                }
            }
        }
        // NOTE: testcase function is [0,0,0,0] !fallback!
        testcase.add_metadata(PowerABITestcaseMetadata::new(1));
        Ok(())
    }
}

impl<S> UsesState for PowerABIScheduler<S>
where
    S: UsesInput,
{
    type State = S;
}

impl<S> Scheduler for PowerABIScheduler<S>
where
    S: HasCorpus<Input = EVMInput> + HasTestcase + HasMetadata,
{
    fn on_add(&mut self, state: &mut Self::State, idx: CorpusId) -> Result<(), Error> {
        let mut testcase = state.testcase_mut(idx).unwrap();
        let input = testcase.input().clone().unwrap();
        let meta = state.metadata_map().get::<ArtifactInfoMetadata>().unwrap();
        let artifact = match meta.get(&input.contract) {
            Some(artifact) => artifact,
            None => {
                testcase.add_metadata(PowerABITestcaseMetadata::new(1));
                return Ok(());
            } // some contracts are not in ArtifactInfo, like borrow
        };
        let current_idx = *state.corpus().current();
        if !input.is_step() {
            self.add_abi_metadata(&mut testcase, artifact)?;
        }
        testcase.set_parent_id_optional(current_idx);
        Ok(())
    }

    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error> {
        if state.corpus().count() == 0 {
            Err(Error::empty("No entries in corpus".to_owned()))
        } else {
            let id = state
                .corpus()
                .current()
                .map(|id| state.corpus().next(id))
                .flatten()
                .unwrap_or_else(|| state.corpus().first().unwrap());
            self.set_current_scheduled(state, Some(id))?;
            Ok(id)
        }
    }
}

impl<S> RemovableScheduler for PowerABIScheduler<S>
where
    S: HasCorpus<Input = EVMInput> + HasTestcase + HasMetadata,
{
    fn on_remove(
        &mut self,
        _state: &mut Self::State,
        _idx: CorpusId,
        _testcase: &Option<Testcase<<Self::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn on_replace(
        &mut self,
        _state: &mut Self::State,
        _idx: CorpusId,
        _prev: &Testcase<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

pub trait ABIScheduler: Scheduler
where
    Self::State: HasCorpus,
{
    // on_add but with artifacts passed when state has no ArtifactInfoMetadata
    fn on_add_artifacts(
        &mut self,
        state: &mut Self::State,
        idx: CorpusId,
        artifacts: &EVMInitializationArtifacts,
    ) -> Result<(), Error>;
}

impl<S> ABIScheduler for PowerABIScheduler<S>
where
    S: HasCorpus<Input = EVMInput> + HasTestcase + HasMetadata,
{
    fn on_add_artifacts(
        &mut self,
        state: &mut S,
        idx: CorpusId,
        artifacts: &EVMInitializationArtifacts,
    ) -> Result<(), Error> {
        let mut testcase = state.testcase_mut(idx).unwrap();
        testcase.set_parent_id_optional(None);
        let input = testcase.input().clone().unwrap();
        let artifact = match artifacts.build_artifacts.get(&input.contract) {
            Some(artifact) => artifact,
            None => {
                testcase.add_metadata(PowerABITestcaseMetadata::new(1));
                return Ok(());
            } // build_artifacts may not contain contracts whose source code is not available
        };
        self.add_abi_metadata(&mut testcase, artifact)?;
        Ok(())
    }
}

/// The power assigned to each corpus entry
/// This result is used for power scheduling
#[derive(Debug, Clone)]
pub struct CorpusPowerABITestcaseScore<S> {
    phantom: PhantomData<S>,
}

impl<S> TestcaseScore<S> for CorpusPowerABITestcaseScore<S>
where
    S: HasCorpus + HasMetadata,
{
    fn compute(state: &S, entry: &mut Testcase<S::Input>) -> Result<f64, Error> {
        let num_lines = match entry.metadata::<PowerABITestcaseMetadata>() {
            Ok(meta) => meta.lines,
            Err(e) => 1, // FIXME: should not happen
        };
        // TODO: more sophisticated power score
        Ok(num_lines as f64 * 100.0)
    }
}

/// The standard powerscheduling stage
pub type PowerABIMutationalStage<E, EM, I, M, Z> =
    PowerMutationalStage<E, CorpusPowerABITestcaseScore<<E as UsesState>::State>, EM, I, M, Z>;
