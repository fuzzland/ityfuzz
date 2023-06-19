/// Implements LibAFL's State trait supporting our fuzzing logic.
use crate::indexed_corpus::IndexedInMemoryCorpus;
use crate::input::VMInputT;

use crate::state_input::StagedVMState;
use libafl::corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase};
use libafl::inputs::Input;
use libafl::monitors::ClientPerfMonitor;
use libafl::prelude::{
    current_nanos, HasMetadata, NamedSerdeAnyMap, Rand, RomuDuoJrRand, Scheduler, SerdeAnyMap,
    StdRand,
};
use std::collections::HashSet;
use std::fmt::Debug;

use libafl::state::{
    HasClientPerfMonitor, HasCorpus, HasExecutions, HasMaxSize, HasNamedMetadata, HasRand,
    HasSolutions, State,
};

use primitive_types::H160;
use serde::{Deserialize, Serialize};

use crate::generic_vm::vm_executor::ExecutionResult;
use crate::generic_vm::vm_state::VMStateT;
use libafl::Error;
use serde::de::DeserializeOwned;
use std::path::Path;

/// Amount of accounts and contracts that can be caller during fuzzing.
/// We will generate random addresses for these accounts and contracts.
pub const ACCOUNT_AMT: u8 = 2;
pub const CONTRACT_AMT: u8 = 2;

/// Trait providing state functions needed by ItyFuzz
pub trait HasItyState<Loc, Addr, VS>
where
    VS: Default + VMStateT,
    Addr: Clone + Debug + Serialize + DeserializeOwned,
    Loc: Clone + Debug + Serialize + DeserializeOwned,
{
    /// Get a random VMState from the infant state corpus selected by scheduler
    /// If the corpus is empty, return None
    /// If the corpus is not empty, return Some((index of VMState in corpus, VMState))
    fn get_infant_state<SC>(
        &mut self,
        scheduler: &SC,
    ) -> Option<(usize, StagedVMState<Loc, Addr, VS>)>
    where
        SC: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>;

    /// Add a VMState to the infant state corpus
    fn add_infant_state<SC>(&mut self, state: &StagedVMState<Loc, Addr, VS>, scheduler: &SC)
    where
        SC: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>;
}

/// Trait providing caller/address functions
/// Callers are the addresses that can send transactions
/// Address are any addresses collected during execution, superset of callers
pub trait HasCaller<Addr> {
    /// Get a random address from the address set, used for ABI mutation
    fn get_rand_address(&mut self) -> Addr;
    /// Get a random caller from the caller set, used for transaction sender mutation
    fn get_rand_caller(&mut self) -> Addr;
    /// Add a caller to the caller set
    fn add_caller(&mut self, caller: &Addr);
    /// Add an address to the address set
    fn add_address(&mut self, caller: &Addr);
}

/// [Deprecated] Trait providing functions for getting current input index in the input corpus
pub trait HasCurrentInputIdx {
    /// Get the current input index in the input corpus
    fn get_current_input_idx(&self) -> usize;
    /// Set the current input index in the input corpus
    fn set_current_input_idx(&mut self, idx: usize);
}

/// Trait providing functions for getting [`InfantStateState`]
pub trait HasInfantStateState<Loc, Addr, VS>
where
    VS: Default + VMStateT,
    Addr: Clone + Debug + Serialize + DeserializeOwned,
    Loc: Clone + Debug + Serialize + DeserializeOwned,
{
    /// Get the [`InfantStateState`] from the state
    fn get_infant_state_state(&mut self) -> &mut InfantStateState<Loc, Addr, VS>;
}

/// [Deprecated] Trait providing functions for mapping between function hash with the
/// contract addresses that have the function
pub trait HasHashToAddress {
    /// Get the mapping between function hash with the address
    fn get_hash_to_address(&self) -> &std::collections::HashMap<[u8; 4], HashSet<H160>>;
}

/// Trait providing functions for getting the current execution result
pub trait HasExecutionResult<Loc, Addr, VS, Out>
where
    VS: Default + VMStateT,
    Loc: Clone + Debug + Serialize + DeserializeOwned,
    Addr: Clone + Debug + Serialize + DeserializeOwned,
    Out: Default,
{
    /// Get the current execution result
    fn get_execution_result(&self) -> &ExecutionResult<Loc, Addr, VS, Out>;
    /// Get the current execution result mutably
    fn get_execution_result_mut(&mut self) -> &mut ExecutionResult<Loc, Addr, VS, Out>;
    /// Set the current execution result
    fn set_execution_result(&mut self, res: ExecutionResult<Loc, Addr, VS, Out>);
}

/// The global state of ItyFuzz, containing all the information needed for fuzzing
/// Implements LibAFL's [`State`] trait and passed to all the fuzzing components as a reference
///
/// VI: The type of input
/// VS: The type of VMState
/// Loc: The type of the call target
/// Addr: The type of the address (e.g., H160 address for EVM)
/// Out: The type of the output
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "Addr: Serialize + DeserializeOwned, Out: Serialize + DeserializeOwned")]
pub struct FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Debug + Serialize + DeserializeOwned + Clone,
    Loc: Debug + Serialize + DeserializeOwned + Clone,
    Out: Default,
{
    /// InfantStateState wraps the infant state corpus with [`State`] trait so that it is easier to use
    #[serde(deserialize_with = "InfantStateState::deserialize")]
    pub infant_states_state: InfantStateState<Loc, Addr, VS>,

    /// The input corpus
    #[cfg(feature = "evaluation")]
    #[serde(deserialize_with = "OnDiskCorpus::deserialize")]
    txn_corpus: OnDiskCorpus<VI>,
    #[cfg(not(feature = "evaluation"))]
    #[serde(deserialize_with = "InMemoryCorpus::deserialize")]
    txn_corpus: InMemoryCorpus<VI>,

    /// The solution corpus
    #[serde(deserialize_with = "OnDiskCorpus::deserialize")]
    solutions: OnDiskCorpus<VI>,

    /// Amount of total executions
    executions: usize,

    /// Metadata of the state, required for implementing [HasMetadata] and [HasNamedMetadata] trait
    metadata: SerdeAnyMap,
    named_metadata: NamedSerdeAnyMap,

    /// Current input index, used for concolic execution
    current_input_idx: usize,

    /// The current execution result
    #[serde(deserialize_with = "ExecutionResult::deserialize")]
    execution_result: ExecutionResult<Loc, Addr, VS, Out>,

    /// Caller and address pools, required for implementing [`HasCaller`] trait
    pub callers_pool: Vec<Addr>,
    pub addresses_pool: Vec<Addr>,

    /// Random number generator, required for implementing [`HasRand`] trait
    pub rand_generator: RomuDuoJrRand,

    /// Maximum size for input, required for implementing [`HasMaxSize`] trait, used mainly for limiting the size of the arrays for ETH ABI
    pub max_size: usize,

    /// Mapping between function hash with the contract addresses that have the function, required for implementing [`HasHashToAddress`] trait
    pub hash_to_address: std::collections::HashMap<[u8; 4], HashSet<H160>>,

    pub phantom: std::marker::PhantomData<(VI, Addr)>,
}

impl<VI, VS, Loc, Addr, Out> FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT + 'static,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Debug + Clone + PartialEq,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Create a new [`FuzzState`] with default values
    pub fn new(lparam_seed: u64) -> Self {
        let mut seed: u64 = lparam_seed;
        if lparam_seed == 0 {
            seed = current_nanos();
        }
        println!("Seed: {}", seed);
        Self {
            infant_states_state: InfantStateState::new(),
            #[cfg(not(feature = "evaluation"))]
            txn_corpus: InMemoryCorpus::new(),
            #[cfg(feature = "evaluation")]
            txn_corpus: OnDiskCorpus::new(Path::new("corpus")).unwrap(),
            solutions: OnDiskCorpus::new(Path::new("solutions")).unwrap(),
            executions: 0,
            metadata: Default::default(),
            named_metadata: Default::default(),
            current_input_idx: 0,
            execution_result: ExecutionResult::empty_result(),
            callers_pool: Vec::new(),
            addresses_pool: Vec::new(),
            rand_generator: RomuDuoJrRand::with_seed(seed),
            max_size: 20,
            hash_to_address: Default::default(),
            phantom: Default::default(),
        }
    }

    /// Add an input testcase to the input corpus
    pub fn add_tx_to_corpus(&mut self, input: Testcase<VI>) -> Result<usize, Error> {
        self.txn_corpus.add(input)
    }
}

impl<VI, VS, Loc, Addr, Out> Default for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT + 'static,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Debug + Clone + PartialEq,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Create a new [`FuzzState`] with default values
    fn default() -> Self {
        Self::new(0)
    }
}

impl<VI, VS, Loc, Addr, Out> HasCaller<Addr> for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT + 'static,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Clone + Debug + PartialEq,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Get a random address from the address pool, used for ABI mutation
    fn get_rand_address(&mut self) -> Addr {
        let idx = self.rand_generator.below(self.addresses_pool.len() as u64);
        self.addresses_pool[idx as usize].clone()
    }

    /// Get a random caller from the caller pool, used for mutating the caller
    fn get_rand_caller(&mut self) -> Addr {
        let idx = self.rand_generator.below(self.callers_pool.len() as u64);
        self.callers_pool[idx as usize].clone()
    }

    /// Add a caller to the caller pool
    fn add_caller(&mut self, addr: &Addr) {
        if !self.callers_pool.contains(addr) {
            self.callers_pool.push(addr.clone());
        }
        self.add_address(addr);
    }

    /// Add an address to the address pool
    fn add_address(&mut self, caller: &Addr) {
        if !self.addresses_pool.contains(caller) {
            self.addresses_pool.push(caller.clone());
        }
    }
}

/// InfantStateState wraps the infant state corpus
/// shou: To use power schedule, we need to make it as a funny state lol, i'll submit a pr to libafl
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InfantStateState<Loc, Addr, VS>
where
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    #[serde(deserialize_with = "IndexedInMemoryCorpus::deserialize")]
    pub infant_state: IndexedInMemoryCorpus<StagedVMState<Loc, Addr, VS>>,
    metadata: SerdeAnyMap,
    pub rand_generator: StdRand,
}

impl<Loc, Addr, VS> InfantStateState<Loc, Addr, VS>
where
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    /// Create a new [`InfantStateState`] with default values
    pub fn new() -> Self {
        Self {
            infant_state: IndexedInMemoryCorpus::new(),
            metadata: SerdeAnyMap::new(),
            rand_generator: Default::default(),
        }
    }
}

impl<VI, VS, Loc, Addr, Out> HasHashToAddress for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Get the hash to address map
    fn get_hash_to_address(&self) -> &std::collections::HashMap<[u8; 4], HashSet<H160>> {
        &self.hash_to_address
    }
}

impl<Loc, Addr, VS> State for InfantStateState<Loc, Addr, VS>
where
    VS: Default + VMStateT + DeserializeOwned,
    Addr: Debug + Serialize + DeserializeOwned + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
}

impl<Loc, Addr, VS> HasCorpus<StagedVMState<Loc, Addr, VS>> for InfantStateState<Loc, Addr, VS>
where
    VS: Default + VMStateT + DeserializeOwned,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    type Corpus = IndexedInMemoryCorpus<StagedVMState<Loc, Addr, VS>>;

    fn corpus(&self) -> &IndexedInMemoryCorpus<StagedVMState<Loc, Addr, VS>> {
        &self.infant_state
    }

    fn corpus_mut(&mut self) -> &mut IndexedInMemoryCorpus<StagedVMState<Loc, Addr, VS>> {
        &mut self.infant_state
    }
}

impl<Loc, Addr, VS> HasMetadata for InfantStateState<Loc, Addr, VS>
where
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    fn metadata(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<Loc, Addr, VS> HasRand for InfantStateState<Loc, Addr, VS>
where
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    type Rand = StdRand;

    fn rand(&self) -> &Self::Rand {
        &self.rand_generator
    }

    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand_generator
    }
}

impl<VI, VS, Loc, Addr, Out> HasItyState<Loc, Addr, VS> for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Loc, Addr> + Input + 'static,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Get a infant state from the infant state corpus using the scheduler
    fn get_infant_state<SC>(
        &mut self,
        scheduler: &SC,
    ) -> Option<(usize, StagedVMState<Loc, Addr, VS>)>
    where
        SC: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    {
        let idx = scheduler
            .next(&mut self.infant_states_state)
            .expect("no more infant state");
        let state = self
            .infant_states_state
            .corpus()
            .get(idx)
            .unwrap()
            .borrow_mut();

        Some((idx, state.input().clone().unwrap()))
    }

    /// Add a new infant state to the infant state corpus
    /// and setup the scheduler
    fn add_infant_state<SC>(&mut self, state: &StagedVMState<Loc, Addr, VS>, scheduler: &SC)
    where
        SC: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    {
        let idx = self
            .infant_states_state
            .corpus_mut()
            .add(Testcase::new(state.clone()))
            .expect("Failed to add new infant state");
        scheduler
            .on_add(&mut self.infant_states_state, idx)
            .expect("Failed to setup scheduler");
    }
}

impl<VI, VS, Loc, Addr, Out> HasCurrentInputIdx for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Get the current input index
    fn get_current_input_idx(&self) -> usize {
        self.current_input_idx
    }

    /// Set the current input index
    fn set_current_input_idx(&mut self, idx: usize) {
        self.current_input_idx = idx;
    }
}

impl<VI, VS, Loc, Addr, Out> HasInfantStateState<Loc, Addr, VS>
    for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Get the infant state state ([`InfantStateState`])
    fn get_infant_state_state(&mut self) -> &mut InfantStateState<Loc, Addr, VS> {
        &mut self.infant_states_state
    }
}

impl<VI, VS, Loc, Addr, Out> HasMaxSize for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Get the maximum size of the input
    fn max_size(&self) -> usize {
        self.max_size
    }

    /// Set the maximum size of the input
    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
    }
}

impl<VI, VS, Loc, Addr, Out> HasRand for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    type Rand = StdRand;

    /// Get the random number generator
    fn rand(&self) -> &Self::Rand {
        &self.rand_generator
    }

    /// Get the mutable random number generator
    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand_generator
    }
}

impl<VI, VS, Loc, Addr, Out> HasExecutions for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Get the number of executions
    fn executions(&self) -> &usize {
        &self.executions
    }

    /// Get the mutable number of executions
    fn executions_mut(&mut self) -> &mut usize {
        &mut self.executions
    }
}

impl<VI, VS, Loc, Addr, Out> HasMetadata for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Get the metadata
    fn metadata(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    /// Get the mutable metadata
    fn metadata_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<VI, VS, Loc, Addr, Out> HasCorpus<VI> for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    #[cfg(not(feature = "evaluation"))]
    type Corpus = InMemoryCorpus<VI>;
    #[cfg(feature = "evaluation")]
    type Corpus = OnDiskCorpus<VI>;

    /// Get the corpus
    fn corpus(&self) -> &Self::Corpus {
        &self.txn_corpus
    }

    /// Get the mutable corpus
    fn corpus_mut(&mut self) -> &mut Self::Corpus {
        &mut self.txn_corpus
    }
}

impl<VI, VS, Loc, Addr, Out> HasSolutions<VI> for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    type Solutions = OnDiskCorpus<VI>;

    /// Get the solutions
    fn solutions(&self) -> &Self::Solutions {
        &self.solutions
    }

    /// Get the mutable solutions
    fn solutions_mut(&mut self) -> &mut Self::Solutions {
        &mut self.solutions
    }
}

impl<VI, VS, Loc, Addr, Out> HasClientPerfMonitor for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Get the client performance monitor
    fn introspection_monitor(&self) -> &ClientPerfMonitor {
        todo!()
    }

    /// Get the mutable client performance monitor
    fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor {
        todo!()
    }
}

impl<VI, VS, Loc, Addr, Out> HasExecutionResult<Loc, Addr, VS, Out>
    for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Get the execution result
    fn get_execution_result(&self) -> &ExecutionResult<Loc, Addr, VS, Out> {
        &self.execution_result
    }

    /// Get the mutable execution result
    fn get_execution_result_mut(&mut self) -> &mut ExecutionResult<Loc, Addr, VS, Out> {
        &mut self.execution_result
    }

    /// Set the execution result
    fn set_execution_result(&mut self, res: ExecutionResult<Loc, Addr, VS, Out>) {
        self.execution_result = res
    }
}

impl<VI, VS, Loc, Addr, Out> HasNamedMetadata for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Get the named metadata
    fn named_metadata(&self) -> &NamedSerdeAnyMap {
        &self.named_metadata
    }

    /// Get the mutable named metadata
    fn named_metadata_mut(&mut self) -> &mut NamedSerdeAnyMap {
        &mut self.named_metadata
    }
}

impl<VI, VS, Loc, Addr, Out> State for FuzzState<VI, VS, Loc, Addr, Out>
where
    VS: Default + VMStateT + DeserializeOwned,
    VI: VMInputT<VS, Loc, Addr> + Input,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Serialize + DeserializeOwned + Default,
{
}
