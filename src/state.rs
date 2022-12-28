use crate::indexed_corpus::IndexedInMemoryCorpus;
use crate::input::VMInputT;
use crate::rand_utils::generate_random_address;
use crate::state_input::StagedVMState;
use libafl::corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase};
use libafl::inputs::Input;
use libafl::monitors::ClientPerfMonitor;
use libafl::prelude::RandomSeed;
use libafl::prelude::{
    current_nanos, HasMetadata, NamedSerdeAnyMap, Rand, RomuDuoJrRand, Scheduler, SerdeAnyMap,
    StdRand,
};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

use libafl::state::{
    HasClientPerfMonitor, HasCorpus, HasExecutions, HasMaxSize, HasNamedMetadata, HasRand,
    HasSolutions, State,
};

use primitive_types::H160;
use serde::{Deserialize, Serialize};

use crate::generic_vm::vm_executor::{ExecutionResult, GenericVM};
use crate::generic_vm::vm_state::VMStateT;
use libafl::Error;
use serde::de::DeserializeOwned;
use std::path::Path;
use std::time::Duration;

pub const ACCOUNT_AMT: u8 = 2;
pub const CONTRACT_AMT: u8 = 2;

// Note: Probably a better design is to use StdState with a custom corpus?
// What are other metadata we need?
// shou: may need intermediate info for future adding concolic execution
pub trait HasItyState<Loc, Addr, VS>
where
    VS: Default + VMStateT,
    Addr: Clone + Debug + Serialize + DeserializeOwned,
    Loc: Clone + Debug + Serialize + DeserializeOwned,
{
    fn get_infant_state<SC>(
        &mut self,
        scheduler: &SC,
    ) -> Option<(usize, StagedVMState<Loc, Addr, VS>)>
    where
        SC: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>;
    fn add_infant_state<SC>(&mut self, state: &StagedVMState<Loc, Addr, VS>, scheduler: &SC)
    where
        SC: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>;
}

pub trait HasCaller<Addr> {
    // address are for ABI mutation
    // caller are for transaction sender mutation
    // caller pool is a subset of address pool
    fn get_rand_address(&mut self) -> Addr;
    fn get_rand_caller(&mut self) -> Addr;
    fn add_caller(&mut self, caller: &Addr);
    fn add_address(&mut self, caller: &Addr);
}

pub trait HasInfantStateState<Loc, Addr, VS>
where
    VS: Default + VMStateT,
    Addr: Clone + Debug + Serialize + DeserializeOwned,
    Loc: Clone + Debug + Serialize + DeserializeOwned,
{
    fn get_infant_state_state(&mut self) -> &mut InfantStateState<Loc, Addr, VS>;
}

pub trait HasHashToAddress {
    fn get_hash_to_address(&self) -> &std::collections::HashMap<[u8; 4], HashSet<H160>>;
}

pub trait HasExecutionResult<Loc, Addr, VS, Out>
where
    VS: Default + VMStateT,
    Loc: Clone + Debug + Serialize + DeserializeOwned,
    Addr: Clone + Debug + Serialize + DeserializeOwned,
    Out: Default,
{
    fn get_execution_result(&self) -> &ExecutionResult<Loc, Addr, VS, Out>;
    fn get_execution_result_mut(&mut self) -> &mut ExecutionResult<Loc, Addr, VS, Out>;
    fn set_execution_result(&mut self, res: ExecutionResult<Loc, Addr, VS, Out>);
}

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
    #[serde(deserialize_with = "InfantStateState::deserialize")]
    pub infant_states_state: InfantStateState<Loc, Addr, VS>,
    #[cfg(not(feature = "evaluation"))]
    #[serde(deserialize_with = "InMemoryCorpus::deserialize")]
    txn_corpus: InMemoryCorpus<VI>,
    #[cfg(feature = "evaluation")]
    #[serde(deserialize_with = "OnDiskCorpus::deserialize")]
    txn_corpus: OnDiskCorpus<VI>,
    #[serde(deserialize_with = "OnDiskCorpus::deserialize")]
    solutions: OnDiskCorpus<VI>,
    executions: usize,
    metadata: SerdeAnyMap,
    named_metadata: NamedSerdeAnyMap,
    #[serde(deserialize_with = "ExecutionResult::deserialize")]
    execution_result: ExecutionResult<Loc, Addr, VS, Out>,
    pub callers_pool: Vec<Addr>,
    pub addresses_pool: Vec<Addr>,
    pub rand_generator: RomuDuoJrRand,
    pub max_size: usize,
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
    pub fn new() -> Self {
        let seed = current_nanos();
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
            execution_result: ExecutionResult::empty_result(),
            callers_pool: Vec::new(),
            addresses_pool: Vec::new(),
            rand_generator: RomuDuoJrRand::with_seed(1667840158231589000),
            max_size: 20,
            hash_to_address: Default::default(),
            phantom: Default::default(),
        }
    }

    pub fn add_deployer_to_callers(&mut self, deployer: Addr) {
        self.add_caller(&deployer);
    }

    pub fn add_tx_to_corpus(&mut self, input: Testcase<VI>) -> Result<usize, Error> {
        self.txn_corpus.add(input)
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
    fn get_rand_address(&mut self) -> Addr {
        let idx = self.rand_generator.below(self.addresses_pool.len() as u64);
        self.addresses_pool[idx as usize].clone()
    }

    fn get_rand_caller(&mut self) -> Addr {
        let idx = self.rand_generator.below(self.callers_pool.len() as u64);
        self.callers_pool[idx as usize].clone()
    }

    fn add_caller(&mut self, addr: &Addr) {
        if !self.callers_pool.contains(addr) {
            self.callers_pool.push(addr.clone());
        }
        self.add_address(addr);
    }

    fn add_address(&mut self, caller: &Addr) {
        if !self.addresses_pool.contains(caller) {
            self.addresses_pool.push(caller.clone());
        }
    }
}

// shou: To use power schedule, we need to make it as a state lol, i'll submit a pr to libafl
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

    // fn get_rand_caller(&mut self) -> H160 {
    //     self.default_callers[self.rand_generator.below(self.default_callers.len() as u64) as usize]
    // }
    //
    // fn add_vm_input(&mut self, input: EVMInput) -> usize {
    //     let mut tc = Testcase::new(input.as_any().downcast_ref::<VI>().unwrap().clone());
    //     tc.set_exec_time(Duration::from_secs(0));
    //     let idx = self.txn_corpus.add(tc).expect("failed to add");
    //     idx
    // }
    //
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
    fn max_size(&self) -> usize {
        self.max_size
    }

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

    fn rand(&self) -> &Self::Rand {
        &self.rand_generator
    }

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
    fn executions(&self) -> &usize {
        &self.executions
    }

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
    fn metadata(&self) -> &SerdeAnyMap {
        &self.metadata
    }

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

    fn corpus(&self) -> &Self::Corpus {
        &self.txn_corpus
    }

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

    fn solutions(&self) -> &Self::Solutions {
        &self.solutions
    }

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
    fn introspection_monitor(&self) -> &ClientPerfMonitor {
        todo!()
    }

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
    fn get_execution_result(&self) -> &ExecutionResult<Loc, Addr, VS, Out> {
        &self.execution_result
    }

    fn get_execution_result_mut(&mut self) -> &mut ExecutionResult<Loc, Addr, VS, Out> {
        &mut self.execution_result
    }

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
    fn named_metadata(&self) -> &NamedSerdeAnyMap {
        &self.named_metadata
    }

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
