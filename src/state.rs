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
pub trait HasItyState<VS>
where
    VS: Default + VMStateT,
{
    fn get_infant_state<SC>(&mut self, scheduler: &SC) -> Option<(usize, StagedVMState<VS>)>
    where
        SC: Scheduler<StagedVMState<VS>, InfantStateState<VS>>;
    fn add_infant_state<SC>(&mut self, state: &StagedVMState<VS>, scheduler: &SC)
    where
        SC: Scheduler<StagedVMState<VS>, InfantStateState<VS>>;
}

pub trait HasCaller<Addr> {
    fn get_rand_caller(&mut self) -> Addr;
}

pub trait HasInfantStateState<VS>
where
    VS: Default + VMStateT,
{
    fn get_infant_state_state(&mut self) -> &mut InfantStateState<VS>;
}

pub trait HasHashToAddress {
    fn get_hash_to_address(&self) -> &std::collections::HashMap<[u8; 4], HashSet<H160>>;
}

pub trait HasExecutionResult<VS>
where
    VS: Default + VMStateT,
{
    fn get_execution_result(&self) -> &ExecutionResult<VS>;
    fn get_execution_result_mut(&mut self) -> &mut ExecutionResult<VS>;
    fn set_execution_result(&mut self, res: ExecutionResult<VS>);
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Addr> + Input,
{
    #[serde(deserialize_with = "InfantStateState::deserialize")]
    pub infant_states_state: InfantStateState<VS>,
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
    execution_result: ExecutionResult<VS>,
    pub default_callers: Vec<Addr>,
    pub rand_generator: RomuDuoJrRand,
    pub max_size: usize,
    pub hash_to_address: std::collections::HashMap<[u8; 4], HashSet<H160>>,
    pub phantom: std::marker::PhantomData<(VI, Addr)>,
}

impl<VI, VS, Addr> FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT + 'static,
    VI: VMInputT<VS, Addr> + Input,
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
            default_callers: vec![],
            rand_generator: RomuDuoJrRand::with_seed(1667840158231589000),
            max_size: 20,
            hash_to_address: Default::default(),
            phantom: Default::default()
        }
    }

    pub fn add_deployer_to_callers(&mut self, deployer: Addr) {
        self.default_callers.push(deployer);
    }

    pub fn add_tx_to_corpus(&mut self, input: Testcase<VI>) -> Result<usize, Error> {
        self.txn_corpus.add(input)
    }
}

impl<VI, VS, Addr> HasCaller<Addr> for FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT + 'static,
    VI: VMInputT<VS, Addr> + Input,
    Addr: Clone,
{
    fn get_rand_caller(&mut self) -> Addr {
        let idx = self.rand_generator.below(self.default_callers.len() as u64);
        self.default_callers[idx as usize].clone()
    }
}

// shou: To use power schedule, we need to make it as a state lol, i'll submit a pr to libafl
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InfantStateState<VS>
where
    VS: Default + VMStateT,
{
    #[serde(deserialize_with = "IndexedInMemoryCorpus::deserialize")]
    pub infant_state: IndexedInMemoryCorpus<StagedVMState<VS>>,
    metadata: SerdeAnyMap,
    pub rand_generator: StdRand,
}

impl<VS> InfantStateState<VS>
where
    VS: Default + VMStateT,
{
    pub fn new() -> Self {
        Self {
            infant_state: IndexedInMemoryCorpus::new(),
            metadata: SerdeAnyMap::new(),
            rand_generator: Default::default(),
        }
    }
}

impl<VI, VS, Addr> HasHashToAddress for FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Addr> + Input,
{
    fn get_hash_to_address(&self) -> &std::collections::HashMap<[u8; 4], HashSet<H160>> {
        &self.hash_to_address
    }
}

impl<VS> State for InfantStateState<VS> where VS: Default + VMStateT + DeserializeOwned {}

impl<VS> HasCorpus<StagedVMState<VS>> for InfantStateState<VS>
where
    VS: Default + VMStateT + DeserializeOwned,
{
    type Corpus = IndexedInMemoryCorpus<StagedVMState<VS>>;

    fn corpus(&self) -> &IndexedInMemoryCorpus<StagedVMState<VS>> {
        &self.infant_state
    }

    fn corpus_mut(&mut self) -> &mut IndexedInMemoryCorpus<StagedVMState<VS>> {
        &mut self.infant_state
    }
}

impl<VS> HasMetadata for InfantStateState<VS>
where
    VS: Default + VMStateT,
{
    fn metadata(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<VS> HasRand for InfantStateState<VS>
where
    VS: Default + VMStateT,
{
    type Rand = StdRand;

    fn rand(&self) -> &Self::Rand {
        &self.rand_generator
    }

    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand_generator
    }
}

impl<VI, VS, Addr> HasItyState<VS> for FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Addr> + Input + 'static,
{
    fn get_infant_state<SC>(&mut self, scheduler: &SC) -> Option<(usize, StagedVMState<VS>)>
    where
        SC: Scheduler<StagedVMState<VS>, InfantStateState<VS>>,
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

    fn add_infant_state<SC>(&mut self, state: &StagedVMState<VS>, scheduler: &SC)
    where
        SC: Scheduler<StagedVMState<VS>, InfantStateState<VS>>,
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

impl<VI, VS, Addr> HasInfantStateState<VS> for FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Addr> + Input,
{
    fn get_infant_state_state(&mut self) -> &mut InfantStateState<VS> {
        &mut self.infant_states_state
    }
}

impl<VI, VS, Addr> HasMaxSize for FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Addr> + Input,
{
    fn max_size(&self) -> usize {
        self.max_size
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
    }
}

impl<VI, VS, Addr> HasRand for FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Addr> + Input,
{
    type Rand = StdRand;

    fn rand(&self) -> &Self::Rand {
        &self.rand_generator
    }

    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand_generator
    }
}

impl<VI, VS, Addr> HasExecutions for FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Addr> + Input,
{
    fn executions(&self) -> &usize {
        &self.executions
    }

    fn executions_mut(&mut self) -> &mut usize {
        &mut self.executions
    }
}

impl<VI, VS, Addr> HasMetadata for FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Addr> + Input,
{
    fn metadata(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<VI, VS, Addr> HasCorpus<VI> for FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Addr> + Input,
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

impl<VI, VS, Addr> HasSolutions<VI> for FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Addr> + Input,
{
    type Solutions = OnDiskCorpus<VI>;

    fn solutions(&self) -> &Self::Solutions {
        &self.solutions
    }

    fn solutions_mut(&mut self) -> &mut Self::Solutions {
        &mut self.solutions
    }
}

impl<VI, VS, Addr> HasClientPerfMonitor for FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Addr> + Input,
{
    fn introspection_monitor(&self) -> &ClientPerfMonitor {
        todo!()
    }

    fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor {
        todo!()
    }
}

impl<VI, VS, Addr> HasExecutionResult<VS> for FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Addr> + Input,
{
    fn get_execution_result(&self) -> &ExecutionResult<VS> {
        &self.execution_result
    }

    fn set_execution_result(&mut self, res: ExecutionResult<VS>) {
        self.execution_result = res
    }

    fn get_execution_result_mut(&mut self) -> &mut ExecutionResult<VS> {
        &mut self.execution_result
    }
}

impl<VI, VS, Addr> HasNamedMetadata for FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT,
    VI: VMInputT<VS, Addr> + Input,
{
    fn named_metadata(&self) -> &NamedSerdeAnyMap {
        &self.named_metadata
    }

    fn named_metadata_mut(&mut self) -> &mut NamedSerdeAnyMap {
        &mut self.named_metadata
    }
}

impl<VI, VS, Addr> State for FuzzState<VI, VS, Addr>
where
    VS: Default + VMStateT + DeserializeOwned,
    VI: VMInputT<VS, Addr> + Input,
    Addr: Serialize + DeserializeOwned,
{
}
