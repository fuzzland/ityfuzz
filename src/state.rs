use crate::abi::get_abi_type_boxed;
use crate::contract_utils::ContractInfo;
use crate::evm::ExecutionResult;
use crate::indexed_corpus::IndexedInMemoryCorpus;
use crate::input::{VMInput, VMInputT};
use crate::rand_utils::generate_random_address;
use crate::state_input::StagedVMState;
use crate::EVMExecutor;
use bytes::Bytes;
use libafl::corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase};
use libafl::inputs::Input;
use libafl::monitors::ClientPerfMonitor;
use libafl::prelude::RandomSeed;
use libafl::prelude::{current_nanos, HasMetadata, NamedSerdeAnyMap, Rand, RomuDuoJrRand, Scheduler, SerdeAnyMap, StdRand};

use libafl::state::{
    HasClientPerfMonitor, HasCorpus, HasExecutions, HasMaxSize, HasNamedMetadata, HasRand,
    HasSolutions, State,
};

use primitive_types::H160;
use revm::Bytecode;
use serde::{Deserialize, Serialize};

use std::path::Path;
use std::time::Duration;

const ACCOUNT_AMT: u8 = 2;
const CONTRACT_AMT: u8 = 2;

// Note: Probably a better design is to use StdState with a custom corpus?
// What are other metadata we need?
// shou: may need intermediate info for future adding concolic execution
pub trait HasItyState {
    fn get_infant_state<SC>(&mut self, scheduler: &SC) -> Option<(usize, StagedVMState)>
    where
        SC: Scheduler<StagedVMState, InfantStateState>;
    fn add_infant_state<SC>(&mut self, state: &StagedVMState, scheduler: &SC)
    where
        SC: Scheduler<StagedVMState, InfantStateState>;
    fn get_rand_caller(&mut self) -> H160;
}

pub trait HasInfantStateState {
    fn get_infant_state_state(&mut self) -> &mut InfantStateState;
}

pub trait HasHashToAddress {
    fn get_hash_to_address(&self) -> &std::collections::HashMap<[u8; 4], H160>;
}

pub trait HasExecutionResult {
    fn get_execution_result(&self) -> &ExecutionResult;
    fn get_execution_result_mut(&mut self) -> &mut ExecutionResult;
    fn set_execution_result(&mut self, res: ExecutionResult);
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FuzzState {
    infant_states_state: InfantStateState,
    #[cfg(not(feature = "ondisk_corpus"))]
    txn_corpus: InMemoryCorpus<VMInput>,
    #[cfg(feature = "ondisk_corpus")]
    txn_corpus: OnDiskCorpus<VMInput>,
    solutions: OnDiskCorpus<VMInput>,
    executions: usize,
    metadata: SerdeAnyMap,
    named_metadata: NamedSerdeAnyMap,
    execution_result: ExecutionResult,
    default_callers: Vec<H160>,
    pub rand_generator: RomuDuoJrRand,
    pub rand_generator2: RomuDuoJrRand,
    pub max_size: usize,
    pub hash_to_address: std::collections::HashMap<[u8; 4], H160>,
}

impl FuzzState {
    pub fn new() -> Self {
        let seed = current_nanos();
        println!("Seed: {}", seed);
        Self {
            infant_states_state: InfantStateState::new(),
            #[cfg(not(feature = "ondisk_corpus"))]
            txn_corpus: InMemoryCorpus::new(),
            #[cfg(feature = "ondisk_corpus")]
            txn_corpus: OnDiskCorpus::new(Path::new("corpus")).unwrap(),
            solutions: OnDiskCorpus::new(Path::new("solutions")).unwrap(),
            executions: 0,
            metadata: Default::default(),
            named_metadata: Default::default(),
            execution_result: ExecutionResult::empty_result(),
            default_callers: vec![],
            rand_generator: RomuDuoJrRand::with_seed(1667840158231589000),
            rand_generator2: RomuDuoJrRand::with_seed(1),
            max_size: 1500,
            hash_to_address: Default::default(),
        }
    }

    pub fn add_deployer_to_callers(&mut self, deployer: H160) {
        self.default_callers.push(deployer);
    }

    pub fn initialize<I, S>(
        &mut self,
        contracts: Vec<ContractInfo>,
        executor: &mut EVMExecutor<I, S>,
        scheduler: &dyn Scheduler<I, FuzzState>,
        infant_scheduler: &dyn Scheduler<StagedVMState, InfantStateState>,
        include_static: bool,
    ) where
        I: Input + VMInputT,
    {
        self.setup_default_callers(ACCOUNT_AMT as usize);
        self.setup_contract_callers(CONTRACT_AMT as usize, executor);
        self.initialize_corpus(
            contracts,
            executor,
            scheduler,
            infant_scheduler,
            include_static,
        );
    }

    pub fn initialize_corpus<I, S>(
        &mut self,
        contracts: Vec<ContractInfo>,
        executor: &mut EVMExecutor<I, S>,
        scheduler: &dyn Scheduler<I, FuzzState>,
        infant_scheduler: &dyn Scheduler<StagedVMState, InfantStateState>,
        include_static: bool,
    ) where
        I: Input + VMInputT,
    {
        for contract in contracts {
            println!("Deploying contract: {}", contract.name);
            let deployed_address = match executor.deploy(
                Bytecode::new_raw(Bytes::from(contract.code)),
                Bytes::from(contract.constructor_args),
                generate_random_address()
            ) {
                Some(addr) => addr,
                None => {
                    println!("Failed to deploy contract: {}", contract.name);
                    // we could also panic here
                    continue;
                }
            };

            for abi in contract.abi {
                if abi.is_constructor {
                    continue;
                }
                self.hash_to_address.insert(abi.function, deployed_address);
                if abi.is_static && !include_static {
                    continue;
                }
                let mut abi_instance = get_abi_type_boxed(&abi.abi);
                abi_instance.set_func(abi.function);
                let input = VMInput {
                    caller: self.get_rand_caller(),
                    contract: deployed_address,
                    data: Some(abi_instance),
                    sstate: StagedVMState::new_uninitialized(),
                    sstate_idx: 0,
                    txn_value: 0
                };
                let mut tc = Testcase::new(input);
                tc.set_exec_time(Duration::from_secs(0));
                let idx = self.txn_corpus.add(tc).expect("failed to add");
                scheduler
                    .on_add(self, idx)
                    .expect("failed to call scheduler on_add");
            }
            // add transfer txn
            {
                let input = VMInput {
                    caller: self.get_rand_caller(),
                    contract: deployed_address,
                    data: None,
                    sstate: StagedVMState::new_uninitialized(),
                    sstate_idx: 0,
                    txn_value: 1
                };
                let mut tc = Testcase::new(input);
                tc.set_exec_time(Duration::from_secs(0));
                let idx = self.txn_corpus.add(tc).expect("failed to add");
                scheduler
                    .on_add(self, idx)
                    .expect("failed to call scheduler on_add");
            }
        }
        let mut tc = Testcase::new(StagedVMState::new(executor.host.data.clone(), 0));
        tc.set_exec_time(Duration::from_secs(0));
        let idx = self
            .infant_states_state
            .corpus_mut()
            .add(tc)
            .expect("failed to add");
        infant_scheduler
            .on_add(&mut self.infant_states_state, idx)
            .expect("failed to call infant scheduler on_add");
    }

    pub fn setup_default_callers(&mut self, amount: usize) {
        for _ in 0..amount {
            self.default_callers.push(generate_random_address());
        }
    }

    pub fn setup_contract_callers<I, S>(&mut self, amount: usize, executor: &mut EVMExecutor<I, S>) {
        for _ in 0..amount {
            let address = generate_random_address();
            self.default_callers.push(address);
            executor.host.set_code(address, Bytecode::new_raw(Bytes::from(vec![0xfd, 0x00])));
        }
    }
}

// shou: To use power schedule, we need to make it as a state lol, i'll submit a pr to libafl
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InfantStateState {
    pub infant_state: IndexedInMemoryCorpus<StagedVMState>,
    metadata: SerdeAnyMap,
    pub rand_generator: StdRand,
}

impl InfantStateState {
    pub fn new() -> Self {
        Self {
            infant_state: IndexedInMemoryCorpus::new(),
            metadata: SerdeAnyMap::new(),
            rand_generator: Default::default(),
        }
    }
}

impl HasHashToAddress for FuzzState {
    fn get_hash_to_address(&self) -> &std::collections::HashMap<[u8; 4], H160> {
        &self.hash_to_address
    }
}

impl State for InfantStateState {}

impl HasCorpus<StagedVMState> for InfantStateState {
    type Corpus = IndexedInMemoryCorpus<StagedVMState>;

    fn corpus(&self) -> &IndexedInMemoryCorpus<StagedVMState> {
        &self.infant_state
    }

    fn corpus_mut(&mut self) -> &mut IndexedInMemoryCorpus<StagedVMState> {
        &mut self.infant_state
    }
}

impl HasMetadata for InfantStateState {
    fn metadata(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl HasRand for InfantStateState {
    type Rand = StdRand;

    fn rand(&self) -> &Self::Rand {
        &self.rand_generator
    }

    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand_generator
    }
}

impl HasItyState for FuzzState {
    fn get_infant_state<SC>(&mut self, scheduler: &SC) -> Option<(usize, StagedVMState)>
    where
        SC: Scheduler<StagedVMState, InfantStateState>,
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

    fn add_infant_state<SC>(&mut self, state: &StagedVMState, scheduler: &SC)
    where
        SC: Scheduler<StagedVMState, InfantStateState>,
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

    fn get_rand_caller(&mut self) -> H160 {
        self.default_callers[self.rand_generator.below(self.default_callers.len() as u64) as usize]
    }
}

impl HasInfantStateState for FuzzState {
    fn get_infant_state_state(&mut self) -> &mut InfantStateState {
        &mut self.infant_states_state
    }
}

impl HasMaxSize for FuzzState {
    fn max_size(&self) -> usize {
        self.max_size
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
    }
}

impl HasRand for FuzzState {
    type Rand = StdRand;

    fn rand(&self) -> &Self::Rand {
        &self.rand_generator
    }

    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand_generator
    }
}

impl HasExecutions for FuzzState {
    fn executions(&self) -> &usize {
        &self.executions
    }

    fn executions_mut(&mut self) -> &mut usize {
        &mut self.executions
    }
}

impl HasMetadata for FuzzState {
    fn metadata(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl HasCorpus<VMInput> for FuzzState {
    #[cfg(not(feature = "ondisk_corpus"))]
    type Corpus = InMemoryCorpus<VMInput>;
    #[cfg(feature = "ondisk_corpus")]
    type Corpus = OnDiskCorpus<VMInput>;

    fn corpus(&self) -> &Self::Corpus {
        &self.txn_corpus
    }

    fn corpus_mut(&mut self) -> &mut Self::Corpus {
        &mut self.txn_corpus
    }
}

impl HasSolutions<VMInput> for FuzzState {
    type Solutions = OnDiskCorpus<VMInput>;

    fn solutions(&self) -> &Self::Solutions {
        &self.solutions
    }

    fn solutions_mut(&mut self) -> &mut Self::Solutions {
        &mut self.solutions
    }
}

impl HasClientPerfMonitor for FuzzState {
    fn introspection_monitor(&self) -> &ClientPerfMonitor {
        todo!()
    }

    fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor {
        todo!()
    }
}

impl HasExecutionResult for FuzzState {
    fn get_execution_result(&self) -> &ExecutionResult {
        &self.execution_result
    }

    fn set_execution_result(&mut self, res: ExecutionResult) {
        self.execution_result = res
    }

    fn get_execution_result_mut(&mut self) -> &mut ExecutionResult {
        &mut self.execution_result
    }
}

impl HasNamedMetadata for FuzzState {
    fn named_metadata(&self) -> &NamedSerdeAnyMap {
        &self.named_metadata
    }

    fn named_metadata_mut(&mut self) -> &mut NamedSerdeAnyMap {
        &mut self.named_metadata
    }
}

impl State for FuzzState {}
