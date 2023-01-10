use libafl::corpus::InMemoryCorpus;
use libafl::state::State;
use serde::{Deserialize, Serialize};
use crate::input::VMInput;
use crate::evm::VMState;


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FuzzState {
    infant_states: InMemoryCorpus<VMState>,
    txn_corpus: InMemoryCorpus<VMInput>,
}
