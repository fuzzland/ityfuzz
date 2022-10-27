use std::cell::RefCell;

use libafl::prelude::{Corpus, InMemoryCorpus, Input, Testcase};
use libafl::Error;
use serde::{Deserialize, Serialize};

use crate::input::{CorpusInput, VMInputT};

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct InMemoryItyCorpus<I>
where
    I: Input,
{
    txn_corpus: InMemoryCorpus<I>,
    infant_states: InMemoryCorpus<I>,
}

impl<I> InMemoryItyCorpus<I>
where
    I: Input,
{
    pub fn default() -> Self {
        Self {
            txn_corpus: InMemoryCorpus::new(),
            infant_states: InMemoryCorpus::new(),
        }
    }
}

impl<I> Corpus<I> for InMemoryItyCorpus<I>
where
    I: Input,
{
    fn count(&self) -> usize {
        todo!()
    }

    fn add(&mut self, testcase: Testcase<I>) -> Result<usize, Error> {
        let size = self.txn_corpus.add(testcase)?;
        Ok(size)
    }

    fn replace(&mut self, idx: usize, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        todo!()
    }

    fn remove(&mut self, idx: usize) -> Result<Option<Testcase<I>>, Error> {
        todo!()
    }

    fn get(&self, idx: usize) -> Result<&RefCell<Testcase<I>>, Error> {
        todo!()
    }

    fn current(&self) -> &Option<usize> {
        todo!()
    }

    fn current_mut(&mut self) -> &mut Option<usize> {
        todo!()
    }

    fn is_empty(&self) -> bool {
        self.txn_corpus.is_empty() && self.infant_states.is_empty()
    }
}

#[test]
fn test_in_memory_ity_corpus() {
    let mut corpus = InMemoryItyCorpus::<CorpusInput>::default();
    assert!(corpus.is_empty());
}
