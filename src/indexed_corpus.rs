use core::cell::RefCell;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use libafl::{
    corpus::{Corpus, Testcase},
    inputs::Input,
    Error,
};

pub trait HasIndexed {

}

impl<I> HasIndexed for IndexedInMemoryCorpus<I> where I: Input {}


/// A corpus handling all in memory.
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct IndexedInMemoryCorpus<I>
    where
        I: Input,
{
    entries: HashMap<usize, RefCell<Testcase<I>>>,
    current_idx: usize,
    current: Option<usize>,
}

impl<I> Corpus<I> for IndexedInMemoryCorpus<I>
    where
        I: Input,
{
    /// Returns the number of elements
    #[inline]
    fn count(&self) -> usize {
        self.entries.len()
    }

    /// Add an entry to the corpus and return its index
    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> Result<usize, Error> {
        self.entries.insert(self.current_idx, RefCell::new(testcase));
        self.current_idx += 1;
        Ok(self.current_idx - 1)
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, idx: usize, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        if idx >= self.entries.len() {
            return Err(Error::key_not_found(format!("Index {idx} out of bounds")));
        }
        Ok(self.entries.get_mut(&idx).unwrap().replace(testcase))
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, idx: usize) -> Result<Option<Testcase<I>>, Error> {
        Ok(Some(self.entries.remove(&idx).unwrap().into_inner()))
    }

    /// Get by id
    #[inline]
    fn get(&self, idx: usize) -> Result<&RefCell<Testcase<I>>, Error> {
        Ok(&self.entries.get(&idx).unwrap())
    }

    /// Current testcase scheduled
    #[inline]
    fn current(&self) -> &Option<usize> {
        &self.current
    }

    /// Current testcase scheduled (mutable)
    #[inline]
    fn current_mut(&mut self) -> &mut Option<usize> {
        &mut self.current
    }
}

impl<I> IndexedInMemoryCorpus<I>
    where
        I: Input,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Default::default(),
            current: None,
            current_idx: 0,
        }
    }
}
