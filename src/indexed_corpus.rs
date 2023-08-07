/// A corpus in memory with self-incementing indexes for items.

use core::cell::RefCell;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use libafl::{
    corpus::{Corpus, Testcase},
    inputs::Input,
    Error,
};

pub trait HasIndexed {}
impl<I> HasIndexed for IndexedInMemoryCorpus<I> where I: Input {}

/// A corpus in memory with self-incementing indexes for items.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(bound = "I: Input")]
pub struct IndexedInMemoryCorpus<I>
where
    I: Input,
{
    /// Mapping from index to testcase
    entries: Vec<RefCell<Testcase<I>>>,
    /// Dummy testcase ref
    dummy: RefCell<Testcase<I>>,
    /// Current index
    current_idx: usize,
    /// Current testcase scheduled
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
        self.entries.push(RefCell::new(testcase));
        Ok(self.entries.len() - 1)
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, idx: usize, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        if idx >= self.entries.len() {
            return Err(Error::key_not_found(format!("Index {idx} out of bounds")));
        }
        self.entries[idx] = RefCell::new(testcase);
        Ok(self.entries[idx].borrow().clone())
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, idx: usize) -> Result<Option<Testcase<I>>, Error> {
        self.entries[idx] = self.dummy.clone();
        Ok(None)
    }

    /// Get by id
    #[inline]
    fn get(&self, idx: usize) -> Result<&RefCell<Testcase<I>>, Error> {
        match self.entries.get(idx) {
            Some(entry) => Ok(entry),
            _ => Err(Error::key_not_found(format!("Index {idx} out of bounds"))),
        }
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
    /// Create a new empty corpus
    pub fn new() -> Self {
        Self {
            entries: Default::default(),
            dummy: RefCell::new(Testcase::default()),
            current: None,
            current_idx: 0,
        }
    }
}
