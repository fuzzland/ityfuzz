/// A corpus in memory with self-incementing indexes for items.
use core::cell::RefCell;
use std::{
    cell::{Ref, RefMut},
    collections::HashMap,
};

use libafl::{
    corpus::{Corpus, Testcase},
    inputs::{Input, UsesInput},
    prelude::{CorpusId, HasTestcase},
    Error,
};
use serde::{Deserialize, Serialize};

pub trait HasIndexed {}
impl<I> HasIndexed for IndexedInMemoryCorpus<I> where I: Input {}

/// A corpus in memory with self-incementing indexes for items.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(bound = "I: Input")]
pub struct IndexedInMemoryCorpus<I>
where
    I: Input,
{
    /// Mapping from index to testcase
    entries: HashMap<usize, RefCell<Testcase<I>>>,
    /// Dummy testcase ref
    dummy: RefCell<Testcase<I>>,
    /// Current index
    current_idx: usize,
    /// Current testcase scheduled
    current: Option<CorpusId>,
}

impl<I> UsesInput for IndexedInMemoryCorpus<I>
where
    I: Input,
{
    type Input = I;
}

impl<I> Corpus for IndexedInMemoryCorpus<I>
where
    I: Input,
{
    /// Returns the number of elements
    #[inline]
    fn count(&self) -> usize {
        self.current_idx
    }

    /// Add an entry to the corpus and return its index
    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        self.entries.insert(self.current_idx, RefCell::new(testcase));
        self.current_idx += 1;
        Ok(CorpusId::from(self.current_idx - 1))
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, idx: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        let idx = usize::from(idx);
        let original = self.entries.get(&idx).unwrap().borrow().clone();
        self.entries.insert(idx, RefCell::new(testcase));
        Ok(original)
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, idx: CorpusId) -> Result<Testcase<I>, Error> {
        let idx = usize::from(idx);
        let original = self.entries.remove(&idx).unwrap().into_inner();
        Ok(original)
    }

    /// Get by id
    #[inline]
    fn get(&self, idx: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        match self.entries.get(&usize::from(idx)) {
            Some(entry) => Ok(entry),
            _ => Err(Error::key_not_found(format!("Index {idx} out of bounds"))),
        }
    }

    /// Current testcase scheduled
    #[inline]
    fn current(&self) -> &Option<CorpusId> {
        &self.current
    }

    /// Current testcase scheduled (mutable)
    #[inline]
    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        &mut self.current
    }

    #[inline]
    fn next(&self, idx: CorpusId) -> Option<CorpusId> {
        let idx = usize::from(idx);
        if idx < self.count() - 1 {
            Some(CorpusId::from(idx + 1))
        } else {
            None
        }
    }

    #[inline]
    fn prev(&self, idx: CorpusId) -> Option<CorpusId> {
        let idx = usize::from(idx);
        if idx > 0 && idx < self.count() {
            Some(CorpusId::from(idx - 1))
        } else {
            None
        }
    }

    #[inline]
    fn first(&self) -> Option<CorpusId> {
        if self.count() > 0 {
            Some(CorpusId::from(0usize))
        } else {
            None
        }
    }

    #[inline]
    fn last(&self) -> Option<CorpusId> {
        if self.count() > 0 {
            Some(CorpusId::from(self.count() - 1))
        } else {
            None
        }
    }

    #[inline]
    fn nth(&self, nth: usize) -> CorpusId {
        CorpusId::from(nth)
    }

    #[inline]
    fn load_input_into(&self, _: &mut Testcase<Self::Input>) -> Result<(), Error> {
        Ok(())
    }

    #[inline]
    fn store_input_from(&self, _: &Testcase<Self::Input>) -> Result<(), Error> {
        Ok(())
    }
}

impl<I> HasTestcase for IndexedInMemoryCorpus<I>
where
    I: Input,
{
    /// Shorthand to receive a [`Ref`] to a stored [`Testcase`], by
    /// [`CorpusId`]. For a normal state, this should return a [`Testcase`]
    /// in the corpus, not the objectives.
    fn testcase(&self, id: CorpusId) -> Result<Ref<Testcase<<Self as UsesInput>::Input>>, Error> {
        Ok(self.get(id)?.borrow())
    }

    /// Shorthand to receive a [`RefMut`] to a stored [`Testcase`], by
    /// [`CorpusId`]. For a normal state, this should return a [`Testcase`]
    /// in the corpus, not the objectives.
    fn testcase_mut(&self, id: CorpusId) -> Result<RefMut<Testcase<<Self as UsesInput>::Input>>, Error> {
        Ok(self.get(id)?.borrow_mut())
    }
}

impl<I> Default for IndexedInMemoryCorpus<I>
where
    I: Input,
{
    fn default() -> Self {
        Self::new()
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
