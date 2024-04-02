//! The power schedules. This stage should be invoked after the calibration
//! stage.

use core::{fmt::Debug, marker::PhantomData};

use libafl::{
    corpus::{Corpus, CorpusId},
    executors::{Executor, HasObservers},
    fuzzer::Evaluator,
    mutators::Mutator,
    prelude::Testcase,
    stages::{mutational::MutatedTransform, MutationalStage, Stage},
    state::{HasCorpus, HasMetadata, HasRand, UsesState},
    Error,
};

pub trait TestcaseScoreWithId<S>
where
    S: HasMetadata + HasCorpus,
{
    /// Computes the favor factor of a [`Testcase`]. Lower is better.
    fn compute(state: &S, entry: &mut Testcase<S::Input>, id: CorpusId) -> Result<f64, Error>;
}

/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStageWithId<E, F, EM, I, M, Z> {
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, F, EM, I, Z)>,
}

impl<E, F, EM, I, M, Z> UsesState for PowerMutationalStageWithId<E, F, EM, I, M, Z>
where
    E: UsesState,
{
    type State = E::State;
}

impl<E, F, EM, I, M, Z> MutationalStage<E, EM, I, M, Z> for PowerMutationalStageWithId<E, F, EM, I, M, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScoreWithId<E::State>,
    M: Mutator<I, E::State>,
    E::State: HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
    I: MutatedTransform<E::Input, E::State> + Clone,
{
    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }

    /// Gets the number of iterations as a random number
    #[allow(clippy::cast_sign_loss)]
    fn iterations(&self, state: &mut E::State, corpus_idx: CorpusId) -> Result<u64, Error> {
        // Update handicap
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let score = F::compute(state, &mut *testcase, corpus_idx)? as u64;

        Ok(score)
    }
}

impl<E, F, EM, I, M, Z> Stage<E, EM, Z> for PowerMutationalStageWithId<E, F, EM, I, M, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScoreWithId<E::State>,
    M: Mutator<I, E::State>,
    E::State: HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
    I: MutatedTransform<E::Input, E::State> + Clone,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager, corpus_idx);
        ret
    }
}

impl<E, F, EM, M, Z> PowerMutationalStageWithId<E, F, EM, E::Input, M, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScoreWithId<E::State>,
    M: Mutator<E::Input, E::State>,
    E::State: HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
{
    /// Creates a new [`PowerMutationalStageWithId`]
    pub fn new(mutator: M) -> Self {
        Self::transforming(mutator)
    }
}

impl<E, F, EM, I, M, Z> PowerMutationalStageWithId<E, F, EM, I, M, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScoreWithId<E::State>,
    M: Mutator<I, E::State>,
    E::State: HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
{
    /// Creates a new transforming [`PowerMutationalStageWithId`]
    pub fn transforming(mutator: M) -> Self {
        Self {
            mutator,
            phantom: PhantomData,
        }
    }
}
