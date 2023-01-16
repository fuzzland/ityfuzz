use std::path::PathBuf;

use crate::{
    fuzzer::ItyFuzzer,
    input::{VMInput, VMInputT},
};
use libafl::{
    prelude::{
        current_nanos, ConstFeedback, InMemoryCorpus, MaxMapFeedback, OnDiskCorpus, StdRand,
    },
    schedulers::StdScheduler,
    state::StdState,
};

pub fn dummyfuzzer(corpus_dir: PathBuf, objective_dir: PathBuf) {
    // let objective = OracleFeedback::new();
    // let feedback = feedback_or!(coverage_feedback, OracleCoverageFeedback::new());
    let mut objective = ConstFeedback::new(false);
    let mut feedback = ConstFeedback::new(false);
    let state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<VMInput>::new(),
        OnDiskCorpus::new(objective_dir).unwrap(),
        &mut feedback,
        &mut objective,
    );
    let scheduler = StdScheduler::new();
    let fuzzer = ItyFuzzer::<
        StdScheduler,
        ConstFeedback,
        VMInput,
        ConstFeedback,
        StdState<InMemoryCorpus<VMInput>, VMInput, StdRand, OnDiskCorpus<VMInput>>,
    >::new(scheduler, feedback, objective);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        dummyfuzzer(
            PathBuf::from("./tmp/corpus"),
            PathBuf::from("./tmp/objective"),
        );
    }
}
