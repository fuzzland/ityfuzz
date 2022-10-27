use crate::{
    corpus::InMemoryItyCorpus,
    evm::{EVMExecutor, FuzzHost},
    executor::FuzzExecutor,
    fuzzer::ItyFuzzer,
    input::{VMInput, VMInputT},
    mutator::FuzzMutator,
};
use libafl::prelude::{ShMemProvider, StdShMemProvider};
use libafl::{
    prelude::{
        current_nanos, current_time, tuple_list, ConstFeedback, HitcountsMapObserver,
        InMemoryCorpus, MaxMapFeedback, OnDiskCorpus, SimpleMonitor, SimpleRestartingEventManager,
        StdMapObserver, StdRand,
    },
    schedulers::StdScheduler,
    stages::StdPowerMutationalStage,
    state::StdState,
    Error, Fuzzer,
};
use std::io::Write;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    io,
    path::PathBuf,
};

use nix::unistd::dup;
use primitive_types::H160;

pub fn dummyfuzzer(
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    logfile: PathBuf,
) -> Result<(), Error> {
    let log = RefCell::new(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(&logfile)?,
    );

    let mut stdout_cpy = unsafe {
        let new_fd = dup(io::stdout().as_raw_fd())?;
        File::from_raw_fd(new_fd)
    };

    // TODO: display useful information of the current run
    let monitor = SimpleMonitor::new(|s| {
        writeln!(&mut stdout_cpy, "{}", s).unwrap();
        writeln!(log.borrow_mut(), "{:?} {}", current_time(), s).unwrap();
    });

    let mut shmem_provider = StdShMemProvider::new()?;

    let (_, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider) {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {}", err);
            }
        },
    };

    // TODO: Finish Mutator
    let mutator = FuzzMutator::new();

    // TODO: Finish observer
    let edges = unsafe { &mut [0; 10] };
    let edges_observer = HitcountsMapObserver::new(StdMapObserver::new("edges", edges));
    // TODO: implement coverage feedback for smart contract programs
    // let objective = OracleFeedback::new();
    // let feedback = feedback_or!(coverage_feedback, OracleCoverageFeedback::new());
    let mut objective = ConstFeedback::new(false);
    let mut feedback = ConstFeedback::new(false);
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryItyCorpus::<VMInput>::default(),
        OnDiskCorpus::new(objective_dir).unwrap(),
        &mut feedback,
        &mut objective,
    )?;

    // TODO: currently Scheduler.next: () => usize, we might want to return something different
    let scheduler = StdScheduler::new();

    let std_stage = StdPowerMutationalStage::new(mutator, &edges_observer);
    let mut stages = tuple_list!(std_stage);

    // TODO: Fill EVMExecutor with real data?
    let mut executor = FuzzExecutor::new(
        EVMExecutor::new(FuzzHost::new(), Vec::new(), H160::zero()),
        tuple_list!(edges_observer),
    );

    let mut fuzzer = ItyFuzzer::new(scheduler, feedback, objective);

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() -> Result<(), Error> {
        // dummyfuzzer(
        //     PathBuf::from("./tmp/corpus"),
        //     PathBuf::from("./tmp/objective"),
        //     PathBuf::from("./tmp/log"),
        // )?;
        Ok(())
    }
}
