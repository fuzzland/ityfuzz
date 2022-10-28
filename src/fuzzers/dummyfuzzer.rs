use crate::{
    corpus::InMemoryItyCorpus,
    evm::{EVMExecutor, FuzzHost, JMP_MAP},
    executor::FuzzExecutor,
    fuzzer::ItyFuzzer,
    input::{VMInput, VMInputT},
    mutator::FuzzMutator,
};
use libafl::prelude::{powersched::PowerSchedule, MapFeedback, SimpleEventManager};
use libafl::prelude::{PowerQueueScheduler, ShMemProvider, StdShMemProvider};
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

use crate::state::FuzzState;
use nix::unistd::dup;
use primitive_types::H160;
use crate::infant_state_stage::InfantStateStage;

pub fn dummyfuzzer(
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    logfile: PathBuf,
) -> Result<(), Error> {
    // Fuzzbench style, which requires a host and can have many fuzzing client
    // let log = RefCell::new(
    //     OpenOptions::new()
    //         .append(true)
    //         .create(true)
    //         .open(&logfile)?,
    // );

    // let mut stdout_cpy = unsafe {
    //     let new_fd = dup(io::stdout().as_raw_fd())?;
    //     File::from_raw_fd(new_fd)
    // };

    // // TODO: display useful information of the current run
    // let monitor = SimpleMonitor::new(|s| {
    //     writeln!(&mut stdout_cpy, "{}", s).unwrap();
    //     writeln!(log.borrow_mut(), "{:?} {}", current_time(), s).unwrap();
    // });

    // let mut shmem_provider = StdShMemProvider::new()?;

    // let (_, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider) {
    //     // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
    //     Ok(res) => res,
    //     Err(err) => match err {
    //         Error::ShuttingDown => {
    //             return Ok(());
    //         }
    //         _ => {
    //             panic!("Failed to setup the restarter: {}", err);
    //         }
    //     },
    // };

    let monitor = SimpleMonitor::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);
    let infant_scheduler = PowerQueueScheduler::new(PowerSchedule::FAST);
    let mutator = FuzzMutator::new(infant_scheduler);

    let jmps = unsafe { &mut JMP_MAP };
    let jmp_observer = StdMapObserver::new("jmp_labels", jmps);
    // TODO: implement OracleFeedback
    // let objective = OracleFeedback::new();
    // let feedback = feedback_or!(coverage_feedback, OracleCoverageFeedback::new());
    let mut objective = ConstFeedback::new(false);
    // let mut feedback = ConstFeedback::new(false);
    let mut feedback = MaxMapFeedback::new(&jmp_observer);
    let mut state = FuzzState::new();

    let scheduler = PowerQueueScheduler::new(PowerSchedule::FAST);

    let std_stage = StdPowerMutationalStage::new(mutator, &jmp_observer);
    let infant_state_stage = InfantStateStage::new(infant_scheduler);
    let mut stages = tuple_list!(std_stage, infant_state_stage);

    // TODO: Fill EVMExecutor with real data?
    let mut executor = FuzzExecutor::new(
        EVMExecutor::new(FuzzHost::new(), Vec::new(), H160::zero()),
        tuple_list!(jmp_observer),
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
