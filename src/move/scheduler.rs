use libafl::corpus::Corpus;
use libafl::Error;
use libafl::inputs::Input;
use libafl::prelude::{HasCorpus, Scheduler};
use crate::r#move::input::MoveFunctionInputT;

// A scheduler that ensures that all dependencies of a test case are available
// before executing it.
// pub struct EnsureDepsAvailableTestcaseScheduler<I, S, SC> {
//     pub inner: SC,
//     pub phantom: std::marker::PhantomData<(I, S)>,
// }
//
// impl<I, S, SC> Scheduler<I, S> for EnsureDepsAvailableTestcaseScheduler<I, S, SC>
// where SC: Scheduler<I, S>,
//       I: Input + MoveFunctionInputT,
//       S: HasCorpus<I>,
// {
//     fn next(&self, state: &mut S) -> Result<usize, Error> {
//         let mut deps = false;
//         loop {
//             let idx = self.inner.next(state).expect("failed to get next testcase");
//             let testcase = state.corpus().get(idx).expect("failed to get testcase");
//             deps = testcase.borrow().input().expect("failed to get input").deps_resolved();
//             if deps {
//                 return Ok(idx);
//             }
//         }
//
//     }
// }
//
