use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::executors::ExitKind;
use libafl::inputs::Input;
use libafl::observers::ObserversTuple;
use libafl::prelude::{Feedback, Named};
use libafl::state::{HasClientPerfMonitor, State};
use libafl::Error;

#[derive(Debug)]
pub struct InfantFeedback {}

impl Named for InfantFeedback {
    fn name(&self) -> &str {
        "InfantFeedback"
    }
}

impl<I, S> Feedback<I, S> for InfantFeedback
where
    S: State + HasClientPerfMonitor,
    I: Input,
{
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        todo!()
    }

    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        todo!()
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        _testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        todo!()
    }
}
