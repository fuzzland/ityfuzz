use std::{clone::Clone, collections::HashMap, fmt::Debug};

use alloy_primitives::{Address, Log as RawLog};
use bytes::Bytes;
use foundry_cheatcodes::Vm::{self};
use libafl::schedulers::Scheduler;
use revm_primitives::U256;

use super::Cheatcode;
use crate::evm::{host::FuzzHost, types::EVMFuzzState};

/// Tracks the expected calls per address.
///
/// For each address, we track the expected calls per call data. We track it in
/// such manner so that we don't mix together calldatas that only contain
/// selectors and calldatas that contain selector and arguments (partial and
/// full matches).
///
/// This then allows us to customize the matching behavior for each call data on
/// the `ExpectedCallData` struct and track how many times we've actually seen
/// the call on the second element of the tuple.
///
/// BTreeMap<Address, BTreeMap<Calldata, (ExpectedCallData, count)>>
pub type ExpectedCallTracker = HashMap<Address, HashMap<Vec<u8>, (ExpectedCallData, u64)>>;

#[derive(Clone, Debug, Default)]
pub struct ExpectedRevert {
    /// The expected data returned by the revert, None being any
    pub reason: Option<Bytes>,
    /// The depth at which the revert is expected
    pub depth: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ExpectedEmit {
    /// The depth at which we expect this emit to have occurred
    pub depth: u64,
    /// The log we expect
    pub log: Option<RawLog>,
    /// The checks to perform:
    ///
    /// ┌───────┬───────┬───────┬────┐
    /// │topic 1│topic 2│topic 3│data│
    /// └───────┴───────┴───────┴────┘
    pub checks: [bool; 4],
    /// If present, check originating address against this
    pub address: Option<Address>,
    /// Whether the log was actually found in the subcalls
    pub found: bool,
}

#[derive(Clone, Debug)]
pub struct ExpectedCallData {
    /// The expected value sent in the call
    pub value: Option<U256>,
    /// The number of times the call is expected to be made.
    /// If the type of call is `NonCount`, this is the lower bound for the
    /// number of calls that must be seen.
    /// If the type of call is `Count`, this is the exact number of calls that
    /// must be seen.
    pub count: u64,
    /// The type of call
    pub call_type: ExpectedCallType,
}

/// The type of expected call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpectedCallType {
    /// The call is expected to be made at least once.
    NonCount,
    /// The exact number of calls expected.
    Count,
}

/// Cheat VmCalls
impl<SC> Cheatcode<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    /// Expects an error on next call with any revert data.
    #[inline]
    pub fn expect_revert0(&mut self, host: &mut FuzzHost<SC>) -> Option<Vec<u8>> {
        host.expected_revert = Some(ExpectedRevert {
            reason: None,
            depth: host.call_depth,
        });
        None
    }

    /// Expects an error on next call that starts with the revert data.
    #[inline]
    pub fn expect_revert1(&mut self, host: &mut FuzzHost<SC>, args: Vm::expectRevert_1Call) -> Option<Vec<u8>> {
        let Vm::expectRevert_1Call { revertData } = args;
        let reason = Some(Bytes::from(revertData.0.to_vec()));
        host.expected_revert = Some(ExpectedRevert {
            reason,
            depth: host.call_depth,
        });
        None
    }

    /// Expects an error on next call that exactly matches the revert data.
    #[inline]
    pub fn expect_revert2(&mut self, host: &mut FuzzHost<SC>, args: Vm::expectRevert_2Call) -> Option<Vec<u8>> {
        let Vm::expectRevert_2Call { revertData } = args;
        let reason = Some(Bytes::from(revertData));
        host.expected_revert = Some(ExpectedRevert {
            reason,
            depth: host.call_depth,
        });
        None
    }

    /// Prepare an expected log with (bool checkTopic1, bool checkTopic2, bool
    /// checkTopic3, bool checkData.). Call this function, then emit an
    /// event, then call a function. Internally after the call, we check if
    /// logs were emitted in the expected order with the expected topics and
    /// data (as specified by the booleans).
    #[inline]
    pub fn expect_emit0(&mut self, host: &mut FuzzHost<SC>, args: Vm::expectEmit_0Call) -> Option<Vec<u8>> {
        let Vm::expectEmit_0Call {
            checkTopic1,
            checkTopic2,
            checkTopic3,
            checkData,
        } = args;
        let expected = ExpectedEmit {
            depth: host.call_depth,
            checks: [checkTopic1, checkTopic2, checkTopic3, checkData],
            ..Default::default()
        };
        host.expected_emits.push_back(expected);
        None
    }

    /// Same as the previous method, but also checks supplied address against
    /// emitting contract.
    #[inline]
    pub fn expect_emit1(&mut self, host: &mut FuzzHost<SC>, args: Vm::expectEmit_1Call) -> Option<Vec<u8>> {
        let Vm::expectEmit_1Call {
            checkTopic1,
            checkTopic2,
            checkTopic3,
            checkData,
            emitter,
        } = args;
        let expected = ExpectedEmit {
            depth: host.call_depth,
            checks: [checkTopic1, checkTopic2, checkTopic3, checkData],
            address: Some(emitter),
            ..Default::default()
        };
        host.expected_emits.push_back(expected);
        None
    }

    /// Prepare an expected log with all topic and data checks enabled.
    /// Call this function, then emit an event, then call a function. Internally
    /// after the call, we check if logs were emitted in the expected order
    /// with the expected topics and data.
    #[inline]
    pub fn expect_emit2(&mut self, host: &mut FuzzHost<SC>) -> Option<Vec<u8>> {
        let expected = ExpectedEmit {
            depth: host.call_depth,
            checks: [true, true, true, true],
            ..Default::default()
        };
        host.expected_emits.push_back(expected);
        None
    }

    /// Same as the previous method, but also checks supplied address against
    /// emitting contract.
    #[inline]
    pub fn expect_emit3(&mut self, host: &mut FuzzHost<SC>, args: Vm::expectEmit_3Call) -> Option<Vec<u8>> {
        let Vm::expectEmit_3Call { emitter } = args;
        let expected = ExpectedEmit {
            depth: host.call_depth,
            checks: [true, true, true, true],
            address: Some(emitter),
            ..Default::default()
        };
        host.expected_emits.push_back(expected);
        None
    }

    /// Expects a call to an address with the specified calldata.
    /// Calldata can either be a strict or a partial match.
    #[inline]
    pub fn expect_call0(
        &self,
        expected_calls: &mut ExpectedCallTracker,
        args: Vm::expectCall_0Call,
    ) -> Option<Vec<u8>> {
        let Vm::expectCall_0Call { callee, data } = args;
        expect_call_non_count(expected_calls, callee, data, None)
    }

    /// Expects given number of calls to an address with the specified calldata.
    #[inline]
    pub fn expect_call1(
        &self,
        expected_calls: &mut ExpectedCallTracker,
        args: Vm::expectCall_1Call,
    ) -> Option<Vec<u8>> {
        let Vm::expectCall_1Call { callee, data, count } = args;
        expect_call_with_count(expected_calls, callee, data, None, count)
    }

    /// Expects a call to an address with the specified `msg.value` and
    /// calldata.
    #[inline]
    pub fn expect_call2(
        &self,
        expected_calls: &mut ExpectedCallTracker,
        args: Vm::expectCall_2Call,
    ) -> Option<Vec<u8>> {
        let Vm::expectCall_2Call { callee, msgValue, data } = args;
        expect_call_non_count(expected_calls, callee, data, Some(msgValue))
    }

    /// Expects given number of calls to an address with the specified
    /// `msg.value` and calldata.
    #[inline]
    pub fn expect_call3(
        &self,
        expected_calls: &mut ExpectedCallTracker,
        args: Vm::expectCall_3Call,
    ) -> Option<Vec<u8>> {
        let Vm::expectCall_3Call {
            callee,
            msgValue,
            data,
            count,
        } = args;
        expect_call_with_count(expected_calls, callee, data, Some(msgValue), count)
    }

    /// Expect a call to an address with the specified `msg.value`, gas, and
    /// calldata.
    #[inline]
    pub fn expect_call4(
        &self,
        expected_calls: &mut ExpectedCallTracker,
        args: Vm::expectCall_4Call,
    ) -> Option<Vec<u8>> {
        // ignore gas
        let Vm::expectCall_4Call {
            callee, msgValue, data, ..
        } = args;
        expect_call_non_count(expected_calls, callee, data, Some(msgValue))
    }

    /// Expects given number of calls to an address with the specified
    /// `msg.value`, gas, and calldata.
    #[inline]
    pub fn expect_call5(
        &self,
        expected_calls: &mut ExpectedCallTracker,
        args: Vm::expectCall_5Call,
    ) -> Option<Vec<u8>> {
        // ignore gas
        let Vm::expectCall_5Call {
            callee,
            msgValue,
            data,
            count,
            ..
        } = args;
        expect_call_with_count(expected_calls, callee, data, Some(msgValue), count)
    }

    /// Expect a call to an address with the specified `msg.value` and calldata,
    /// and a *minimum* amount of gas.
    #[inline]
    pub fn expect_call_mingas0(
        &self,
        expected_calls: &mut ExpectedCallTracker,
        args: Vm::expectCallMinGas_0Call,
    ) -> Option<Vec<u8>> {
        // ignore gas
        let Vm::expectCallMinGas_0Call {
            callee, msgValue, data, ..
        } = args;
        expect_call_non_count(expected_calls, callee, data, Some(msgValue))
    }

    /// Expect given number of calls to an address with the specified
    /// `msg.value` and calldata, and a *minimum* amount of gas.
    #[inline]
    pub fn expect_call_mingas1(
        &self,
        expected_calls: &mut ExpectedCallTracker,
        args: Vm::expectCallMinGas_1Call,
    ) -> Option<Vec<u8>> {
        // ignore gas
        let Vm::expectCallMinGas_1Call {
            callee,
            msgValue,
            data,
            count,
            ..
        } = args;
        expect_call_with_count(expected_calls, callee, data, Some(msgValue), count)
    }
}

fn expect_call_with_count(
    expected_calls: &mut ExpectedCallTracker,
    target: Address,
    calldata: Vec<u8>,
    value: Option<U256>,
    count: u64,
) -> Option<Vec<u8>> {
    let expecteds = expected_calls.entry(target).or_default();
    // In this case, as we're using counted expectCalls, we should not be able to
    // set them more than once.
    if expecteds.contains_key(&calldata) {
        return None;
    }

    let call_type = ExpectedCallType::Count;
    expecteds.insert(
        calldata,
        (
            ExpectedCallData {
                value,
                count,
                call_type,
            },
            0,
        ),
    );
    None
}

fn expect_call_non_count(
    expected_calls: &mut ExpectedCallTracker,
    target: Address,
    calldata: Vec<u8>,
    value: Option<U256>,
) -> Option<Vec<u8>> {
    let expecteds = expected_calls.entry(target).or_default();
    // Check if the expected calldata exists.
    // If it does, increment the count by one as we expect to see it one more time.
    if let Some(expected) = expecteds.get_mut(&calldata) {
        expected.0.count += 1;
    } else {
        // If it does not exist, then create it.
        let (count, call_type) = (1, ExpectedCallType::NonCount);
        expecteds.insert(
            calldata,
            (
                ExpectedCallData {
                    value,
                    count,
                    call_type,
                },
                0,
            ),
        );
    }

    None
}
