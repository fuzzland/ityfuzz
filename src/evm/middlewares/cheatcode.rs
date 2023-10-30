use std::clone::Clone;
use std::cmp::min;
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::marker::PhantomData;

use alloy_sol_types::{SolInterface, SolValue};
use alloy_primitives::{Address, Log as RawLog, B256, Bytes as AlloyBytes};
use bytes::Bytes;
use foundry_cheatcodes::Vm::{self, VmCalls, CallerMode};
use libafl::prelude::Input;
use revm_interpreter::{Interpreter, CallInputs};
use revm_primitives::{B160, SpecId, Env, U256, Bytecode};
use libafl::schedulers::Scheduler;
use libafl::state::{HasCorpus, State, HasMetadata, HasRand};

use crate::evm::host::FuzzHost;
use crate::evm::vm::EVMState;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasItyState};
use crate::evm::types::EVMAddress;
use crate::evm::input::{ConciseEVMInput, EVMInputT};
use super::middleware::{Middleware, MiddlewareType};

/// 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D
pub const CHEATCODE_ADDRESS: B160 = B160([
    113, 9, 112, 158, 207, 169, 26, 128, 98, 111, 243, 152, 157, 104, 246, 127, 91, 29, 209, 45,
]);

/// Tracks the expected calls per address.
///
/// For each address, we track the expected calls per call data. We track it in such manner
/// so that we don't mix together calldatas that only contain selectors and calldatas that contain
/// selector and arguments (partial and full matches).
///
/// This then allows us to customize the matching behavior for each call data on the
/// `ExpectedCallData` struct and track how many times we've actually seen the call on the second
/// element of the tuple.
///
/// BTreeMap<Address, BTreeMap<Calldata, (ExpectedCallData, count)>>
pub type ExpectedCallTracker = HashMap<Address, HashMap<Vec<u8>, (ExpectedCallData, u64)>>;

#[derive(Clone, Debug, Default)]
pub struct Cheatcode<I, VS, S, SC> {
    /// Prank information
    prank: Option<Prank>,
    /// Recorded storage reads and writes
    accesses: Option<RecordAccess>,
    /// Recorded logs
    recorded_logs: Option<Vec<Vm::Log>>,
    /// Expected revert information
    expected_revert: Option<ExpectedRevert>,
    /// Expected emits
    expected_emits: VecDeque<ExpectedEmit>,
    /// Expected calls
    expected_calls: ExpectedCallTracker,
    /// Depth of call stack
    call_depth: u64,

    _phantom: PhantomData<(I, VS, S, SC)>,
}

/// Prank information.
#[derive(Clone, Debug, Default)]
struct Prank {
    /// Address of the contract that initiated the prank
    old_caller: EVMAddress,
    /// Address of `tx.origin` when the prank was initiated
    old_origin: Option<EVMAddress>,
    /// The address to assign to `msg.sender`
    new_caller: EVMAddress,
    /// The address to assign to `tx.origin`
    new_origin: Option<EVMAddress>,
    /// Whether the prank stops by itself after the next call
    single_call: bool,
    /// The depth at which the prank was called
    depth: u64,
}

/// Records storage slots reads and writes.
#[derive(Clone, Debug, Default)]
struct RecordAccess {
    /// Storage slots reads.
    reads: HashMap<Address, Vec<U256>>,
    /// Storage slots writes.
    writes: HashMap<Address, Vec<U256>>,
}

#[derive(Clone, Debug, Default)]
struct ExpectedRevert {
    /// The expected data returned by the revert, None being any
    reason: Option<Bytes>,
    /// The depth at which the revert is expected
    depth: u64,
}

#[derive(Clone, Debug, Default)]
struct ExpectedEmit {
    /// The depth at which we expect this emit to have occurred
    depth: u64,
    /// The log we expect
    log: Option<RawLog>,
    /// The checks to perform:
    ///
    /// ┌───────┬───────┬───────┬────┐
    /// │topic 1│topic 2│topic 3│data│
    /// └───────┴───────┴───────┴────┘
    checks: [bool; 4],
    /// If present, check originating address against this
    address: Option<Address>,
    /// Whether the log was actually found in the subcalls
    found: bool,
}

#[derive(Clone, Debug)]
pub struct ExpectedCallData {
    /// The expected value sent in the call
    pub value: Option<U256>,
    /// The number of times the call is expected to be made.
    /// If the type of call is `NonCount`, this is the lower bound for the number of calls
    /// that must be seen.
    /// If the type of call is `Count`, this is the exact number of calls that must be seen.
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

enum OpcodeType {
    /// CALL cheatcode address
    CheatCall,
    /// CALL other addresses
    RealCall,
    /// SLOAD, SSTORE
    Storage,
    /// REVERT
    Revert,
    /// LOG0~LOG4
    Log,
    /// Others we don't care about
    Careless,
}

impl Prank {
    /// Create a new prank.
    pub fn new(
        old_caller: EVMAddress,
        old_origin: Option<EVMAddress>,
        new_caller: EVMAddress,
        new_origin: Option<EVMAddress>,
        single_call: bool,
        depth: u64,
    ) -> Prank {
        Prank {
            old_caller,
            old_origin,
            new_caller,
            new_origin,
            single_call,
            depth,
        }
    }
}

impl<I, VS, S, SC> Cheatcode<I, VS, S, SC>
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        + HasCorpus<Input = I>
        + HasCaller<EVMAddress>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasRand
        + Clone
        + Debug,
    VS: VMStateT,
    SC: Scheduler<State = S> + Clone,
{
    pub fn new() -> Self {
        Self {
            prank: None,
            accesses: None,
            recorded_logs: None,
            expected_revert: None,
            expected_emits: VecDeque::new(),
            call_depth: 0,
            expected_calls: ExpectedCallTracker::new(),
            _phantom: PhantomData,
        }
    }

    /// Call cheatcode address
    pub fn cheat_call(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S, SC>,
        state: &mut S,
    ) {
        let opcode = interp.current_opcode();
        interp.return_data_buffer = Bytes::new();
        let (out_offset, out_len) = unsafe { pop_return_location(interp, opcode) };
        let (input, caller, tx_origin) = (&interp.contract().input, &interp.contract().caller, &host.env.tx.caller);

        // handle vm calls
        let res = match VmCalls::abi_decode(input, false).expect("decode cheatcode failed") {
            VmCalls::warp(args) => self.warp(&mut host.env, args),
            VmCalls::roll(args) => self.roll(&mut host.env, args),
            VmCalls::fee(args) => self.fee(&mut host.env, args),
            VmCalls::difficulty(args) => self.difficulty(&mut host.env, args),
            VmCalls::prevrandao(args) => self.prevrandao(&mut host.env, args),
            VmCalls::chainId(args) => self.chain_id(&mut host.env, args),
            VmCalls::txGasPrice(args) => self.tx_gas_price(&mut host.env, args),
            VmCalls::coinbase(args) => self.coinbase(&mut host.env, args),
            VmCalls::load(args) => self.load(&host.evmstate, args),
            VmCalls::store(args) => self.store(&mut host.evmstate, args),
            VmCalls::etch(args) => self.etch(host, state, args),
            VmCalls::deal(args) => self.deal(&mut host.evmstate, args),
            VmCalls::readCallers(_) => self.read_callers(caller, tx_origin),
            VmCalls::record(_) => self.record(),
            VmCalls::accesses(args) => self.accesses(args),
            VmCalls::recordLogs(_) => self.record_logs(),
            VmCalls::getRecordedLogs(_) => self.get_recorded_logs(),
            VmCalls::prank_0(args) => self.prank0(caller, args),
            VmCalls::prank_1(args) => self.prank1(caller, tx_origin, args),
            VmCalls::startPrank_0(args) => self.start_prank0(caller, args),
            VmCalls::startPrank_1(args) => self.start_prank1(caller, tx_origin, args),
            VmCalls::stopPrank(_) => self.stop_prank(),
            VmCalls::expectRevert_0(_) => self.expect_revert0(),
            VmCalls::expectRevert_1(args) => self.expect_revert1(args),
            VmCalls::expectRevert_2(args) => self.expect_revert2(args),
            VmCalls::expectEmit_0(args) => self.expect_emit0(args),
            VmCalls::expectEmit_1(args) => self.expect_emit1(args),
            VmCalls::expectEmit_2(_) => self.expect_emit2(),
            VmCalls::expectEmit_3(args) => self.expect_emit3(args),
            VmCalls::expectCall_0(args) => self.expect_call0(args),
            VmCalls::expectCall_1(args) => self.expect_call1(args),
            VmCalls::expectCall_2(args) => self.expect_call2(args),
            VmCalls::expectCall_3(args) => self.expect_call3(args),
            VmCalls::expectCall_4(args) => self.expect_call4(args),
            VmCalls::expectCall_5(args) => self.expect_call5(args),
            VmCalls::expectCallMinGas_0(args) => self.expect_call_mingas0(args),
            VmCalls::expectCallMinGas_1(args) => self.expect_call_mingas1(args),
            _ => None,
        };

        // set up return data
        if let Some(return_data) = res {
            interp.return_data_buffer = Bytes::from(return_data);
        }
        let target_len = min(out_len, interp.return_data_buffer.len());
        interp.memory.set(out_offset, &interp.return_data_buffer[..target_len]);
        let _ = interp.stack.push(U256::from(1));

        // step over the instruction
        interp.instruction_pointer = unsafe { interp.instruction_pointer.offset(1) };
    }

    /// Call real addresses
    pub fn real_call(&mut self, interp: &mut Interpreter) {
        // Handle expected calls
        let target = Address::from(interp.contract().address.0);
        // Grab the different calldatas expected.
        if let Some(expected_calls_for_target) = self.expected_calls.get_mut(&target) {
            let contract = interp.contract();
            let (input, value) = (&contract.input, contract.value);
            // Match every partial/full calldata
            for (calldata, (expected, actual_count)) in expected_calls_for_target {
                // Increment actual times seen if the calldata is at most, as big as this call's input, and
                if calldata.len() <= input.len() &&
                    // Both calldata match, taking the length of the assumed smaller one (which will have at least the selector), and
                    *calldata == input[..calldata.len()] &&
                    // The value matches, if provided
                    expected
                        .value
                        .map_or(true, |v| v == value)
                {
                    *actual_count += 1;
                }
            }
        }

        // Update self.call_depth after applying the prank
    }

    /// Apply our prank
    pub fn apply_prank(&mut self, contract_caller: &EVMAddress, input: &mut CallInputs, env: &mut Env) {
        if let Some(prank) = &self.prank {
            if self.call_depth >= prank.depth && contract_caller == &prank.new_caller {
                // At the target depth we set `msg.sender`
                if self.call_depth == prank.depth {
                    input.context.caller = prank.new_caller;
                    input.transfer.source = prank.new_caller;
                }

                // At the target depth, or deeper, we set `tx.origin`
                if let Some(new_origin) = prank.new_origin {
                    env.tx.caller = new_origin;
                }
            }
        }

        self.call_depth += 1;
    }

    /// Check and store logs
    pub fn logs(&mut self, interp: &mut Interpreter) {
        if self.expected_emits.is_empty() && self.record_logs().is_none() {
            return;
        }

        let opcode = interp.current_opcode();
        let data =  peek_log_data(interp);
        let topics = peek_log_topics(interp, opcode);
        let address = &interp.contract().address;

        // Handle expect emit
        if !self.expected_emits.is_empty() {
            self.handle_expect_emit(&Address::from(address.0), &topics, &data);
        }

        // Stores this log if `recordLogs` has been called
        if let Some(storage_recorded_logs) = &mut self.recorded_logs {
            storage_recorded_logs.push(Vm::Log {
                topics: topics,
                data: data.to_vec(),
                emitter: Address::from((*address).0),
            });
        }
    }

    fn handle_expect_emit(&mut self, address: &Address, topics: &[B256], data: &AlloyBytes) {
        // Fill or check the expected emits.
        // We expect for emit checks to be filled as they're declared (from oldest to newest),
        // so we fill them and push them to the back of the queue.
        // If the user has properly filled all the emits, they'll end up in their original order.
        // If not, the queue will not be in the order the events will be intended to be filled,
        // and we'll be able to later detect this and bail.

        // First, we can return early if all events have been matched.
        // This allows a contract to arbitrarily emit more events than expected (additive behavior),
        // as long as all the previous events were matched in the order they were expected to be.
        if self.expected_emits.iter().all(|expected| expected.found) {
            return
        }

        // if there's anything to fill, we need to pop back.
        // Otherwise, if there are any events that are unmatched, we try to match to match them
        // in the order declared, so we start popping from the front (like a queue).
        let mut event_to_fill_or_check =
            if self.expected_emits.iter().any(|expected| expected.log.is_none()) {
                self.expected_emits.pop_back()
            } else {
                self.expected_emits.pop_front()
            }
            .expect("we should have an emit to fill or check");

        let Some(expected) = &event_to_fill_or_check.log else {
            // Fill the event.
            event_to_fill_or_check.log = Some(RawLog::new_unchecked(topics.to_vec(), data.clone()));
            self.expected_emits.push_back(event_to_fill_or_check);
            return
        };

        let expected_topic_0 = expected.topics().first();
        let log_topic_0 = topics.first();

        if expected_topic_0
            .zip(log_topic_0)
            .map_or(false, |(a, b)| a == b && expected.topics().len() == topics.len())
        {
            // Match topics
            event_to_fill_or_check.found = topics
                .iter()
                .skip(1)
                .enumerate()
                .filter(|(i, _)| event_to_fill_or_check.checks[*i])
                .all(|(i, topic)| topic == &expected.topics()[i + 1]);

            // Maybe match source address
            if let Some(addr) = event_to_fill_or_check.address {
                event_to_fill_or_check.found &= addr == *address;
            }

            // Maybe match data
            if event_to_fill_or_check.checks[3] {
                event_to_fill_or_check.found &= expected.data == *data;
            }
        }

        // If we found the event, we can push it to the back of the queue
        // and begin expecting the next event.
        if event_to_fill_or_check.found {
            self.expected_emits.push_back(event_to_fill_or_check);
        } else {
            // We did not match this event, so we need to keep waiting for the right one to
            // appear.
            self.expected_emits.push_front(event_to_fill_or_check);
        }
    }
}

impl<I, VS, S, SC> Middleware<VS, I, S, SC> for Cheatcode<I, VS, S, SC>
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        + HasCorpus<Input = I>
        + HasCaller<EVMAddress>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasRand
        + Clone
        + Debug,
    VS: VMStateT,
    SC: Scheduler<State = S> + Clone + Debug,
{
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S, SC>,
        state: &mut S,
    ) {
        let opcode = interp.current_opcode();
        let contract_addr = &interp.contract().address;
        match get_opcode_type(opcode, contract_addr) {
            OpcodeType::CheatCall => self.cheat_call(interp, host, state),
            OpcodeType::RealCall => self.real_call(interp),
            _ => ()
        }
    }

    unsafe fn on_return(
            &mut self,
            interp: &mut Interpreter,
            host: &mut FuzzHost<VS, I, S, SC>,
            state: &mut S,
            ret: &Bytes,
        ) {
        let opcode = interp.current_opcode();
        let contract_addr = &interp.contract().address;
        match get_opcode_type(opcode, contract_addr) {
            OpcodeType::RealCall => {
                self.call_depth -= 1;
                // clean up prank
            }
            _ => ()
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::Cheatcode
    }
}

/// Cheat calls
impl<I, VS, S, SC> Cheatcode<I, VS, S, SC>
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        + HasCorpus<Input = I>
        + HasCaller<EVMAddress>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasRand
        + Clone
        + Debug,
    VS: VMStateT,
    SC: Scheduler<State = S> + Clone,
{
    /// Sets `block.timestamp`.
    #[inline]
    fn warp(&self, env: &mut Env, args: Vm::warpCall) -> Option<Vec<u8>> {
        env.block.timestamp = args.newTimestamp;
        None
    }

    /// Sets `block.height`.
    #[inline]
    fn roll(&self, env: &mut Env, args: Vm::rollCall) -> Option<Vec<u8>> {
        env.block.number = args.newHeight;
        None
    }

    /// Sets `block.basefee`.
    #[inline]
    fn fee(&self, env: &mut Env, args: Vm::feeCall) -> Option<Vec<u8>> {
        env.block.basefee = args.newBasefee;
        None
    }

    /// Sets `block.difficulty`.
    /// Not available on EVM versions from Paris onwards. Use `prevrandao` instead.
    #[inline]
    fn difficulty(&self, env: &mut Env, args: Vm::difficultyCall) -> Option<Vec<u8>> {
        if env.cfg.spec_id < SpecId::MERGE {
            env.block.difficulty = args.newDifficulty;
        }
        None
    }

    /// Sets `block.prevrandao`.
    /// Not available on EVM versions before Paris. Use `difficulty` instead.
    #[inline]
    fn prevrandao(&self, env: &mut Env, args: Vm::prevrandaoCall) -> Option<Vec<u8>> {
        if env.cfg.spec_id >= SpecId::MERGE {
            env.block.prevrandao = Some(args.newPrevrandao.0.into());
        }
        None
    }

    /// Sets `block.chainid`.
    #[inline]
    fn chain_id(&self, env: &mut Env, args: Vm::chainIdCall) -> Option<Vec<u8>> {
        if args.newChainId <= U256::from(u64::MAX) {
            env.cfg.chain_id = args.newChainId;
        }
        None
    }

    /// Sets `tx.gasprice`.
    #[inline]
    fn tx_gas_price(&self, env: &mut Env, args: Vm::txGasPriceCall) -> Option<Vec<u8>> {
        env.tx.gas_price = args.newGasPrice;
        None
    }

    /// Sets `block.coinbase`.
    #[inline]
    fn coinbase(&self, env: &mut Env, args: Vm::coinbaseCall) -> Option<Vec<u8>> {
        env.block.coinbase = B160(args.newCoinbase.into());
        None
    }

    /// Loads a storage slot from an address.
    #[inline]
    fn load(&self, state: &EVMState, args: Vm::loadCall) -> Option<Vec<u8>> {
        let Vm::loadCall { target, slot } = args;
        state.sload(B160(target.into()), slot.into())
            .map(|v| v.abi_encode())
    }

    /// Stores a value to an address' storage slot.
    #[inline]
    fn store(&self, state: &mut EVMState, args: Vm::storeCall) -> Option<Vec<u8>> {
        let Vm::storeCall { target, slot, value} = args;
        state.sstore(B160(target.into()), slot.into(), value.into());
        None
    }

    /// Sets an address' code.
    #[inline]
    fn etch(&self, host: &mut FuzzHost<VS, I, S, SC>, state: &mut S, args: Vm::etchCall) -> Option<Vec<u8>> {
        let Vm::etchCall { target, newRuntimeBytecode } = args;
        let bytecode = Bytecode::new_raw(Bytes::from(newRuntimeBytecode));
        host.set_code(B160(target.into()), bytecode, state);
        None
    }

    /// Sets an address' balance.
    #[inline]
    fn deal(&self, state: &mut EVMState, args: Vm::dealCall) -> Option<Vec<u8>> {
        let Vm::dealCall { account, newBalance } = args;
        state.set_balance(B160(account.into()), newBalance.into());
        None
    }

    /// Reads the current `msg.sender` and `tx.origin` from state and reports if there is any active caller modification.
    #[inline]
    fn read_callers(&self, default_sender: &EVMAddress, default_origin: &EVMAddress) -> Option<Vec<u8>> {
        let (mut mode, mut sender, mut origin) = (CallerMode::None, default_sender, default_origin);

        if let Some(ref prank) = self.prank {
            mode = if prank.single_call {
                CallerMode::Prank
            } else {
                CallerMode::RecurrentPrank
            };
            sender = &prank.new_caller;
            if let Some(ref new_origin) = prank.new_origin {
                origin = new_origin;
            }
        }

        Some((mode, Address::from(sender.0), Address::from(origin.0)).abi_encode_params())
    }

    /// Records all storage reads and writes.
    #[inline]
    fn record(&mut self) -> Option<Vec<u8>> {
        self.accesses = Some(RecordAccess::default());
        None
    }

    /// Gets all accessed reads and write slot from a `vm.record` session, for a given address.
    #[inline]
    fn accesses(&mut self, args: Vm::accessesCall) -> Option<Vec<u8>> {
        let Vm::accessesCall { target } = args;
        let result = self
            .accesses
            .as_mut()
            .map(|accesses| {
                (
                    &accesses.reads.entry(target).or_default()[..],
                    &accesses.writes.entry(target).or_default()[..],
                )
            })
            .unwrap_or_default();
        Some(result.abi_encode_params())
    }

    /// Record all the transaction logs.
    #[inline]
    fn record_logs(&mut self) -> Option<Vec<u8>> {
        self.recorded_logs = Some(Default::default());
        None
    }

    /// Gets all the recorded logs.
    #[inline]
    fn get_recorded_logs(&mut self) -> Option<Vec<u8>> {
        let result = self.recorded_logs.replace(Default::default()).unwrap_or_default();
        Some(result.abi_encode())
    }

    /// Sets the *next* call's `msg.sender` to be the input address.
    #[inline]
    fn prank0(&mut self, old_caller: &EVMAddress, args: Vm::prank_0Call) -> Option<Vec<u8>> {
        let Vm::prank_0Call { msgSender } = args;
        self.prank = Some(
            Prank::new(
                old_caller.clone(),
                None,
                B160(msgSender.into()),
                None,
                true,
                self.call_depth,
            )
        );

        None
    }

    /// Sets the *next* call's `msg.sender` to be the input address,
    /// and the `tx.origin` to be the second input.
    #[inline]
    fn prank1(
        &mut self,
        old_caller: &EVMAddress,
        old_origin: &EVMAddress,
        args: Vm::prank_1Call
    ) -> Option<Vec<u8>> {
        let Vm::prank_1Call { msgSender, txOrigin } = args;
        self.prank = Some(
            Prank::new(
                old_caller.clone(),
                Some(old_origin.clone()),
                B160(msgSender.into()),
                Some(B160(txOrigin.into())),
                true,
                self.call_depth,
            )
        );

        None
    }

    /// Sets all subsequent calls' `msg.sender` to be the input address until `stopPrank` is called.
    #[inline]
    fn start_prank0(&mut self, old_caller: &EVMAddress, args: Vm::startPrank_0Call) -> Option<Vec<u8>> {
        let Vm::startPrank_0Call { msgSender } = args;
        self.prank = Some(
            Prank::new(
                old_caller.clone(),
                None,
                B160(msgSender.into()),
                None,
                false,
                self.call_depth,
            )
        );

        None
    }

    /// Sets all subsequent calls' `msg.sender` to be the input address until `stopPrank` is called,
    /// and the `tx.origin` to be the second input.
    #[inline]
    fn start_prank1(
        &mut self,
        old_caller: &EVMAddress,
        old_origin: &EVMAddress,
        args: Vm::startPrank_1Call
    ) -> Option<Vec<u8>> {
        let Vm::startPrank_1Call { msgSender, txOrigin } = args;
        self.prank = Some(
            Prank::new(
                old_caller.clone(),
                Some(old_origin.clone()),
                B160(msgSender.into()),
                Some(B160(txOrigin.into())),
                false,
                self.call_depth,
            )
        );

        None
    }

    /// Resets subsequent calls' `msg.sender` to be `address(this)`.
    #[inline]
    fn stop_prank(&mut self) -> Option<Vec<u8>> {
        self.prank = None;
        None
    }

    /// Expects an error on next call with any revert data.
    #[inline]
    fn expect_revert0(&mut self) -> Option<Vec<u8>> {
        self.expected_revert = Some(ExpectedRevert {
            reason: None,
            depth: self.call_depth,
        });
        None
    }

    /// Expects an error on next call that starts with the revert data.
    #[inline]
    fn expect_revert1(&mut self, args: Vm::expectRevert_1Call) -> Option<Vec<u8>> {
        let Vm::expectRevert_1Call{ revertData } = args;
        let reason = Some(Bytes::from(revertData.0.to_vec()));
        self.expected_revert = Some(ExpectedRevert {
            reason,
            depth: self.call_depth,
        });
        None
    }

    /// Expects an error on next call that exactly matches the revert data.
    #[inline]
    fn expect_revert2(&mut self, args: Vm::expectRevert_2Call) -> Option<Vec<u8>> {
        let Vm::expectRevert_2Call{ revertData } = args;
        let reason = Some(Bytes::from(revertData));
        self.expected_revert = Some(ExpectedRevert {
            reason,
            depth: self.call_depth,
        });
        None
    }

    /// Prepare an expected log with (bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData.).
    /// Call this function, then emit an event, then call a function. Internally after the call, we check if
    /// logs were emitted in the expected order with the expected topics and data (as specified by the booleans).
    #[inline]
    fn expect_emit0(&mut self, args: Vm::expectEmit_0Call) -> Option<Vec<u8>> {
        let Vm::expectEmit_0Call { checkTopic1, checkTopic2, checkTopic3, checkData } = args;
        let expected = ExpectedEmit {
            depth: self.call_depth,
            checks: [checkTopic1, checkTopic2, checkTopic3, checkData],
            ..Default::default()
        };
        self.expected_emits.push_back(expected);
        None
    }

    /// Same as the previous method, but also checks supplied address against emitting contract.
    #[inline]
    fn expect_emit1(&mut self, args: Vm::expectEmit_1Call) -> Option<Vec<u8>> {
        let Vm::expectEmit_1Call {
            checkTopic1,
            checkTopic2,
            checkTopic3,
            checkData,
            emitter,
        } = args;
        let expected = ExpectedEmit {
            depth: self.call_depth,
            checks: [checkTopic1, checkTopic2, checkTopic3, checkData],
            address: Some(emitter),
            ..Default::default()
        };
        self.expected_emits.push_back(expected);
        None
    }

    /// Prepare an expected log with all topic and data checks enabled.
    /// Call this function, then emit an event, then call a function. Internally after the call, we check if
    /// logs were emitted in the expected order with the expected topics and data.
    #[inline]
    fn expect_emit2(&mut self) -> Option<Vec<u8>> {
        let expected = ExpectedEmit {
            depth: self.call_depth,
            checks: [true, true, true, true],
            ..Default::default()
        };
        self.expected_emits.push_back(expected);
        None
    }

    /// Same as the previous method, but also checks supplied address against emitting contract.
    #[inline]
    fn expect_emit3(&mut self, args: Vm::expectEmit_3Call) -> Option<Vec<u8>> {
        let Vm::expectEmit_3Call { emitter } = args;
        let expected = ExpectedEmit {
            depth: self.call_depth,
            checks: [true, true, true, true],
            address: Some(emitter),
            ..Default::default()
        };
        self.expected_emits.push_back(expected);
        None
    }

    /// Expects a call to an address with the specified calldata.
    /// Calldata can either be a strict or a partial match.
    #[inline]
    fn expect_call0(&mut self, args: Vm::expectCall_0Call) -> Option<Vec<u8>> {
        let Vm::expectCall_0Call { callee, data } = args;
        self.expect_call_non_count(callee, data, None)
    }

    /// Expects given number of calls to an address with the specified calldata.
    #[inline]
    fn expect_call1(&mut self, args: Vm::expectCall_1Call) -> Option<Vec<u8>> {
        let Vm::expectCall_1Call { callee, data, count } = args;
        self.expect_call_with_count(callee, data, None, count)
    }

    /// Expects a call to an address with the specified `msg.value` and calldata.
    #[inline]
    fn expect_call2(&mut self, args: Vm::expectCall_2Call) -> Option<Vec<u8>> {
        let Vm::expectCall_2Call { callee, msgValue, data } = args;
        self.expect_call_non_count(callee, data, Some(msgValue))
    }

    /// Expects given number of calls to an address with the specified `msg.value` and calldata.
    #[inline]
    fn expect_call3(&mut self, args: Vm::expectCall_3Call) -> Option<Vec<u8>> {
        let Vm::expectCall_3Call { callee, msgValue, data, count } = args;
        self.expect_call_with_count(callee, data, Some(msgValue), count)
    }

    /// Expect a call to an address with the specified `msg.value`, gas, and calldata.
    #[inline]
    fn expect_call4(&mut self, args: Vm::expectCall_4Call) -> Option<Vec<u8>> {
        // ignore gas
        let Vm::expectCall_4Call { callee, msgValue, data, .. } = args;
        self.expect_call_non_count(callee, data, Some(msgValue))
    }

    /// Expects given number of calls to an address with the specified `msg.value`, gas, and calldata.
    #[inline]
    fn expect_call5(&mut self, args: Vm::expectCall_5Call) -> Option<Vec<u8>> {
        // ignore gas
        let Vm::expectCall_5Call { callee, msgValue, data, count, .. } = args;
        self.expect_call_with_count(callee, data, Some(msgValue), count)
    }

    /// Expect a call to an address with the specified `msg.value` and calldata, and a *minimum* amount of gas.
    #[inline]
    fn expect_call_mingas0(&mut self, args: Vm::expectCallMinGas_0Call) -> Option<Vec<u8>> {
        // ignore gas
        let Vm::expectCallMinGas_0Call { callee, msgValue, data, .. } = args;
        self.expect_call_non_count(callee, data, Some(msgValue))
    }

    /// Expect given number of calls to an address with the specified `msg.value` and calldata, and a *minimum* amount of gas.
    #[inline]
    fn expect_call_mingas1(&mut self, args: Vm::expectCallMinGas_1Call) -> Option<Vec<u8>> {
        // ignore gas
        let Vm::expectCallMinGas_1Call { callee, msgValue, data, count, .. } = args;
        self.expect_call_with_count(callee, data, Some(msgValue), count)
    }

    fn expect_call_non_count(
        &mut self,
        target: Address,
        calldata: Vec<u8>,
        value: Option<U256>,
    ) -> Option<Vec<u8>> {
        let expecteds = self.expected_calls.entry(target).or_default();
        // Check if the expected calldata exists.
        // If it does, increment the count by one as we expect to see it one more time.
        if let Some(expected) = expecteds.get_mut(&calldata) {
            expected.0.count += 1;
        } else {
            // If it does not exist, then create it.
            let (count, call_type) = (1, ExpectedCallType::NonCount);
            expecteds.insert(
                calldata,
                (ExpectedCallData { value, count, call_type }, 0),
            );
        }

        None
    }

    fn expect_call_with_count(
        &mut self,
        target: Address,
        calldata: Vec<u8>,
        value: Option<U256>,
        count: u64,
    ) -> Option<Vec<u8>> {
        let expecteds = self.expected_calls.entry(target).or_default();
        // In this case, as we're using counted expectCalls, we should not be able to set them
        // more than once.
        if expecteds.contains_key(&calldata) {
            return None;
        }

        let call_type = ExpectedCallType::Count;
        expecteds
            .insert(calldata, (ExpectedCallData { value, count, call_type }, 0));
        None
    }
}


unsafe fn pop_return_location(interp: &mut Interpreter, opcode: u8) -> (usize, usize) {
    if opcode == 0xf1 || opcode == 0xf2 {
        let _ = interp.stack.pop_unsafe();
    }
    let (_, _, _, _) = interp.stack.pop4_unsafe();
    let (out_offset, out_len) = interp.stack.pop2_unsafe();

    (out_offset.as_limbs()[0] as usize, out_len.as_limbs()[0] as usize)
}

fn peek_log_data(interp: &mut Interpreter) -> AlloyBytes {
    let stack_len = interp.stack().len();
    let offset = interp.stack.data()[stack_len - 1];
    let len = interp.stack.data()[stack_len - 2];
    let (offset, len) = (offset.as_limbs()[0] as usize, len.as_limbs()[0] as usize);
    if len == 0 {
        return AlloyBytes::new();
    }

    // resize memory if necessary
    let new_size = offset.checked_add(len).expect("Recorded log data exceeds memory size");
    #[cfg(feature = "memory_limit")]
    if new_size > interp.memory_limit as usize {
        panic!("Recorded log data exceeds memory limit");
    }
    if new_size > interp.memory.len() {
        interp.memory.resize(new_size);
    }

    AlloyBytes::copy_from_slice(interp.memory.get_slice(offset, len))
}

fn peek_log_topics(interp: &mut Interpreter, opcode: u8) -> Vec<B256> {
    let n = (opcode - 0xa0) as usize;
    if interp.stack.len() < n + 2 {
        panic!("Not enough topics on the stack");
    }

    let stack_len = interp.stack().len();
    let mut topics = Vec::with_capacity(n);
    for i in 0..n {
        topics.push(B256::from(interp.stack.data()[stack_len - 3 - i].to_be_bytes()));
    }

    topics
}

fn get_opcode_type(opcode: u8, contract: &B160) -> OpcodeType {
    if opcode != 0xf1 && opcode != 0xf2 && opcode != 0xf4 && opcode != 0xfa {
        if contract == &CHEATCODE_ADDRESS {
            return OpcodeType::CheatCall;
        }
        return OpcodeType::RealCall;
    }

    match opcode {
        0x54 | 0x55 => OpcodeType::Storage,
        0xa0..=0xa4 => OpcodeType::Log,
        0xfd => OpcodeType::Revert,
        _ => OpcodeType::Careless,
    }
}
