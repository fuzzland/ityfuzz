use std::{
    clone::Clone,
    cmp::min,
    collections::{HashMap, VecDeque},
    fmt::Debug,
    marker::PhantomData,
    ops::{BitAnd, Not},
    sync::Arc,
};

use alloy_primitives::{Address, Bytes as AlloyBytes, Log as RawLog, B256};
use alloy_sol_types::{SolInterface, SolValue};
use bytes::Bytes;
use foundry_cheatcodes::Vm::{self, CallerMode, VmCalls};
use libafl::schedulers::Scheduler;
use revm_interpreter::{analysis::to_analysed, opcode, BytecodeLocked, InstructionResult, Interpreter};
use revm_primitives::{Bytecode, Env, SpecId, B160, U256};
use tracing::{debug, error, warn};

use super::middleware::{Middleware, MiddlewareType};
use crate::evm::{
    host::FuzzHost,
    types::{EVMAddress, EVMFuzzState},
    vm::EVMState,
};

/// 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D
/// address(bytes20(uint160(uint256(keccak256('hevm cheat code')))))
pub const CHEATCODE_ADDRESS: B160 = B160([
    113, 9, 112, 158, 207, 169, 26, 128, 98, 111, 243, 152, 157, 104, 246, 127, 91, 29, 209, 45,
]);

/// Solidity revert prefix.
///
/// `keccak256("Error(String)")[..4] == 0x08c379a0`
pub const REVERT_PREFIX: [u8; 4] = [8, 195, 121, 160];

/// Custom Cheatcode error prefix.
///
/// `keccak256("CheatCodeError")[..4] == 0x0bc44503`
pub const ERROR_PREFIX: [u8; 4] = [11, 196, 69, 3];

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
pub struct Cheatcode<SC> {
    /// Recorded storage reads and writes
    accesses: Option<RecordAccess>,
    /// Recorded logs
    recorded_logs: Option<Vec<Vm::Log>>,

    _phantom: PhantomData<SC>,
}

/// Prank information.
#[derive(Clone, Debug, Default)]
pub struct Prank {
    /// Address of the contract that initiated the prank
    pub old_caller: EVMAddress,
    /// Address of `tx.origin` when the prank was initiated
    pub old_origin: Option<EVMAddress>,
    /// The address to assign to `msg.sender`
    pub new_caller: EVMAddress,
    /// The address to assign to `tx.origin`
    pub new_origin: Option<EVMAddress>,
    /// Whether the prank stops by itself after the next call
    pub single_call: bool,
    /// The depth at which the prank was called
    pub depth: u64,
}

/// Records storage slots reads and writes.
#[derive(Clone, Debug, Default)]
struct RecordAccess {
    /// Storage slots reads.
    reads: HashMap<EVMAddress, Vec<U256>>,
    /// Storage slots writes.
    writes: HashMap<EVMAddress, Vec<U256>>,
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
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

macro_rules! try_or_continue {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => {
                debug!("skip cheatcode due to: {:?}", e);
                return;
            }
        }
    };
}

macro_rules! cheat_call_error {
    ($interp:expr, $err:expr) => {{
        error!("[cheatcode] failed to call CHEATCODE_ADDRESS: {:?}", $err);
        $interp.instruction_result = $err;
        let _ = $interp.stack.push(U256::ZERO);
        $interp.instruction_pointer = unsafe { $interp.instruction_pointer.offset(1) };
        return;
    }};
}

impl<SC> Middleware<SC> for Cheatcode<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone + Debug,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) {
        let op = interp.current_opcode();
        match get_opcode_type(op, interp) {
            OpcodeType::CheatCall => self.cheat_call(interp, host),
            OpcodeType::RealCall => self.real_call(interp, &mut host.expected_calls),
            OpcodeType::Storage => self.record_accesses(interp),
            OpcodeType::Log => self.log(interp, &mut host.expected_emits),
            _ => (),
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::Cheatcode
    }
}

impl<SC> Cheatcode<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    pub fn new() -> Self {
        Self {
            accesses: None,
            recorded_logs: None,
            _phantom: PhantomData,
        }
    }

    /// Call cheatcode address
    pub fn cheat_call(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>) {
        let op = interp.current_opcode();
        let calldata = unsafe { pop_cheatcall_stack(interp, op) };
        if let Err(err) = calldata {
            cheat_call_error!(interp, err);
        }

        let (input, out_offset, out_len) = calldata.unwrap();
        if let Err(err) = try_memory_resize(interp, out_offset, out_len) {
            cheat_call_error!(interp, err);
        }

        let (caller, tx_origin) = (&interp.contract().caller, &host.env.tx.caller.clone());
        // handle vm calls
        let vm_call = VmCalls::abi_decode(&input, false).expect("decode cheatcode failed");
        debug!("[cheatcode] vm.{:?}", vm_call);
        let res = match vm_call {
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
            VmCalls::etch(args) => self.etch(host, args),
            VmCalls::deal(args) => self.deal(&mut host.evmstate, args),
            VmCalls::readCallers(_) => self.read_callers(&host.prank, caller, tx_origin),
            VmCalls::record(_) => self.record(),
            VmCalls::accesses(args) => self.accesses(args),
            VmCalls::recordLogs(_) => self.record_logs(),
            VmCalls::getRecordedLogs(_) => self.get_recorded_logs(),
            VmCalls::prank_0(args) => self.prank0(host, caller, args),
            VmCalls::prank_1(args) => self.prank1(host, caller, tx_origin, args),
            VmCalls::startPrank_0(args) => self.start_prank0(host, caller, args),
            VmCalls::startPrank_1(args) => self.start_prank1(host, caller, tx_origin, args),
            VmCalls::stopPrank(_) => self.stop_prank(host),
            VmCalls::expectRevert_0(_) => self.expect_revert0(host),
            VmCalls::expectRevert_1(args) => self.expect_revert1(host, args),
            VmCalls::expectRevert_2(args) => self.expect_revert2(host, args),
            VmCalls::expectEmit_0(args) => self.expect_emit0(host, args),
            VmCalls::expectEmit_1(args) => self.expect_emit1(host, args),
            VmCalls::expectEmit_2(_) => self.expect_emit2(host),
            VmCalls::expectEmit_3(args) => self.expect_emit3(host, args),
            VmCalls::expectCall_0(args) => self.expect_call0(&mut host.expected_calls, args),
            VmCalls::expectCall_1(args) => self.expect_call1(&mut host.expected_calls, args),
            VmCalls::expectCall_2(args) => self.expect_call2(&mut host.expected_calls, args),
            VmCalls::expectCall_3(args) => self.expect_call3(&mut host.expected_calls, args),
            VmCalls::expectCall_4(args) => self.expect_call4(&mut host.expected_calls, args),
            VmCalls::expectCall_5(args) => self.expect_call5(&mut host.expected_calls, args),
            VmCalls::expectCallMinGas_0(args) => self.expect_call_mingas0(&mut host.expected_calls, args),
            VmCalls::expectCallMinGas_1(args) => self.expect_call_mingas1(&mut host.expected_calls, args),
            VmCalls::addr(args) => self.addr(args),
            _ => {
                warn!("[cheatcode] unknown VmCall: {:?}", vm_call);
                None
            }
        };
        debug!("[cheatcode] VmCall result: {:?}", res);

        // set up return data
        interp.instruction_result = InstructionResult::Continue;
        interp.return_data_buffer = Bytes::new();
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
    pub fn real_call(&self, interp: &mut Interpreter, expected_calls: &mut ExpectedCallTracker) {
        let target = peek_realcall_target(interp);
        if let Err(err) = target {
            error!("[cheatcode] failed to peek call target: {:?}", err);
            return;
        }
        let target = target.unwrap();

        // Grab the different calldatas expected.
        if let Some(expected_calls_for_target) = expected_calls.get_mut(&target) {
            let op = interp.current_opcode();
            let callstack = peek_realcall_input_value(interp, op);
            if let Err(err) = callstack {
                error!("[cheatcode] failed to peek call input: {:?}", err);
                return;
            }
            let (input, value) = callstack.unwrap();
            debug!(
                "[cheatcode] handle expected_calls_for_target: {:?}, input: {:?}, value: {:?}",
                target, input, value
            );

            // Match every partial/full calldata
            for (calldata, (expected, actual_count)) in expected_calls_for_target {
                // Increment actual times seen if the calldata is at most, as big as this call's
                // input, and
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
    }

    /// Record storage writes and reads if `record` has been called
    pub fn record_accesses(&mut self, interp: &mut Interpreter) {
        if let Some(storage_accesses) = &mut self.accesses {
            debug!("[cheatcode] record_accesses");
            match interp.current_opcode() {
                opcode::SLOAD => {
                    let key = try_or_continue!(interp.stack().peek(0));
                    storage_accesses
                        .reads
                        .entry(interp.contract().address)
                        .or_default()
                        .push(key);
                }
                opcode::SSTORE => {
                    let key = try_or_continue!(interp.stack().peek(0));

                    // An SSTORE does an SLOAD internally
                    storage_accesses
                        .reads
                        .entry(interp.contract().address)
                        .or_default()
                        .push(key);
                    storage_accesses
                        .writes
                        .entry(interp.contract().address)
                        .or_default()
                        .push(key);
                }
                _ => (),
            }
        }
    }

    /// Check emits / Record logs
    pub fn log(&mut self, interp: &mut Interpreter, expected_emits: &mut VecDeque<ExpectedEmit>) {
        if expected_emits.is_empty() && self.recorded_logs.is_none() {
            return;
        }

        debug!("[cheatcode] log");
        let op = interp.current_opcode();
        let data = try_or_continue!(peek_log_data(interp));
        let topics = try_or_continue!(peek_log_topics(interp, op));
        let address = &interp.contract().address;

        // Handle expect emit
        if !expected_emits.is_empty() {
            handle_expect_emit(expected_emits, &Address::from(address.0), &topics, &data);
        }

        // Stores this log if `recordLogs` has been called
        if let Some(storage_recorded_logs) = &mut self.recorded_logs {
            storage_recorded_logs.push(Vm::Log {
                topics,
                data: data.to_vec(),
                emitter: Address::from(address.0),
            });
        }
    }
}

/// Cheat VmCalls
impl<SC> Cheatcode<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
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
    /// Not available on EVM versions from Paris onwards. Use `prevrandao`
    /// instead.
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

        Some(
            state
                .sload(B160(target.into()), slot.into())
                .unwrap_or_default()
                .abi_encode(),
        )
    }

    /// Stores a value to an address' storage slot.
    #[inline]
    fn store(&self, state: &mut EVMState, args: Vm::storeCall) -> Option<Vec<u8>> {
        let Vm::storeCall { target, slot, value } = args;
        state.sstore(B160(target.into()), slot.into(), value.into());
        None
    }

    /// Sets an address' code.
    #[inline]
    fn etch(&self, host: &mut FuzzHost<SC>, args: Vm::etchCall) -> Option<Vec<u8>> {
        let Vm::etchCall {
            target,
            newRuntimeBytecode,
        } = args;
        let bytecode = to_analysed(Bytecode::new_raw(Bytes::from(newRuntimeBytecode)));

        // set code but don't invoke middlewares
        host.code.insert(
            B160(target.into()),
            Arc::new(BytecodeLocked::try_from(bytecode).unwrap()),
        );
        None
    }

    /// Sets an address' balance.
    #[inline]
    fn deal(&self, state: &mut EVMState, args: Vm::dealCall) -> Option<Vec<u8>> {
        let Vm::dealCall { account, newBalance } = args;
        state.set_balance(B160(account.into()), newBalance);
        None
    }

    /// Reads the current `msg.sender` and `tx.origin` from state and reports if
    /// there is any active caller modification.
    #[inline]
    fn read_callers(
        &self,
        prank: &Option<Prank>,
        default_sender: &EVMAddress,
        default_origin: &EVMAddress,
    ) -> Option<Vec<u8>> {
        let (mut mode, mut sender, mut origin) = (CallerMode::None, default_sender, default_origin);

        if let Some(ref prank) = prank {
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

    /// Gets all accessed reads and write slot from a `vm.record` session, for a
    /// given address.
    #[inline]
    fn accesses(&mut self, args: Vm::accessesCall) -> Option<Vec<u8>> {
        let Vm::accessesCall { target } = args;
        let target = B160(target.into());

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
    fn prank0(&mut self, host: &mut FuzzHost<SC>, old_caller: &EVMAddress, args: Vm::prank_0Call) -> Option<Vec<u8>> {
        let Vm::prank_0Call { msgSender } = args;
        host.prank = Some(Prank::new(
            *old_caller,
            None,
            B160(msgSender.into()),
            None,
            true,
            host.call_depth,
        ));

        None
    }

    /// Sets the *next* call's `msg.sender` to be the input address,
    /// and the `tx.origin` to be the second input.
    #[inline]
    fn prank1(
        &mut self,
        host: &mut FuzzHost<SC>,
        old_caller: &EVMAddress,
        old_origin: &EVMAddress,
        args: Vm::prank_1Call,
    ) -> Option<Vec<u8>> {
        let Vm::prank_1Call { msgSender, txOrigin } = args;
        host.prank = Some(Prank::new(
            *old_caller,
            Some(*old_origin),
            B160(msgSender.into()),
            Some(B160(txOrigin.into())),
            true,
            host.call_depth,
        ));

        None
    }

    /// Sets all subsequent calls' `msg.sender` to be the input address until
    /// `stopPrank` is called.
    #[inline]
    fn start_prank0(
        &mut self,
        host: &mut FuzzHost<SC>,
        old_caller: &EVMAddress,
        args: Vm::startPrank_0Call,
    ) -> Option<Vec<u8>> {
        let Vm::startPrank_0Call { msgSender } = args;
        host.prank = Some(Prank::new(
            *old_caller,
            None,
            B160(msgSender.into()),
            None,
            false,
            host.call_depth,
        ));

        None
    }

    /// Sets all subsequent calls' `msg.sender` to be the input address until
    /// `stopPrank` is called, and the `tx.origin` to be the second input.
    #[inline]
    fn start_prank1(
        &mut self,
        host: &mut FuzzHost<SC>,
        old_caller: &EVMAddress,
        old_origin: &EVMAddress,
        args: Vm::startPrank_1Call,
    ) -> Option<Vec<u8>> {
        let Vm::startPrank_1Call { msgSender, txOrigin } = args;
        host.prank = Some(Prank::new(
            *old_caller,
            Some(*old_origin),
            B160(msgSender.into()),
            Some(B160(txOrigin.into())),
            false,
            host.call_depth,
        ));

        None
    }

    /// Resets subsequent calls' `msg.sender` to be `address(this)`.
    #[inline]
    fn stop_prank(&mut self, host: &mut FuzzHost<SC>) -> Option<Vec<u8>> {
        let _ = host.prank.take();
        None
    }

    /// Expects an error on next call with any revert data.
    #[inline]
    fn expect_revert0(&mut self, host: &mut FuzzHost<SC>) -> Option<Vec<u8>> {
        host.expected_revert = Some(ExpectedRevert {
            reason: None,
            depth: host.call_depth,
        });
        None
    }

    /// Expects an error on next call that starts with the revert data.
    #[inline]
    fn expect_revert1(&mut self, host: &mut FuzzHost<SC>, args: Vm::expectRevert_1Call) -> Option<Vec<u8>> {
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
    fn expect_revert2(&mut self, host: &mut FuzzHost<SC>, args: Vm::expectRevert_2Call) -> Option<Vec<u8>> {
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
    fn expect_emit0(&mut self, host: &mut FuzzHost<SC>, args: Vm::expectEmit_0Call) -> Option<Vec<u8>> {
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
    fn expect_emit1(&mut self, host: &mut FuzzHost<SC>, args: Vm::expectEmit_1Call) -> Option<Vec<u8>> {
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
    fn expect_emit2(&mut self, host: &mut FuzzHost<SC>) -> Option<Vec<u8>> {
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
    fn expect_emit3(&mut self, host: &mut FuzzHost<SC>, args: Vm::expectEmit_3Call) -> Option<Vec<u8>> {
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
    fn expect_call0(&self, expected_calls: &mut ExpectedCallTracker, args: Vm::expectCall_0Call) -> Option<Vec<u8>> {
        let Vm::expectCall_0Call { callee, data } = args;
        expect_call_non_count(expected_calls, callee, data, None)
    }

    /// Expects given number of calls to an address with the specified calldata.
    #[inline]
    fn expect_call1(&self, expected_calls: &mut ExpectedCallTracker, args: Vm::expectCall_1Call) -> Option<Vec<u8>> {
        let Vm::expectCall_1Call { callee, data, count } = args;
        expect_call_with_count(expected_calls, callee, data, None, count)
    }

    /// Expects a call to an address with the specified `msg.value` and
    /// calldata.
    #[inline]
    fn expect_call2(&self, expected_calls: &mut ExpectedCallTracker, args: Vm::expectCall_2Call) -> Option<Vec<u8>> {
        let Vm::expectCall_2Call { callee, msgValue, data } = args;
        expect_call_non_count(expected_calls, callee, data, Some(msgValue))
    }

    /// Expects given number of calls to an address with the specified
    /// `msg.value` and calldata.
    #[inline]
    fn expect_call3(&self, expected_calls: &mut ExpectedCallTracker, args: Vm::expectCall_3Call) -> Option<Vec<u8>> {
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
    fn expect_call4(&self, expected_calls: &mut ExpectedCallTracker, args: Vm::expectCall_4Call) -> Option<Vec<u8>> {
        // ignore gas
        let Vm::expectCall_4Call {
            callee, msgValue, data, ..
        } = args;
        expect_call_non_count(expected_calls, callee, data, Some(msgValue))
    }

    /// Expects given number of calls to an address with the specified
    /// `msg.value`, gas, and calldata.
    #[inline]
    fn expect_call5(&self, expected_calls: &mut ExpectedCallTracker, args: Vm::expectCall_5Call) -> Option<Vec<u8>> {
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
    fn expect_call_mingas0(
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
    fn expect_call_mingas1(
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

    /// Gets the address for a given private key.
    fn addr(&self, args: Vm::addrCall) -> Option<Vec<u8>> {
        let Vm::addrCall { privateKey } = args;
        let address: Address = privateKey.to_be_bytes::<{ U256::BYTES }>()[..20].try_into().unwrap();
        Some(address.abi_encode())
    }
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

macro_rules! memory_resize {
    ($interp:expr, $offset:expr, $len:expr) => {{
        let len: usize = $len;
        let offset: usize = $offset;
        let new_size = {
            let x = offset.saturating_add(len);
            // Rounds up `x` to the closest multiple of 32. If `x % 32 == 0` then `x` is
            // returned.
            let r = x.bitand(31).not().wrapping_add(1).bitand(31);
            x.checked_add(r)
        };

        if let Some(new_size) = new_size {
            #[cfg(feature = "memory_limit")]
            if new_size > ($interp.memory_limit as usize) {
                return Err(InstructionResult::MemoryLimitOOG);
            }
            if new_size > $interp.memory.len() {
                $interp.memory.resize(new_size);
            }
        } else {
            return Err(InstructionResult::MemoryOOG);
        }
    }};
}

unsafe fn pop_cheatcall_stack(interp: &mut Interpreter, op: u8) -> Result<(Bytes, usize, usize), InstructionResult> {
    // Pop gas, addr, val
    if op == opcode::CALL || op == opcode::CALLCODE {
        let _ = interp.stack.pop_unsafe();
    }
    let _ = interp.stack.pop2_unsafe();

    let (in_offset, in_len, out_offset, out_len) = {
        let (in_offset, in_len, out_offset, out_len) = interp.stack.pop4_unsafe();
        (
            in_offset.as_limbs()[0] as usize,
            in_len.as_limbs()[0] as usize,
            out_offset.as_limbs()[0] as usize,
            out_len.as_limbs()[0] as usize,
        )
    };

    let input = if in_len != 0 {
        memory_resize!(interp, in_offset, in_len);
        Bytes::copy_from_slice(interp.memory.get_slice(in_offset, in_len))
    } else {
        Bytes::new()
    };

    Ok((input, out_offset, out_len))
}

// Every real call needs to peek the target address.
fn peek_realcall_target(interp: &Interpreter) -> Result<Address, InstructionResult> {
    let addr_bytes = interp.stack().peek(1)?;
    let addr: Address = addr_bytes.to_be_bytes::<{ U256::BYTES }>()[12..].try_into().unwrap();
    Ok(addr)
}

// Peek input and value only when target is in the expected calls.
//
// CALL|CALLCODE: gas, addr, val, in_offset, in_len, out_offset, out_len
// DELEGATECALL|STATICCALL: gas, addr, in_offset, in_len, out_offset, out_len
fn peek_realcall_input_value(interp: &mut Interpreter, op: u8) -> Result<(Bytes, U256), InstructionResult> {
    let value = if op == opcode::CALL || op == opcode::CALLCODE {
        interp.stack().peek(2)?
    } else {
        U256::ZERO
    };

    let (in_offset, in_len) = {
        let (in_offset, in_len) = if op == opcode::CALL || op == opcode::CALLCODE {
            (interp.stack().peek(3)?, interp.stack().peek(4)?)
        } else {
            (interp.stack().peek(2)?, interp.stack().peek(3)?)
        };

        (in_offset.as_limbs()[0] as usize, in_len.as_limbs()[0] as usize)
    };

    let input = if in_len != 0 {
        memory_resize!(interp, in_offset, in_len);
        Bytes::copy_from_slice(interp.memory.get_slice(in_offset, in_len))
    } else {
        Bytes::new()
    };

    Ok((input, value))
}

fn peek_log_data(interp: &mut Interpreter) -> Result<AlloyBytes, InstructionResult> {
    let offset = interp.stack().peek(0)?;
    let len = interp.stack().peek(1)?;
    let (offset, len) = (offset.as_limbs()[0] as usize, len.as_limbs()[0] as usize);
    if len == 0 {
        return Ok(AlloyBytes::new());
    }

    memory_resize!(interp, offset, len);
    Ok(AlloyBytes::copy_from_slice(interp.memory.get_slice(offset, len)))
}

fn peek_log_topics(interp: &Interpreter, op: u8) -> Result<Vec<B256>, InstructionResult> {
    let n = (op - opcode::LOG0) as usize;
    let mut topics = Vec::with_capacity(n);

    // Start from idx 2. The first two elements are the offset and len of the data.
    for i in 2..(n + 2) {
        let topic = interp.stack().peek(i)?;
        topics.push(B256::from(topic.to_be_bytes()));
    }

    Ok(topics)
}

fn try_memory_resize(interp: &mut Interpreter, offset: usize, len: usize) -> Result<(), InstructionResult> {
    memory_resize!(interp, offset, len);
    Ok(())
}

fn get_opcode_type(op: u8, interp: &Interpreter) -> OpcodeType {
    match op {
        opcode::CALL | opcode::CALLCODE | opcode::DELEGATECALL | opcode::STATICCALL => {
            let target: B160 = B160(
                interp.stack().peek(1).unwrap().to_be_bytes::<{ U256::BYTES }>()[12..]
                    .try_into()
                    .unwrap(),
            );

            if target.as_slice() == CHEATCODE_ADDRESS.as_slice() {
                OpcodeType::CheatCall
            } else {
                OpcodeType::RealCall
            }
        }
        opcode::SLOAD | opcode::SSTORE => OpcodeType::Storage,
        opcode::LOG0..=opcode::LOG4 => OpcodeType::Log,
        opcode::REVERT => OpcodeType::Revert,
        _ => OpcodeType::Careless,
    }
}

// Handle an emitting log and update `expected_emits` which will be checked
// before the call returns.
fn handle_expect_emit(
    expected_emits: &mut VecDeque<ExpectedEmit>,
    address: &Address,
    topics: &[B256],
    data: &AlloyBytes,
) {
    if expected_emits.iter().all(|expected| expected.found) {
        return;
    }

    // if there's anything to fill, we need to pop back.
    // Otherwise, if there are any events that are unmatched, we try to match to
    // match them in the order declared, so we start popping from the front
    // (like a queue).
    let mut event_to_fill_or_check = if expected_emits.iter().any(|expected| expected.log.is_none()) {
        expected_emits.pop_back()
    } else {
        expected_emits.pop_front()
    }
    .expect("we should have an emit to fill or check");

    let Some(expected) = &event_to_fill_or_check.log else {
        // Fill the event.
        event_to_fill_or_check.log = Some(RawLog::new_unchecked(topics.to_vec(), data.clone()));
        expected_emits.push_back(event_to_fill_or_check);
        return;
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
        expected_emits.push_back(event_to_fill_or_check);
    } else {
        // We did not match this event, so we need to keep waiting for the right one to
        // appear.
        expected_emits.push_front(event_to_fill_or_check);
    }
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

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, fs, path::Path, rc::Rc, str::FromStr};

    use bytes::Bytes;
    use libafl::prelude::StdScheduler;
    use revm_primitives::Bytecode;

    use super::*;
    use crate::{
        evm::{
            host::FuzzHost,
            input::{ConciseEVMInput, EVMInput, EVMInputTy},
            mutator::AccessPattern,
            types::{generate_random_address, EVMFuzzState, EVMU256},
            vm::{EVMExecutor, EVMState},
        },
        generic_vm::vm_executor::GenericVM,
        state::FuzzState,
        state_input::StagedVMState,
    };

    #[test]
    fn test_foundry_contract() {
        let mut state: EVMFuzzState = FuzzState::new(0);

        // Reverter.sol: tests/presets/cheatcode/Reverter.sol
        let reverter_addr = B160::from_str("0xaAbeB5BA46709f61CFd0090334C6E71513ED7BCf").unwrap();
        let reverter_code = load_bytecode("tests/presets/cheatcode/Reverter.bytecode");

        // Emitter.sol: tests/presets/cheatcode/Emitter.sol
        let emitter_addr = B160::from_str("0xC6829a4b1a9bCCc842387F223dd2bC5FA50fd9eD").unwrap();
        let emitter_code = load_bytecode("tests/presets/cheatcode/Emitter.bytecode");

        // Caller.sol: tests/presets/cheatcode/Caller.sol
        let caller_addr = B160::from_str("0xBE8d2A52f21dce4b17Ec809BCE76cb403BbFbaCE").unwrap();
        let caller_code = load_bytecode("tests/presets/cheatcode/Caller.bytecode");

        // Cheatcode.t.sol: tests/presets/cheatcode/Cheatcode.t.sol
        let cheat_test_addr = generate_random_address(&mut state);
        let cheat_test_code = load_bytecode("tests/presets/cheatcode/Cheatcode.t.bytecode");

        let path = Path::new("work_dir");
        if !path.exists() {
            std::fs::create_dir(path).unwrap();
        }
        let mut fuzz_host = FuzzHost::new(StdScheduler::new(), "work_dir".to_string());
        fuzz_host.add_middlewares(Rc::new(RefCell::new(Cheatcode::new())));
        fuzz_host.set_code(
            CHEATCODE_ADDRESS,
            Bytecode::new_raw(Bytes::from(vec![0xfd, 0x00])),
            &mut state,
        );

        let mut evm_executor: EVMExecutor<EVMState, ConciseEVMInput, StdScheduler<EVMFuzzState>> =
            EVMExecutor::new(fuzz_host, generate_random_address(&mut state));

        let mut deploy_state = FuzzState::new(0);
        // Deploy Reverter
        let _ = evm_executor
            .deploy(reverter_code, None, reverter_addr, &mut deploy_state)
            .unwrap();
        // Deploy Emitter
        let _ = evm_executor
            .deploy(emitter_code, None, emitter_addr, &mut deploy_state)
            .unwrap();
        // Deploy Caller
        let _ = evm_executor
            .deploy(caller_code, None, caller_addr, &mut deploy_state)
            .unwrap();
        // Deploy CheatcodeTest
        let _ = evm_executor
            .deploy(cheat_test_code, None, cheat_test_addr, &mut deploy_state)
            .unwrap();

        macro_rules! assert_fn_success {
            ($fn_selector:expr) => {
                let function_hash = hex::decode($fn_selector).unwrap();
                let mut input = EVMInput {
                    caller: generate_random_address(&mut state),
                    contract: cheat_test_addr,
                    data: None,
                    sstate: StagedVMState::new_uninitialized(),
                    sstate_idx: 0,
                    txn_value: Some(EVMU256::ZERO),
                    step: false,
                    env: Default::default(),
                    access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                    liquidation_percent: 0,
                    direct_data: Bytes::from(
                        [
                            function_hash.clone(),
                            hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                        ]
                        .concat(),
                    ),
                    input_type: EVMInputTy::ABI,
                    randomness: vec![],
                    repeat: 1,
                };
                let mut state = FuzzState::new(0);
                // deposit some ETH to the test contract
                input.sstate.state.set_balance(cheat_test_addr, U256::from(1000));

                let res = evm_executor.execute(&input, &mut state);
                assert!(!res.reverted);
            };
        }

        // test()
        assert_fn_success!("f8a8fd6d");
        // testPrank()
        assert_fn_success!("7e550aac");
        // testExpectRevertBeforePrank()
        assert_fn_success!("c2bb38d3");
        // testExpectRevertAfterConsumePrank()
        assert_fn_success!("cc5c4741");
        // testExpectRevertPrankSenderOrigin()
        assert_fn_success!("177d2a31");
        // testStartStopPrank()
        assert_fn_success!("9c0046b9");
        // testExpectRevertAfterStopPrank()
        assert_fn_success!("3dee8e2a");
        // testExpectRevertWithoutReason()
        assert_fn_success!("6bd496f0");
        // testExpectRevertWithMessage()
        assert_fn_success!("0b324ebf");
        // testExpectRevertCustomError()
        assert_fn_success!("10fca384");
        // testExpectRevertNested()
        assert_fn_success!("cc017d5c");
        // testExpectEmitMultiple()
        assert_fn_success!("8795d87a");
        // testExpectEmitMultipleWithArgs()
        assert_fn_success!("65e9c19f");
        // testExpectedEmitMultipleNested()
        assert_fn_success!("d06f71e2");
        // testExpectEmitCanMatchWithoutExactOrder()
        assert_fn_success!("47feb1dd");
        // testExpectEmitCanMatchWithoutExactOrder2()
        assert_fn_success!("5e553090");
        // testExpectCallWithData()
        assert_fn_success!("268100f8");
        // testExpectCallWithValue()
        assert_fn_success!("77651c29");
        // testExpectMultipleCallsWithData()
        assert_fn_success!("b5a49624");
    }

    fn load_bytecode(path: &str) -> Bytecode {
        let hex_code = fs::read_to_string(path).expect("bytecode not found").trim().to_string();
        let bytecode = hex::decode(hex_code).unwrap();
        Bytecode::new_raw(Bytes::from(bytecode))
    }
}
