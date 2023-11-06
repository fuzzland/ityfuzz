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
use libafl::{
    prelude::Input,
    schedulers::Scheduler,
    state::{HasCorpus, HasMetadata, HasRand, State},
};
use revm_interpreter::{analysis::to_analysed, opcode, BytecodeLocked, InstructionResult, Interpreter};
use revm_primitives::{Bytecode, Env, SpecId, B160, U256};
use tracing::{debug, error};

use super::middleware::{Middleware, MiddlewareType};
use crate::{
    evm::{
        host::FuzzHost,
        input::{ConciseEVMInput, EVMInputT},
        types::EVMAddress,
        vm::EVMState,
    },
    generic_vm::vm_state::VMStateT,
    input::VMInputT,
    state::{HasCaller, HasItyState},
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
pub struct Cheatcode<I, VS, S, SC> {
    /// Recorded storage reads and writes
    accesses: Option<RecordAccess>,
    /// Recorded logs
    recorded_logs: Option<Vec<Vm::Log>>,

    _phantom: PhantomData<(I, VS, S, SC)>,
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
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<VS, I, S, SC>, _state: &mut S) {
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
            accesses: None,
            recorded_logs: None,
            _phantom: PhantomData,
        }
    }

    /// Call cheatcode address
    pub fn cheat_call(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<VS, I, S, SC>) {
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
            _ => None,
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
    pub fn real_call(&self, interp: &Interpreter, expected_calls: &mut ExpectedCallTracker) {
        // Handle expected calls
        let target = Address::from(interp.contract().address.0);
        // Grab the different calldatas expected.
        if let Some(expected_calls_for_target) = expected_calls.get_mut(&target) {
            debug!("[cheatcode] real_call");
            let contract = interp.contract();
            let (input, value) = (&contract.input, contract.value);
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
        if expected_emits.is_empty() && self.record_logs().is_none() {
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
    fn etch(&self, host: &mut FuzzHost<VS, I, S, SC>, args: Vm::etchCall) -> Option<Vec<u8>> {
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
    fn prank0(
        &mut self,
        host: &mut FuzzHost<VS, I, S, SC>,
        old_caller: &EVMAddress,
        args: Vm::prank_0Call,
    ) -> Option<Vec<u8>> {
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
        host: &mut FuzzHost<VS, I, S, SC>,
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
        host: &mut FuzzHost<VS, I, S, SC>,
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
        host: &mut FuzzHost<VS, I, S, SC>,
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
    fn stop_prank(&mut self, host: &mut FuzzHost<VS, I, S, SC>) -> Option<Vec<u8>> {
        let _ = host.prank.take();
        None
    }

    /// Expects an error on next call with any revert data.
    #[inline]
    fn expect_revert0(&mut self, host: &mut FuzzHost<VS, I, S, SC>) -> Option<Vec<u8>> {
        host.expected_revert = Some(ExpectedRevert {
            reason: None,
            depth: host.call_depth,
        });
        None
    }

    /// Expects an error on next call that starts with the revert data.
    #[inline]
    fn expect_revert1(&mut self, host: &mut FuzzHost<VS, I, S, SC>, args: Vm::expectRevert_1Call) -> Option<Vec<u8>> {
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
    fn expect_revert2(&mut self, host: &mut FuzzHost<VS, I, S, SC>, args: Vm::expectRevert_2Call) -> Option<Vec<u8>> {
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
    fn expect_emit0(&mut self, host: &mut FuzzHost<VS, I, S, SC>, args: Vm::expectEmit_0Call) -> Option<Vec<u8>> {
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
    fn expect_emit1(&mut self, host: &mut FuzzHost<VS, I, S, SC>, args: Vm::expectEmit_1Call) -> Option<Vec<u8>> {
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
    fn expect_emit2(&mut self, host: &mut FuzzHost<VS, I, S, SC>) -> Option<Vec<u8>> {
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
    fn expect_emit3(&mut self, host: &mut FuzzHost<VS, I, S, SC>, args: Vm::expectEmit_3Call) -> Option<Vec<u8>> {
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
    use std::{cell::RefCell, path::Path, rc::Rc};

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

    /*
    contract VMTest is Test {
        function test() external {
            string memory s = string(abi.encodePacked(block.timestamp));
            address randomAddr = makeAddr(s);
            uint256 random = uint160(randomAddr);

            assertNotEq(block.timestamp, random);
            vm.warp(random);
            assertEq(block.timestamp, random);

            assertNotEq(block.number, random);
            vm.roll(random);
            assertEq(block.number, random);

            assertNotEq(block.basefee, random);
            vm.fee(random);
            assertEq(block.basefee, random);

            assertNotEq(block.prevrandao, random);
            vm.prevrandao(bytes32(random));
            assertEq(block.prevrandao, random);

            assertNotEq(block.chainid, 100);
            vm.chainId(100);
            assertEq(block.chainid, 100);

            assertNotEq(tx.gasprice, random);
            vm.txGasPrice(random);
            assertEq(tx.gasprice, random);

            assertNotEq(block.coinbase, randomAddr);
            vm.coinbase(randomAddr);
            assertEq(block.coinbase, randomAddr);
        }
    }
    */
    const BYTECODE: &str = "608060405260078054600160ff199182168117909255600b8054909116909117905534801561002d57600080fd5b506125978061003d6000396000f3fe608060405234801561001057600080fd5b50600436106100b45760003560e01c8063916a17c611610071578063916a17c614610126578063b5508aa91461012e578063ba414fa614610136578063e20c9f711461014e578063f8a8fd6d14610156578063fa7626d41461016057600080fd5b80631ed7831c146100b95780632ade3880146100d75780633e5e3c23146100ec5780633f7286f4146100f457806366d9a9a0146100fc57806385226c8114610111575b600080fd5b6100c161016d565b6040516100ce9190611f96565b60405180910390f35b6100df6101cf565b6040516100ce9190612033565b6100c1610311565b6100c1610371565b6101046103d1565b6040516100ce91906120f3565b6101196104b7565b6040516100ce91906121a6565b610104610587565b61011961066d565b61013e61073d565b60405190151581526020016100ce565b6100c161085e565b61015e6108be565b005b60075461013e9060ff1681565b606060148054806020026020016040519081016040528092919081815260200182805480156101c557602002820191906000526020600020905b81546001600160a01b031681526001909101906020018083116101a7575b5050505050905090565b6060601b805480602002602001604051908101604052809291908181526020016000905b8282101561030857600084815260208082206040805180820182526002870290920180546001600160a01b03168352600181018054835181870281018701909452808452939591948681019491929084015b828210156102f157838290600052602060002001805461026490612208565b80601f016020809104026020016040519081016040528092919081815260200182805461029090612208565b80156102dd5780601f106102b2576101008083540402835291602001916102dd565b820191906000526020600020905b8154815290600101906020018083116102c057829003601f168201915b505050505081526020019060010190610245565b5050505081525050815260200190600101906101f3565b50505050905090565b606060168054806020026020016040519081016040528092919081815260200182805480156101c5576020028201919060005260206000209081546001600160a01b031681526001909101906020018083116101a7575050505050905090565b606060158054806020026020016040519081016040528092919081815260200182805480156101c5576020028201919060005260206000209081546001600160a01b031681526001909101906020018083116101a7575050505050905090565b60606019805480602002602001604051908101604052809291908181526020016000905b828210156103085760008481526020908190206040805180820182526002860290920180546001600160a01b0316835260018101805483518187028101870190945280845293949193858301939283018282801561049f57602002820191906000526020600020906000905b82829054906101000a900460e01b6001600160e01b031916815260200190600401906020826003010492830192600103820291508084116104615790505b505050505081525050815260200190600101906103f5565b60606018805480602002602001604051908101604052809291908181526020016000905b828210156103085783829060005260206000200180546104fa90612208565b80601f016020809104026020016040519081016040528092919081815260200182805461052690612208565b80156105735780601f1061054857610100808354040283529160200191610573565b820191906000526020600020905b81548152906001019060200180831161055657829003601f168201915b5050505050815260200190600101906104db565b6060601a805480602002602001604051908101604052809291908181526020016000905b828210156103085760008481526020908190206040805180820182526002860290920180546001600160a01b0316835260018101805483518187028101870190945280845293949193858301939283018282801561065557602002820191906000526020600020906000905b82829054906101000a900460e01b6001600160e01b031916815260200190600401906020826003010492830192600103820291508084116106175790505b505050505081525050815260200190600101906105ab565b60606017805480602002602001604051908101604052809291908181526020016000905b828210156103085783829060005260206000200180546106b090612208565b80601f01602080910402602001604051908101604052809291908181526020018280546106dc90612208565b80156107295780601f106106fe57610100808354040283529160200191610729565b820191906000526020600020905b81548152906001019060200180831161070c57829003601f168201915b505050505081526020019060010190610691565b600754600090610100900460ff161561075f5750600754610100900460ff1690565b60006000805160206125228339815191523b156108595760408051600080516020612522833981519152602082018190526519985a5b195960d21b828401528251808303840181526060830190935260009290916107e1917f667f9d70ca411d70ead50d8d5c22070dafc36ad75f3dcf5e7237b22ade9aecc491608001612242565b60408051601f19818403018152908290526107fb91612273565b6000604051808303816000865af19150503d8060008114610838576040519150601f19603f3d011682016040523d82523d6000602084013e61083d565b606091505b5091505080806020019051810190610855919061228f565b9150505b919050565b606060138054806020026020016040519081016040528092919081815260200182805480156101c5576020028201919060005260206000209081546001600160a01b031681526001909101906020018083116101a7575050505050905090565b6040805142602082015260009101604051602081830303815290604052905060006108e882611846565b60408051808201909152600681526503078363038360d41b60208201529091506001600160a01b03821690819060009081808033326109274289611858565b6040516372eb5f8160e11b8152600481018a90526000805160206125228339815191529063e5d6bf0290602401600060405180830381600087803b15801561096e57600080fd5b505af1158015610982573d6000803e3d6000fd5b50505050610990428a611939565b61099a438a611858565b6040516301f7b4f360e41b8152600481018a905260008051602061252283398151915290631f7b4f3090602401600060405180830381600087803b1580156109e157600080fd5b505af11580156109f5573d6000803e3d6000fd5b50505050610a03438a611939565b610a0d488a611858565b60405163039b37ab60e41b8152600481018a9052600080516020612522833981519152906339b37ab090602401600060405180830381600087803b158015610a5457600080fd5b505af1158015610a68573d6000803e3d6000fd5b50505050610a76488a611939565b610a80448a611858565b604051633b92554960e01b81526004810189905260008051602061252283398151915290633b92554990602401600060405180830381600087803b158015610ac757600080fd5b505af1158015610adb573d6000803e3d6000fd5b50505050610ae9448a611939565b610af4466064611858565b604051632024eee960e11b81526064600482015260008051602061252283398151915290634049ddd290602401600060405180830381600087803b158015610b3b57600080fd5b505af1158015610b4f573d6000803e3d6000fd5b50505050610b5e466064611939565b610b683a8a611858565b6040516348f50c0f60e01b8152600481018a9052600080516020612522833981519152906348f50c0f90602401600060405180830381600087803b158015610baf57600080fd5b505af1158015610bc3573d6000803e3d6000fd5b50505050610bd13a8a611939565b610bdb418b611998565b6040516001622df0eb60e21b031981526001600160a01b038b1660048201526000805160206125228339815191529063ff483c5490602401600060405180830381600087803b158015610c2d57600080fd5b505af1158015610c41573d6000803e3d6000fd5b50505050610c4f418b611a7a565b604051630667f9d760e41b81526001600160a01b038b16600482015260248101889052610cd79089906000805160206125228339815191529063667f9d7090604401602060405180830381865afa158015610cae573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610cd291906122b8565b611aee565b6040516370ca10bb60e01b81526001600160a01b038b1660048201526024810188905260448101899052600080516020612522833981519152906370ca10bb90606401600060405180830381600087803b158015610d3457600080fd5b505af1158015610d48573d6000803e3d6000fd5b5050604051630667f9d760e41b81526001600160a01b038d166004820152602481018a9052610dd492508a91506000805160206125228339815191529063667f9d7090604401602060405180830381865afa158015610dab573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610dcf91906122b8565b611bbe565b610de960008b6001600160a01b031631611939565b60405163c88a5e6d60e01b81526001600160a01b038b166004820152606460248201526000805160206125228339815191529063c88a5e6d90604401600060405180830381600087803b158015610e3f57600080fd5b505af1158015610e53573d6000803e3d6000fd5b50505050610e6c60648b6001600160a01b031631611939565b610e8160008b6001600160a01b03163b611939565b604051635a6b63c160e11b81526000805160206125228339815191529063b4d6c78290610eb4908d908a906004016122d1565b600060405180830381600087803b158015610ece57600080fd5b505af1158015610ee2573d6000803e3d6000fd5b50505050610f15868b6001600160a01b0316803b806020016040519081016040528181526000908060200190933c611c20565b60008051602061254283398151915260001c6001600160a01b0316634ad0bac96040518163ffffffff1660e01b81526004016060604051808303816000875af1158015610f66573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610f8a9190612314565b91965094509250610fad856004811115610fa657610fa661235d565b6000611939565b610fb78483611a7a565b610fc18382611a7a565b60405163ca669fa760e01b81526001600160a01b038b1660048201526000805160206125228339815191529063ca669fa790602401600060405180830381600087803b15801561101057600080fd5b505af1158015611024573d6000803e3d6000fd5b5050505060008051602061254283398151915260001c6001600160a01b0316634ad0bac96040518163ffffffff1660e01b81526004016060604051808303816000875af1158015611079573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061109d9190612314565b919650945092506110c08560048111156110b9576110b961235d565b6003611939565b6110ca848b611a7a565b6110d48382611a7a565b60408051600481526024810182526020810180516001600160e01b0316633ccfd60b60e01b17905290516000916001600160a01b038d16916111169190612273565b6000604051808303816000865af19150503d8060008114611153576040519150601f19603f3d011682016040523d82523d6000602084013e611158565b606091505b5050905060008051602061254283398151915260001c6001600160a01b0316634ad0bac96040518163ffffffff1660e01b81526004016060604051808303816000875af11580156111ad573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906111d19190612314565b919750955093506111ed866004811115610fa657610fa661235d565b6111f78584611a7a565b6112018483611a7a565b6040516323f2866760e11b81526001600160a01b038c16600482018190526024820152600080516020612522833981519152906347e50cce90604401600060405180830381600087803b15801561125757600080fd5b505af115801561126b573d6000803e3d6000fd5b5050505060008051602061254283398151915260001c6001600160a01b0316634ad0bac96040518163ffffffff1660e01b81526004016060604051808303816000875af11580156112c0573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906112e49190612314565b919750955093506113008660048111156110b9576110b961235d565b61130a858c611a7a565b611314848c611a7a565b60408051600481526024810182526020810180516001600160e01b0316633ccfd60b60e01b17905290516001600160a01b038d169161135291612273565b6000604051808303816000865af19150503d806000811461138f576040519150601f19603f3d011682016040523d82523d6000602084013e611394565b606091505b50506040516303223eab60e11b81526001600160a01b038d166004820152909150600080516020612522833981519152906306447d5690602401600060405180830381600087803b1580156113e857600080fd5b505af11580156113fc573d6000803e3d6000fd5b505060408051600481526024810182526020810180516001600160e01b0316633ccfd60b60e01b17905290516001600160a01b038f16935061143e9250612273565b6000604051808303816000865af19150503d806000811461147b576040519150601f19603f3d011682016040523d82523d6000602084013e611480565b606091505b50508091505060008051602061254283398151915260001c6001600160a01b0316634ad0bac96040518163ffffffff1660e01b81526004016060604051808303816000875af11580156114d7573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906114fb9190612314565b9197509550935061151e8660048111156115175761151761235d565b6004611939565b611528858c611a7a565b6115328483611a7a565b60008051602061254283398151915260001c6001600160a01b03166390c5013b6040518163ffffffff1660e01b8152600401600060405180830381600087803b15801561157e57600080fd5b505af1158015611592573d6000803e3d6000fd5b5050505060008051602061254283398151915260001c6001600160a01b0316634ad0bac96040518163ffffffff1660e01b81526004016060604051808303816000875af11580156115e7573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061160b9190612314565b91975095509350611627866004811115610fa657610fa661235d565b6116318584611a7a565b61163b8483611a7a565b6040516308b6ac0f60e31b81526001600160a01b038c16600482018190526024820152600080516020612522833981519152906345b5607890604401600060405180830381600087803b15801561169157600080fd5b505af11580156116a5573d6000803e3d6000fd5b505060408051600481526024810182526020810180516001600160e01b0316633ccfd60b60e01b17905290516001600160a01b038f1693506116e79250612273565b6000604051808303816000865af19150503d8060008114611724576040519150601f19603f3d011682016040523d82523d6000602084013e611729565b606091505b50508091505060008051602061254283398151915260001c6001600160a01b0316634ad0bac96040518163ffffffff1660e01b81526004016060604051808303816000875af1158015611780573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906117a49190612314565b919750955093506117c08660048111156115175761151761235d565b6117ca858c611a7a565b6117d4848c611a7a565b60008051602061254283398151915260001c6001600160a01b03166390c5013b6040518163ffffffff1660e01b8152600401600060405180830381600087803b15801561182057600080fd5b505af1158015611834573d6000803e3d6000fd5b50505050505050505050505050505050565b600061185182611c2a565b5092915050565b808203611935576000805160206125028339815191526040516118b79060208082526022908201527f4572726f723a206120213d2062206e6f7420736174697366696564205b75696e604082015261745d60f01b606082015260800190565b60405180910390a17fb2de2fbe801a0df6c0cbddfd448ba3c41d48a040ca35c56c8196ef0fcae721a8826040516118ee9190612373565b60405180910390a17fb2de2fbe801a0df6c0cbddfd448ba3c41d48a040ca35c56c8196ef0fcae721a88160405161192591906123ab565b60405180910390a1611935611d34565b5050565b808214611935576000805160206125028339815191526040516118b79060208082526022908201527f4572726f723a2061203d3d2062206e6f7420736174697366696564205b75696e604082015261745d60f01b606082015260800190565b806001600160a01b0316826001600160a01b03160361193557600080516020612502833981519152604051611a0c9060208082526025908201527f4572726f723a206120213d2062206e6f7420736174697366696564205b616464604082015264726573735d60d81b606082015260800190565b60405180910390a17f9c4e8541ca8f0dc1c413f9108f66d82d3cecb1bddbce437a61caa3175c4cc96f82604051611a4391906123d5565b60405180910390a17f9c4e8541ca8f0dc1c413f9108f66d82d3cecb1bddbce437a61caa3175c4cc96f816040516119259190612419565b806001600160a01b0316826001600160a01b03161461193557600080516020612502833981519152604051611a0c9060208082526025908201527f4572726f723a2061203d3d2062206e6f7420736174697366696564205b616464604082015264726573735d60d81b606082015260800190565b80820361193557600080516020612502833981519152604051611b509060208082526025908201527f4572726f723a206120213d2062206e6f7420736174697366696564205b627974604082015264657333325d60d81b606082015260800190565b60405180910390a17fafb795c9c61e4fe7468c386f925d7a5429ecad9c0495ddb8d38d690614d32f9982604051611b879190612373565b60405180910390a17fafb795c9c61e4fe7468c386f925d7a5429ecad9c0495ddb8d38d690614d32f998160405161192591906123ab565b80821461193557600080516020612502833981519152604051611b509060208082526025908201527f4572726f723a2061203d3d2062206e6f7420736174697366696564205b627974604082015264657333325d60d81b606082015260800190565b6119358282611e34565b60008082604051602001611c3e9190612273565b60408051808303601f190181529082905280516020909101206001625e79b760e01b031982526004820181905291506000805160206125228339815191529063ffa1864990602401602060405180830381865afa158015611ca3573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611cc79190612443565b6040516318caf8e360e31b81529092506000805160206125228339815191529063c657c71890611cfd90859087906004016122d1565b600060405180830381600087803b158015611d1757600080fd5b505af1158015611d2b573d6000803e3d6000fd5b50505050915091565b6000805160206125228339815191523b15611e235760408051600080516020612522833981519152602082018190526519985a5b195960d21b9282019290925260016060820152600091907f70ca10bbd0dbfd9020a9f4b13402c16cb120705e0d1c0aeab10fa353ae586fc49060800160408051601f1981840301815290829052611dc29291602001612242565b60408051601f1981840301815290829052611ddc91612273565b6000604051808303816000865af19150503d8060008114611e19576040519150601f19603f3d011682016040523d82523d6000602084013e611e1e565b606091505b505050505b6007805461ff001916610100179055565b611e3e8282611f09565b61193557600080516020612502833981519152604051611e9b9060208082526023908201527f4572726f723a2061203d3d2062206e6f7420736174697366696564205b62797460408201526265735d60e81b606082015260800190565b60405180910390a17fd26e16cad4548705e4c9e2d94f98ee91c289085ee425594fd5635fa2964ccf1882604051611ed2919061245e565b60405180910390a17fd26e16cad4548705e4c9e2d94f98ee91c289085ee425594fd5635fa2964ccf1881604051611925919061249a565b805182516001919003611f8c5760005b8351811015611f8657828181518110611f3457611f346124c4565b602001015160f81c60f81b6001600160f81b031916848281518110611f5b57611f5b6124c4565b01602001516001600160f81b03191614611f7457600091505b80611f7e816124da565b915050611f19565b50611f90565b5060005b92915050565b6020808252825182820181905260009190848201906040850190845b81811015611fd75783516001600160a01b031683529284019291840191600101611fb2565b50909695505050505050565b60005b83811015611ffe578181015183820152602001611fe6565b50506000910152565b6000815180845261201f816020860160208601611fe3565b601f01601f19169290920160200192915050565b602080825282518282018190526000919060409081850190600581811b8701840188860187805b858110156120e357603f198b8503018752825180516001600160a01b031685528901518985018990528051898601819052908a0190606081881b870181019190870190855b818110156120cd57605f198985030183526120bb848651612007565b948e01949350918d019160010161209f565b505050978a01979450509188019160010161205a565b50919a9950505050505050505050565b60006020808301818452808551808352604092508286019150828160051b8701018488016000805b8481101561219757898403603f19018652825180516001600160a01b03168552880151888501889052805188860181905290890190839060608701905b808310156121825783516001600160e01b0319168252928b019260019290920191908b0190612158565b50978a0197955050509187019160010161211b565b50919998505050505050505050565b6000602080830181845280855180835260408601915060408160051b870101925083870160005b828110156121fb57603f198886030184526121e9858351612007565b945092850192908501906001016121cd565b5092979650505050505050565b600181811c9082168061221c57607f821691505b60208210810361223c57634e487b7160e01b600052602260045260246000fd5b50919050565b6001600160e01b0319831681528151600090612265816004850160208701611fe3565b919091016004019392505050565b60008251612285818460208701611fe3565b9190910192915050565b6000602082840312156122a157600080fd5b815180151581146122b157600080fd5b9392505050565b6000602082840312156122ca57600080fd5b5051919050565b6001600160a01b03831681526040602082018190526000906122f590830184612007565b949350505050565b80516001600160a01b038116811461085957600080fd5b60008060006060848603121561232957600080fd5b83516005811061233857600080fd5b9250612346602085016122fd565b9150612354604085016122fd565b90509250925092565b634e487b7160e01b600052602160045260246000fd5b60408152600061239d60408301600a8152690808080808081319599d60b21b602082015260400190565b905082602083015292915050565b60408152600061239d60408301600a8152690808080808149a59da1d60b21b602082015260400190565b6040815260006123ff60408301600a8152690808080808081319599d60b21b602082015260400190565b6001600160a01b0393909316602092909201919091525090565b6040815260006123ff60408301600a8152690808080808149a59da1d60b21b602082015260400190565b60006020828403121561245557600080fd5b6122b1826122fd565b60408152600061248860408301600a8152690808080808081319599d60b21b602082015260400190565b82810360208401526122f58185612007565b60408152600061248860408301600a8152690808080808149a59da1d60b21b602082015260400190565b634e487b7160e01b600052603260045260246000fd5b6000600182016124fa57634e487b7160e01b600052601160045260246000fd5b506001019056fe41304facd9323d75b11bcdd609cb38effffdb05710f7caf0e9b16c6d9d709f500000000000000000000000007109709ecfa91a80626ff3989d68f67f5b1dd12d885cb69240a935d632d79c317109709ecfa91a80626ff3989d68f67f5b1dd12da2646970667358221220dd70c14aaddaa11046896562c4e4bb94f73fd6a8210664074881d1c59835e03d64736f6c63430008150033";

    #[test]
    fn test_foundry_contract() {
        let mut state: EVMFuzzState = FuzzState::new(0);
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

        let mut evm_executor: EVMExecutor<
            EVMInput,
            EVMFuzzState,
            EVMState,
            ConciseEVMInput,
            StdScheduler<EVMFuzzState>,
        > = EVMExecutor::new(fuzz_host, generate_random_address(&mut state));

        let bytecode = hex::decode(BYTECODE).unwrap();
        let contract_addr = evm_executor
            .deploy(
                Bytecode::new_raw(Bytes::from(bytecode)),
                None,
                generate_random_address(&mut state),
                &mut FuzzState::new(0),
            )
            .unwrap();
        debug!("deployed to address: {:?}", contract_addr);

        let code_addrs = evm_executor.host.code.keys().cloned().collect::<Vec<_>>();
        debug!("code_addrs: {:?}", code_addrs);

        // test()
        let function_hash = hex::decode("f8a8fd6d").unwrap();
        let input = EVMInput {
            caller: generate_random_address(&mut state),
            contract: contract_addr,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            #[cfg(feature = "flashloan_v2")]
            liquidation_percent: 0,
            direct_data: Bytes::from(
                [
                    function_hash.clone(),
                    hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                ]
                .concat(),
            ),
            #[cfg(feature = "flashloan_v2")]
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
        };
        let mut state = FuzzState::new(0);
        let res = evm_executor.execute(&input, &mut state);
        assert!(!res.reverted);
    }
}
