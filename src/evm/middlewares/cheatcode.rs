use std::clone::Clone;
use std::cmp::min;
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;

use alloy_sol_types::{SolInterface, SolValue};
use alloy_primitives::Address;
use bytes::Bytes;
use foundry_cheatcodes::Vm::{self, VmCalls, CallerMode};
use libafl::prelude::Input;
use revm_interpreter::Interpreter;
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

#[derive(Clone, Debug, Default)]
pub struct Cheatcode<I, VS, S, SC> {
    /// Prank information
    pub prank: Option<Prank>,
    /// Recorded storage reads and writes
    pub accesses: Option<RecordAccess>,
    /// Recorded logs
    pub recorded_logs: Option<Vec<Vm::Log>>,

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
}

/// Records storage slots reads and writes.
#[derive(Clone, Debug, Default)]
pub struct RecordAccess {
    /// Storage slots reads.
    pub reads: HashMap<Address, Vec<U256>>,
    /// Storage slots writes.
    pub writes: HashMap<Address, Vec<U256>>,
}

impl Prank {
    /// Create a new prank.
    pub fn new(
        old_caller: EVMAddress,
        old_origin: Option<EVMAddress>,
        new_caller: EVMAddress,
        new_origin: Option<EVMAddress>,
        single_call: bool,
    ) -> Prank {
        Prank {
            old_caller,
            old_origin,
            new_caller,
            new_origin,
            single_call,
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
            _phantom: PhantomData,
        }
    }

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
    fn expect_revert(&self) -> Option<Vec<u8>> {
        None
    }

    unsafe fn pop_return_location(&self, interp: &mut Interpreter, opcode: u8) -> (usize, usize) {
        if opcode == 0xf1 || opcode == 0xf2 {
            let _ = interp.stack.pop_unsafe();
        }
        let (_, _, _, _) = interp.stack.pop4_unsafe();
        let (out_offset, out_len) = interp.stack.pop2_unsafe();

        (out_offset.as_limbs()[0] as usize, out_len.as_limbs()[0] as usize)
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
        // check if we are calling cheatcode
        let opcode = interp.current_opcode();
        if opcode != 0xf1 && opcode != 0xf2 && opcode != 0xf4 && opcode != 0xfa {
            return;
        }
        let contract = interp.contract();
        if contract.address != CHEATCODE_ADDRESS {
            return;
        }

        // handle a vm call
        let input = contract.input.clone();
        let caller = contract.caller.clone();
        let tx_origin = host.env.tx.caller.clone();
        interp.return_data_buffer = Bytes::new();
        let (out_offset, out_len) = self.pop_return_location(interp, opcode);

        let res = match VmCalls::abi_decode(&input, false).expect("decode cheatcode failed") {
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
            VmCalls::readCallers(_) => self.read_callers(&caller, &tx_origin),
            VmCalls::record(_) => self.record(),
            VmCalls::accesses(args) => self.accesses(args),
            VmCalls::recordLogs(_) => self.record_logs(),
            VmCalls::getRecordedLogs(_) => self.get_recorded_logs(),
            VmCalls::prank_0(args) => self.prank0(&caller, args),
            VmCalls::prank_1(args) => self.prank1(&caller, &tx_origin, args),
            VmCalls::startPrank_0(args) => self.start_prank0(&caller, args),
            VmCalls::startPrank_1(args) => self.start_prank1(&caller, &tx_origin, args),
            VmCalls::stopPrank(_) => self.stop_prank(),
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
        interp.instruction_pointer = interp.instruction_pointer.offset(1);
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::Cheatcode
    }
}
