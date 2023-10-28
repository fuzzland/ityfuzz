use std::clone::Clone;
use std::fmt::Debug;

use alloy_sol_types::SolInterface;
use bytes::Bytes;
use foundry_cheatcodes::Vm::{self, VmCalls};
use libafl::prelude::Input;
use revm_interpreter::{Interpreter, InstructionResult};
use revm_primitives::{B160, SpecId, Env, U256, Bytecode};
use libafl::schedulers::Scheduler;
use libafl::state::{HasCorpus, State, HasMetadata, HasRand};
use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, Serialize, Default, Deserialize)]
pub struct Cheatcode;

impl<I, VS, S, SC> Middleware<VS, I, S, SC> for Cheatcode
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

        // handle cheatcode
        match VmCalls::abi_decode(&contract.input, false).expect("decode cheatcode failed") {
            VmCalls::warp(args) => warp(&mut host.env, args),
            VmCalls::roll(args) => roll(&mut host.env, args),
            VmCalls::fee(args) => fee(&mut host.env, args),
            VmCalls::difficulty(args) => difficulty(&mut host.env, args),
            VmCalls::prevrandao(args) => prevrandao(&mut host.env, args),
            VmCalls::chainId(args) => chain_id(&mut host.env, args),
            VmCalls::txGasPrice(args) => tx_gas_price(&mut host.env, args),
            VmCalls::coinbase(args) => coinbase(&mut host.env, args),
            VmCalls::load(args) => load(interp, &host.evmstate, args),
            VmCalls::store(args) => store(&mut host.evmstate, args),
            VmCalls::etch(args) => etch(host, state, args),
            VmCalls::deal(args) => deal(&mut host.evmstate, args),
            VmCalls::readCallers(_) => read_callers(),
            _ => {}
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::Cheatcode
    }
}

/// Sets `block.timestamp`.
fn warp(env: &mut Env, args: Vm::warpCall) {
    env.block.timestamp = args.newTimestamp;
}

/// Sets `block.height`.
fn roll(env: &mut Env, args: Vm::rollCall) {
    env.block.number = args.newHeight;
}

/// Sets `block.basefee`.
fn fee(env: &mut Env, args: Vm::feeCall) {
    env.block.basefee = args.newBasefee;
}

/// Sets `block.difficulty`.
/// Not available on EVM versions from Paris onwards. Use `prevrandao` instead.
fn difficulty(env: &mut Env, args: Vm::difficultyCall) {
    if env.cfg.spec_id >= SpecId::MERGE {
        return;
    }
    env.block.difficulty = args.newDifficulty;
}

/// Sets `block.prevrandao`.
/// Not available on EVM versions before Paris. Use `difficulty` instead.
fn prevrandao(env: &mut Env, args: Vm::prevrandaoCall) {
    if env.cfg.spec_id < SpecId::MERGE {
        return;
    }
    env.block.prevrandao = Some(args.newPrevrandao.0.into());
}

/// Sets `block.chainid`.
fn chain_id(env: &mut Env, args: Vm::chainIdCall) {
    if args.newChainId > U256::from(u64::MAX) {
        return;
    }
    env.cfg.chain_id = args.newChainId;
}

/// Sets `tx.gasprice`.
fn tx_gas_price(env: &mut Env, args: Vm::txGasPriceCall) {
    env.tx.gas_price = args.newGasPrice;
}

/// Sets `block.coinbase`.
fn coinbase(env: &mut Env, args: Vm::coinbaseCall) {
    env.block.coinbase = B160(args.newCoinbase.into());
}

/// Loads a storage slot from an address.
fn load(interp: &mut Interpreter, state: &EVMState, args: Vm::loadCall) {
    todo!()
}

/// Stores a value to an address' storage slot.
fn store(state: &mut EVMState, args: Vm::storeCall) {
    let Vm::storeCall { target, slot, value} = args;
    state.sstore(B160(target.into()), slot.into(), value.into());
}

/// Sets an address' code.
fn etch<VS, I, S, SC>(host: &mut FuzzHost<VS, I, S, SC>, state: &mut S, args: Vm::etchCall)
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
    let Vm::etchCall { target, newRuntimeBytecode } = args;
    let bytecode = Bytecode::new_raw(Bytes::from(newRuntimeBytecode));
    host.set_code(B160(target.into()), bytecode, state);
}

/// Sets an address' balance.
fn deal(state: &mut EVMState, args: Vm::dealCall) {
    let Vm::dealCall { account, newBalance } = args;
    state.set_balance(B160(account.into()), newBalance.into());
}

/// Reads the current `msg.sender` and `tx.origin` from state and reports if there is any active caller modification.
fn read_callers() {
    todo!()
}
