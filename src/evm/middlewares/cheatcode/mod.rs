use std::{
    clone::Clone,
    cmp::min,
    collections::{HashMap, VecDeque},
    fmt::Debug,
    marker::PhantomData,
    ops::{BitAnd, Not},
};

use alloy_primitives::{Address, Bytes as AlloyBytes, Log as RawLog, B256};
use alloy_sol_types::SolInterface;
use bytes::Bytes;
use foundry_cheatcodes::Vm::{self, VmCalls};
use libafl::schedulers::Scheduler;
use revm_interpreter::{opcode, InstructionResult, Interpreter};
use revm_primitives::{B160, U256};
use tracing::{debug, error, warn};

use super::middleware::{Middleware, MiddlewareType};
use crate::evm::{host::FuzzHost, types::EVMFuzzState};

mod assert;
mod common;
mod env;
mod expect;
mod fork;
mod string;

pub use common::{Prank, RecordAccess};
pub use expect::{ExpectedCallData, ExpectedCallTracker, ExpectedCallType, ExpectedEmit, ExpectedRevert};

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

#[derive(Clone, Debug, Default)]
pub struct Cheatcode<SC> {
    /// Recorded storage reads and writes
    accesses: Option<RecordAccess>,
    /// Recorded logs
    recorded_logs: Option<Vec<Vm::Log>>,
    /// Etherscan API key
    etherscan_api_key: Vec<String>,
    /// Address labels
    labels: HashMap<Address, String>,

    _phantom: PhantomData<SC>,
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
    SC: Scheduler<State = EVMFuzzState> + Clone + Debug + 'static,
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

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl<SC> Cheatcode<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    pub fn new(etherscan_api_key: &str) -> Self {
        Self {
            accesses: None,
            recorded_logs: None,
            etherscan_api_key: etherscan_api_key.split(',').map(|s| s.to_string()).collect(),
            labels: HashMap::new(),
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
            // common
            VmCalls::addr(args) => self.addr(args),
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
            VmCalls::label(args) => self.label(args),
            VmCalls::getLabel(args) => self.get_label(args),

            // fork
            VmCalls::createSelectFork_0(args) => self.create_select_fork0(host, args),
            VmCalls::createSelectFork_1(args) => self.create_select_fork1(host, args),
            VmCalls::createSelectFork_2(args) => self.create_select_fork2(host, args),

            // expect
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

            // assert
            VmCalls::assertTrue_0(args) => self.assert_true0(args, &mut host.assert_msg),
            VmCalls::assertTrue_1(args) => self.assert_true1(args, &mut host.assert_msg),
            VmCalls::assertFalse_0(args) => self.assert_false0(args, &mut host.assert_msg),
            VmCalls::assertFalse_1(args) => self.assert_false1(args, &mut host.assert_msg),
            VmCalls::assertEq_0(args) => self.assert_eq0(args, &mut host.assert_msg),
            VmCalls::assertEq_1(args) => self.assert_eq1(args, &mut host.assert_msg),
            VmCalls::assertEq_2(args) => self.assert_eq2(args, &mut host.assert_msg),
            VmCalls::assertEq_3(args) => self.assert_eq3(args, &mut host.assert_msg),
            VmCalls::assertEq_4(args) => self.assert_eq4(args, &mut host.assert_msg),
            VmCalls::assertEq_5(args) => self.assert_eq5(args, &mut host.assert_msg),
            VmCalls::assertEq_6(args) => self.assert_eq6(args, &mut host.assert_msg),
            VmCalls::assertEq_7(args) => self.assert_eq7(args, &mut host.assert_msg),
            VmCalls::assertEq_8(args) => self.assert_eq8(args, &mut host.assert_msg),
            VmCalls::assertEq_9(args) => self.assert_eq9(args, &mut host.assert_msg),
            VmCalls::assertEq_10(args) => self.assert_eq10(args, &mut host.assert_msg),
            VmCalls::assertEq_11(args) => self.assert_eq11(args, &mut host.assert_msg),
            VmCalls::assertEq_12(args) => self.assert_eq12(args, &mut host.assert_msg),
            VmCalls::assertEq_13(args) => self.assert_eq13(args, &mut host.assert_msg),
            VmCalls::assertEq_14(args) => self.assert_eq14(args, &mut host.assert_msg),
            VmCalls::assertEq_15(args) => self.assert_eq15(args, &mut host.assert_msg),
            VmCalls::assertEq_16(args) => self.assert_eq16(args, &mut host.assert_msg),
            VmCalls::assertEq_17(args) => self.assert_eq17(args, &mut host.assert_msg),
            VmCalls::assertEq_18(args) => self.assert_eq18(args, &mut host.assert_msg),
            VmCalls::assertEq_19(args) => self.assert_eq19(args, &mut host.assert_msg),
            VmCalls::assertEq_20(args) => self.assert_eq20(args, &mut host.assert_msg),
            VmCalls::assertEq_21(args) => self.assert_eq21(args, &mut host.assert_msg),
            VmCalls::assertEq_22(args) => self.assert_eq22(args, &mut host.assert_msg),
            VmCalls::assertEq_23(args) => self.assert_eq23(args, &mut host.assert_msg),
            VmCalls::assertEq_24(args) => self.assert_eq24(args, &mut host.assert_msg),
            VmCalls::assertEq_25(args) => self.assert_eq25(args, &mut host.assert_msg),
            VmCalls::assertEq_26(args) => self.assert_eq26(args, &mut host.assert_msg),
            VmCalls::assertEq_27(args) => self.assert_eq27(args, &mut host.assert_msg),
            VmCalls::assertEqDecimal_0(args) => self.assert_eq_decimal0(args, &mut host.assert_msg),
            VmCalls::assertEqDecimal_1(args) => self.assert_eq_decimal1(args, &mut host.assert_msg),
            VmCalls::assertEqDecimal_2(args) => self.assert_eq_decimal2(args, &mut host.assert_msg),
            VmCalls::assertEqDecimal_3(args) => self.assert_eq_decimal3(args, &mut host.assert_msg),
            VmCalls::assertNotEq_0(args) => self.assert_not_eq0(args, &mut host.assert_msg),
            VmCalls::assertNotEq_1(args) => self.assert_not_eq1(args, &mut host.assert_msg),
            VmCalls::assertNotEq_2(args) => self.assert_not_eq2(args, &mut host.assert_msg),
            VmCalls::assertNotEq_3(args) => self.assert_not_eq3(args, &mut host.assert_msg),
            VmCalls::assertNotEq_4(args) => self.assert_not_eq4(args, &mut host.assert_msg),
            VmCalls::assertNotEq_5(args) => self.assert_not_eq5(args, &mut host.assert_msg),
            VmCalls::assertNotEq_6(args) => self.assert_not_eq6(args, &mut host.assert_msg),
            VmCalls::assertNotEq_7(args) => self.assert_not_eq7(args, &mut host.assert_msg),
            VmCalls::assertNotEq_8(args) => self.assert_not_eq8(args, &mut host.assert_msg),
            VmCalls::assertNotEq_9(args) => self.assert_not_eq9(args, &mut host.assert_msg),
            VmCalls::assertNotEq_10(args) => self.assert_not_eq10(args, &mut host.assert_msg),
            VmCalls::assertNotEq_11(args) => self.assert_not_eq11(args, &mut host.assert_msg),
            VmCalls::assertNotEq_12(args) => self.assert_not_eq12(args, &mut host.assert_msg),
            VmCalls::assertNotEq_13(args) => self.assert_not_eq13(args, &mut host.assert_msg),
            VmCalls::assertNotEq_14(args) => self.assert_not_eq14(args, &mut host.assert_msg),
            VmCalls::assertNotEq_15(args) => self.assert_not_eq15(args, &mut host.assert_msg),
            VmCalls::assertNotEq_16(args) => self.assert_not_eq16(args, &mut host.assert_msg),
            VmCalls::assertNotEq_17(args) => self.assert_not_eq17(args, &mut host.assert_msg),
            VmCalls::assertNotEq_18(args) => self.assert_not_eq18(args, &mut host.assert_msg),
            VmCalls::assertNotEq_19(args) => self.assert_not_eq19(args, &mut host.assert_msg),
            VmCalls::assertNotEq_20(args) => self.assert_not_eq20(args, &mut host.assert_msg),
            VmCalls::assertNotEq_21(args) => self.assert_not_eq21(args, &mut host.assert_msg),
            VmCalls::assertNotEq_22(args) => self.assert_not_eq22(args, &mut host.assert_msg),
            VmCalls::assertNotEq_23(args) => self.assert_not_eq23(args, &mut host.assert_msg),
            VmCalls::assertNotEq_24(args) => self.assert_not_eq24(args, &mut host.assert_msg),
            VmCalls::assertNotEq_25(args) => self.assert_not_eq25(args, &mut host.assert_msg),
            VmCalls::assertNotEq_26(args) => self.assert_not_eq26(args, &mut host.assert_msg),
            VmCalls::assertNotEq_27(args) => self.assert_not_eq27(args, &mut host.assert_msg),
            VmCalls::assertNotEqDecimal_0(args) => self.assert_not_eq_decimal0(args, &mut host.assert_msg),
            VmCalls::assertNotEqDecimal_1(args) => self.assert_not_eq_decimal1(args, &mut host.assert_msg),
            VmCalls::assertNotEqDecimal_2(args) => self.assert_not_eq_decimal2(args, &mut host.assert_msg),
            VmCalls::assertNotEqDecimal_3(args) => self.assert_not_eq_decimal3(args, &mut host.assert_msg),
            VmCalls::assertGt_0(args) => self.assert_gt0(args, &mut host.assert_msg),
            VmCalls::assertGt_1(args) => self.assert_gt1(args, &mut host.assert_msg),
            VmCalls::assertGt_2(args) => self.assert_gt2(args, &mut host.assert_msg),
            VmCalls::assertGt_3(args) => self.assert_gt3(args, &mut host.assert_msg),
            VmCalls::assertGtDecimal_0(args) => self.assert_gt_decimal0(args, &mut host.assert_msg),
            VmCalls::assertGtDecimal_1(args) => self.assert_gt_decimal1(args, &mut host.assert_msg),
            VmCalls::assertGtDecimal_2(args) => self.assert_gt_decimal2(args, &mut host.assert_msg),
            VmCalls::assertGtDecimal_3(args) => self.assert_gt_decimal3(args, &mut host.assert_msg),
            VmCalls::assertGe_0(args) => self.assert_ge0(args, &mut host.assert_msg),
            VmCalls::assertGe_1(args) => self.assert_ge1(args, &mut host.assert_msg),
            VmCalls::assertGe_2(args) => self.assert_ge2(args, &mut host.assert_msg),
            VmCalls::assertGe_3(args) => self.assert_ge3(args, &mut host.assert_msg),
            VmCalls::assertGeDecimal_0(args) => self.assert_ge_decimal0(args, &mut host.assert_msg),
            VmCalls::assertGeDecimal_1(args) => self.assert_ge_decimal1(args, &mut host.assert_msg),
            VmCalls::assertGeDecimal_2(args) => self.assert_ge_decimal2(args, &mut host.assert_msg),
            VmCalls::assertGeDecimal_3(args) => self.assert_ge_decimal3(args, &mut host.assert_msg),
            VmCalls::assertLt_0(args) => self.assert_lt0(args, &mut host.assert_msg),
            VmCalls::assertLt_1(args) => self.assert_lt1(args, &mut host.assert_msg),
            VmCalls::assertLt_2(args) => self.assert_lt2(args, &mut host.assert_msg),
            VmCalls::assertLt_3(args) => self.assert_lt3(args, &mut host.assert_msg),
            VmCalls::assertLtDecimal_0(args) => self.assert_lt_decimal0(args, &mut host.assert_msg),
            VmCalls::assertLtDecimal_1(args) => self.assert_lt_decimal1(args, &mut host.assert_msg),
            VmCalls::assertLtDecimal_2(args) => self.assert_lt_decimal2(args, &mut host.assert_msg),
            VmCalls::assertLtDecimal_3(args) => self.assert_lt_decimal3(args, &mut host.assert_msg),
            VmCalls::assertLe_0(args) => self.assert_le0(args, &mut host.assert_msg),
            VmCalls::assertLe_1(args) => self.assert_le1(args, &mut host.assert_msg),
            VmCalls::assertLe_2(args) => self.assert_le2(args, &mut host.assert_msg),
            VmCalls::assertLe_3(args) => self.assert_le3(args, &mut host.assert_msg),
            VmCalls::assertLeDecimal_0(args) => self.assert_le_decimal0(args, &mut host.assert_msg),
            VmCalls::assertLeDecimal_1(args) => self.assert_le_decimal1(args, &mut host.assert_msg),
            VmCalls::assertLeDecimal_2(args) => self.assert_le_decimal2(args, &mut host.assert_msg),
            VmCalls::assertLeDecimal_3(args) => self.assert_le_decimal3(args, &mut host.assert_msg),
            VmCalls::assertApproxEqAbs_0(args) => self.assert_approx_eq_abs0(args, &mut host.assert_msg),
            VmCalls::assertApproxEqAbs_1(args) => self.assert_approx_eq_abs1(args, &mut host.assert_msg),
            VmCalls::assertApproxEqAbs_2(args) => self.assert_approx_eq_abs2(args, &mut host.assert_msg),
            VmCalls::assertApproxEqAbs_3(args) => self.assert_approx_eq_abs3(args, &mut host.assert_msg),
            VmCalls::assertApproxEqAbsDecimal_0(args) => self.assert_approx_eq_abs_decimal0(args, &mut host.assert_msg),
            VmCalls::assertApproxEqAbsDecimal_1(args) => self.assert_approx_eq_abs_decimal1(args, &mut host.assert_msg),
            VmCalls::assertApproxEqAbsDecimal_2(args) => self.assert_approx_eq_abs_decimal2(args, &mut host.assert_msg),
            VmCalls::assertApproxEqAbsDecimal_3(args) => self.assert_approx_eq_abs_decimal3(args, &mut host.assert_msg),
            VmCalls::assertApproxEqRel_0(args) => self.assert_approx_eq_rel0(args, &mut host.assert_msg),
            VmCalls::assertApproxEqRel_1(args) => self.assert_approx_eq_rel1(args, &mut host.assert_msg),
            VmCalls::assertApproxEqRel_2(args) => self.assert_approx_eq_rel2(args, &mut host.assert_msg),
            VmCalls::assertApproxEqRel_3(args) => self.assert_approx_eq_rel3(args, &mut host.assert_msg),
            VmCalls::assertApproxEqRelDecimal_0(args) => self.assert_approx_eq_rel_decimal0(args, &mut host.assert_msg),
            VmCalls::assertApproxEqRelDecimal_1(args) => self.assert_approx_eq_rel_decimal1(args, &mut host.assert_msg),
            VmCalls::assertApproxEqRelDecimal_2(args) => self.assert_approx_eq_rel_decimal2(args, &mut host.assert_msg),
            VmCalls::assertApproxEqRelDecimal_3(args) => self.assert_approx_eq_rel_decimal3(args, &mut host.assert_msg),

            // env
            VmCalls::envBool_0(args) => self.env_bool0(args),
            VmCalls::envUint_0(args) => self.env_uint0(args),
            VmCalls::envInt_0(args) => self.env_int0(args),
            VmCalls::envAddress_0(args) => self.env_address0(args),
            VmCalls::envBytes32_0(args) => self.env_bytes32_0(args),
            VmCalls::envString_0(args) => self.env_string(args),
            VmCalls::envBytes_0(args) => self.env_bytes(args),
            VmCalls::envBool_1(args) => self.env_bool1(args),
            VmCalls::envUint_1(args) => self.env_uint1(args),
            VmCalls::envInt_1(args) => self.env_int1(args),
            VmCalls::envAddress_1(args) => self.env_address1(args),
            VmCalls::envBytes32_1(args) => self.env_bytes32_1(args),
            VmCalls::envString_1(args) => self.env_string1(args),
            VmCalls::envBytes_1(args) => self.env_bytes1(args),
            VmCalls::envOr_0(args) => self.env_or0(args),
            VmCalls::envOr_1(args) => self.env_or1(args),
            VmCalls::envOr_2(args) => self.env_or2(args),
            VmCalls::envOr_3(args) => self.env_or3(args),
            VmCalls::envOr_4(args) => self.env_or4(args),
            VmCalls::envOr_5(args) => self.env_or5(args),
            VmCalls::envOr_6(args) => self.env_or6(args),
            VmCalls::envOr_7(args) => self.env_or7(args),
            VmCalls::envOr_8(args) => self.env_or8(args),
            VmCalls::envOr_9(args) => self.env_or9(args),
            VmCalls::envOr_10(args) => self.env_or10(args),
            VmCalls::envOr_11(args) => self.env_or11(args),
            VmCalls::envOr_12(args) => self.env_or12(args),
            VmCalls::envOr_13(args) => self.env_or13(args),

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
        event_to_fill_or_check.log = Some(RawLog::new_unchecked(*address, topics.to_vec(), data.clone()));
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
            event_to_fill_or_check.found &= expected.data.data.as_ref() == data.as_ref();
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

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::HashMap, fs, path::Path, rc::Rc, str::FromStr};

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
        logger,
        state::FuzzState,
        state_input::StagedVMState,
    };

    #[test]
    fn test_foundry_contract() {
        logger::init_test();

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
        fuzz_host.add_middlewares(Rc::new(RefCell::new(Cheatcode::new(""))));
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
                    swap_data: HashMap::new(),
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
