use std::fmt::Display;

use alloy_primitives::{hex, I256};
use foundry_cheatcodes::Vm;
use itertools::Itertools;
use libafl::schedulers::Scheduler;
use revm_primitives::U256;

use super::Cheatcode;
use crate::evm::types::EVMFuzzState;

const EQ_REL_DELTA_RESOLUTION: U256 = U256::from_limbs([18, 0, 0, 0]);

/// Cheat VmCalls
impl<SC> Cheatcode<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    #[inline]
    pub fn assert_true0(&self, args: Vm::assertTrue_0Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertTrue_0Call { condition } = args;
        if !condition {
            assert_msg.replace("assertion failed".to_string());
        }
        None
    }

    #[inline]
    pub fn assert_true1(&self, args: Vm::assertTrue_1Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertTrue_1Call { condition, error } = args;
        if !condition {
            assert_msg.replace(error);
        }
        None
    }

    #[inline]
    pub fn assert_false0(&self, args: Vm::assertFalse_0Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertFalse_0Call { condition } = args;
        if condition {
            assert_msg.replace("assertion failed".to_string());
        }
        None
    }

    #[inline]
    pub fn assert_false1(&self, args: Vm::assertFalse_1Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertFalse_1Call { condition, error } = args;
        if condition {
            assert_msg.replace(error);
        }
        None
    }

    #[inline]
    pub fn assert_eq0(&self, args: Vm::assertEq_0Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_0Call { left, right } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_eq1(&self, args: Vm::assertEq_1Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_1Call { left, right, error } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_eq2(&self, args: Vm::assertEq_2Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_2Call { left, right } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_eq3(&self, args: Vm::assertEq_3Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_3Call { left, right, error } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_eq4(&self, args: Vm::assertEq_4Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_4Call { left, right } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_eq5(&self, args: Vm::assertEq_5Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_5Call { left, right, error } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_eq6(&self, args: Vm::assertEq_6Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_6Call { left, right } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_eq7(&self, args: Vm::assertEq_7Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_7Call { left, right, error } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_eq8(&self, args: Vm::assertEq_8Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_8Call { left, right } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_eq9(&self, args: Vm::assertEq_9Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_9Call { left, right, error } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_eq10(&self, args: Vm::assertEq_10Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_10Call { left, right } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_eq11(&self, args: Vm::assertEq_11Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_11Call { left, right, error } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_eq12(&self, args: Vm::assertEq_12Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_12Call { left, right } = args;
        if let Err(e) = assert_eq(&hex::encode_prefixed(left), &hex::encode_prefixed(right)) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_eq13(&self, args: Vm::assertEq_13Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_13Call { left, right, error } = args;
        if let Err(e) = assert_eq(&hex::encode_prefixed(left), &hex::encode_prefixed(right)) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_eq14(&self, args: Vm::assertEq_14Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_14Call { left, right } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_eq15(&self, args: Vm::assertEq_15Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_15Call { left, right, error } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_eq16(&self, args: Vm::assertEq_16Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_16Call { left, right } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_eq17(&self, args: Vm::assertEq_17Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_17Call { left, right, error } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_eq18(&self, args: Vm::assertEq_18Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_18Call { left, right } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_eq19(&self, args: Vm::assertEq_19Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_19Call { left, right, error } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_eq20(&self, args: Vm::assertEq_20Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_20Call { left, right } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_eq21(&self, args: Vm::assertEq_21Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_21Call { left, right, error } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_eq22(&self, args: Vm::assertEq_22Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_22Call { left, right } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_eq23(&self, args: Vm::assertEq_23Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_23Call { left, right, error } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_eq24(&self, args: Vm::assertEq_24Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_24Call { left, right } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_eq25(&self, args: Vm::assertEq_25Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_25Call { left, right, error } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_eq26(&self, args: Vm::assertEq_26Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_26Call { left, right } = args;
        let left = left.iter().map(hex::encode_prefixed).collect::<Vec<_>>();
        let right = right.iter().map(hex::encode_prefixed).collect::<Vec<_>>();
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_eq27(&self, args: Vm::assertEq_27Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertEq_27Call { left, right, error } = args;
        let left = left.iter().map(hex::encode_prefixed).collect::<Vec<_>>();
        let right = right.iter().map(hex::encode_prefixed).collect::<Vec<_>>();
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_eq_decimal0(
        &self,
        args: Vm::assertEqDecimal_0Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertEqDecimal_0Call { left, right, decimals } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_eq_decimal1(
        &self,
        args: Vm::assertEqDecimal_1Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertEqDecimal_1Call {
            left,
            right,
            decimals,
            error,
        } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_eq_decimal2(
        &self,
        args: Vm::assertEqDecimal_2Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertEqDecimal_2Call { left, right, decimals } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_eq_decimal3(
        &self,
        args: Vm::assertEqDecimal_3Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertEqDecimal_3Call {
            left,
            right,
            decimals,
            error,
        } = args;
        if let Err(e) = assert_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq0(&self, args: Vm::assertNotEq_0Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_0Call { left, right } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq1(&self, args: Vm::assertNotEq_1Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_1Call { left, right, error } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq2(&self, args: Vm::assertNotEq_2Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_2Call { left, right } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq3(&self, args: Vm::assertNotEq_3Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_3Call { left, right, error } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq4(&self, args: Vm::assertNotEq_4Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_4Call { left, right } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq5(&self, args: Vm::assertNotEq_5Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_5Call { left, right, error } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq6(&self, args: Vm::assertNotEq_6Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_6Call { left, right } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq7(&self, args: Vm::assertNotEq_7Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_7Call { left, right, error } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq8(&self, args: Vm::assertNotEq_8Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_8Call { left, right } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq9(&self, args: Vm::assertNotEq_9Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_9Call { left, right, error } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq10(&self, args: Vm::assertNotEq_10Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_10Call { left, right } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq11(&self, args: Vm::assertNotEq_11Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_11Call { left, right, error } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq12(&self, args: Vm::assertNotEq_12Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_12Call { left, right } = args;
        if let Err(e) = assert_not_eq(&hex::encode_prefixed(left), &hex::encode_prefixed(right)) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq13(&self, args: Vm::assertNotEq_13Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_13Call { left, right, error } = args;
        if let Err(e) = assert_not_eq(&hex::encode_prefixed(left), &hex::encode_prefixed(right)) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq14(&self, args: Vm::assertNotEq_14Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_14Call { left, right } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq15(&self, args: Vm::assertNotEq_15Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_15Call { left, right, error } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq16(&self, args: Vm::assertNotEq_16Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_16Call { left, right } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq17(&self, args: Vm::assertNotEq_17Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_17Call { left, right, error } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq18(&self, args: Vm::assertNotEq_18Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_18Call { left, right } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq19(&self, args: Vm::assertNotEq_19Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_19Call { left, right, error } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq20(&self, args: Vm::assertNotEq_20Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_20Call { left, right } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq21(&self, args: Vm::assertNotEq_21Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_21Call { left, right, error } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq22(&self, args: Vm::assertNotEq_22Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_22Call { left, right } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq23(&self, args: Vm::assertNotEq_23Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_23Call { left, right, error } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq24(&self, args: Vm::assertNotEq_24Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_24Call { left, right } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq25(&self, args: Vm::assertNotEq_25Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_25Call { left, right, error } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq26(&self, args: Vm::assertNotEq_26Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_26Call { left, right } = args;
        let left = left.iter().map(hex::encode_prefixed).collect::<Vec<_>>();
        let right = right.iter().map(hex::encode_prefixed).collect::<Vec<_>>();
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq27(&self, args: Vm::assertNotEq_27Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertNotEq_27Call { left, right, error } = args;
        let left = left.iter().map(hex::encode_prefixed).collect::<Vec<_>>();
        let right = right.iter().map(hex::encode_prefixed).collect::<Vec<_>>();
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_arrays()));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq_decimal0(
        &self,
        args: Vm::assertNotEqDecimal_0Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertNotEqDecimal_0Call { left, right, decimals } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq_decimal1(
        &self,
        args: Vm::assertNotEqDecimal_1Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertNotEqDecimal_1Call {
            left,
            right,
            decimals,
            error,
        } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq_decimal2(
        &self,
        args: Vm::assertNotEqDecimal_2Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertNotEqDecimal_2Call { left, right, decimals } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_not_eq_decimal3(
        &self,
        args: Vm::assertNotEqDecimal_3Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertNotEqDecimal_3Call {
            left,
            right,
            decimals,
            error,
        } = args;
        if let Err(e) = assert_not_eq(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_gt0(&self, args: Vm::assertGt_0Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertGt_0Call { left, right } = args;
        if let Err(e) = assert_gt(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_gt1(&self, args: Vm::assertGt_1Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertGt_1Call { left, right, error } = args;
        if let Err(e) = assert_gt(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_gt2(&self, args: Vm::assertGt_2Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertGt_2Call { left, right } = args;
        if let Err(e) = assert_gt(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_gt3(&self, args: Vm::assertGt_3Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertGt_3Call { left, right, error } = args;
        if let Err(e) = assert_gt(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_gt_decimal0(
        &self,
        args: Vm::assertGtDecimal_0Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertGtDecimal_0Call { left, right, decimals } = args;
        if let Err(e) = assert_gt(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_gt_decimal1(
        &self,
        args: Vm::assertGtDecimal_1Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertGtDecimal_1Call {
            left,
            right,
            decimals,
            error,
        } = args;
        if let Err(e) = assert_gt(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_gt_decimal2(
        &self,
        args: Vm::assertGtDecimal_2Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertGtDecimal_2Call { left, right, decimals } = args;
        if let Err(e) = assert_gt(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_gt_decimal3(
        &self,
        args: Vm::assertGtDecimal_3Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertGtDecimal_3Call {
            left,
            right,
            decimals,
            error,
        } = args;
        if let Err(e) = assert_gt(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_ge0(&self, args: Vm::assertGe_0Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertGe_0Call { left, right } = args;
        if let Err(e) = assert_ge(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_ge1(&self, args: Vm::assertGe_1Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertGe_1Call { left, right, error } = args;
        if let Err(e) = assert_ge(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_ge2(&self, args: Vm::assertGe_2Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertGe_2Call { left, right } = args;
        if let Err(e) = assert_ge(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_ge3(&self, args: Vm::assertGe_3Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertGe_3Call { left, right, error } = args;
        if let Err(e) = assert_ge(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_ge_decimal0(
        &self,
        args: Vm::assertGeDecimal_0Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertGeDecimal_0Call { left, right, decimals } = args;
        if let Err(e) = assert_ge(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_ge_decimal1(
        &self,
        args: Vm::assertGeDecimal_1Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertGeDecimal_1Call {
            left,
            right,
            decimals,
            error,
        } = args;
        if let Err(e) = assert_ge(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_ge_decimal2(
        &self,
        args: Vm::assertGeDecimal_2Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertGeDecimal_2Call { left, right, decimals } = args;
        if let Err(e) = assert_ge(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_ge_decimal3(
        &self,
        args: Vm::assertGeDecimal_3Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertGeDecimal_3Call {
            left,
            right,
            decimals,
            error,
        } = args;
        if let Err(e) = assert_ge(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_lt0(&self, args: Vm::assertLt_0Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertLt_0Call { left, right } = args;
        if let Err(e) = assert_lt(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_lt1(&self, args: Vm::assertLt_1Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertLt_1Call { left, right, error } = args;
        if let Err(e) = assert_lt(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_lt2(&self, args: Vm::assertLt_2Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertLt_2Call { left, right } = args;
        if let Err(e) = assert_lt(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_lt3(&self, args: Vm::assertLt_3Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertLt_3Call { left, right, error } = args;
        if let Err(e) = assert_lt(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_lt_decimal0(
        &self,
        args: Vm::assertLtDecimal_0Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertLtDecimal_0Call { left, right, decimals } = args;
        if let Err(e) = assert_lt(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_lt_decimal1(
        &self,
        args: Vm::assertLtDecimal_1Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertLtDecimal_1Call {
            left,
            right,
            decimals,
            error,
        } = args;
        if let Err(e) = assert_lt(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_lt_decimal2(
        &self,
        args: Vm::assertLtDecimal_2Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertLtDecimal_2Call { left, right, decimals } = args;
        if let Err(e) = assert_lt(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_lt_decimal3(
        &self,
        args: Vm::assertLtDecimal_3Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertLtDecimal_3Call {
            left,
            right,
            decimals,
            error,
        } = args;
        if let Err(e) = assert_lt(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_le0(&self, args: Vm::assertLe_0Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertLe_0Call { left, right } = args;
        if let Err(e) = assert_le(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_le1(&self, args: Vm::assertLe_1Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertLe_1Call { left, right, error } = args;
        if let Err(e) = assert_le(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_le2(&self, args: Vm::assertLe_2Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertLe_2Call { left, right } = args;
        if let Err(e) = assert_le(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_le3(&self, args: Vm::assertLe_3Call, assert_msg: &mut Option<String>) -> Option<Vec<u8>> {
        let Vm::assertLe_3Call { left, right, error } = args;
        if let Err(e) = assert_le(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_for_values()));
        }
        None
    }

    #[inline]
    pub fn assert_le_decimal0(
        &self,
        args: Vm::assertLeDecimal_0Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertLeDecimal_0Call { left, right, decimals } = args;
        if let Err(e) = assert_le(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_le_decimal1(
        &self,
        args: Vm::assertLeDecimal_1Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertLeDecimal_1Call {
            left,
            right,
            decimals,
            error,
        } = args;
        if let Err(e) = assert_le(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_le_decimal2(
        &self,
        args: Vm::assertLeDecimal_2Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertLeDecimal_2Call { left, right, decimals } = args;
        if let Err(e) = assert_le(&left, &right) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_le_decimal3(
        &self,
        args: Vm::assertLeDecimal_3Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertLeDecimal_3Call {
            left,
            right,
            decimals,
            error,
        } = args;
        if let Err(e) = assert_le(&left, &right) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_abs0(
        &self,
        args: Vm::assertApproxEqAbs_0Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqAbs_0Call { left, right, maxDelta } = args;
        if let Err(e) = uint_assert_approx_eq_abs(left, right, maxDelta) {
            assert_msg.replace(format!("assertion failed: {}", e));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_abs1(
        &self,
        args: Vm::assertApproxEqAbs_1Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqAbs_1Call {
            left,
            right,
            maxDelta,
            error,
        } = args;
        if let Err(e) = uint_assert_approx_eq_abs(left, right, maxDelta) {
            assert_msg.replace(format!("{}: {}", error, e));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_abs2(
        &self,
        args: Vm::assertApproxEqAbs_2Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqAbs_2Call { left, right, maxDelta } = args;
        if let Err(e) = int_assert_approx_eq_abs(left, right, maxDelta) {
            assert_msg.replace(format!("assertion failed: {}", e));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_abs3(
        &self,
        args: Vm::assertApproxEqAbs_3Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqAbs_3Call {
            left,
            right,
            maxDelta,
            error,
        } = args;
        if let Err(e) = int_assert_approx_eq_abs(left, right, maxDelta) {
            assert_msg.replace(format!("{}: {}", error, e));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_abs_decimal0(
        &self,
        args: Vm::assertApproxEqAbsDecimal_0Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqAbsDecimal_0Call {
            left,
            right,
            maxDelta,
            decimals,
        } = args;
        if let Err(e) = uint_assert_approx_eq_abs(left, right, maxDelta) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_abs_decimal1(
        &self,
        args: Vm::assertApproxEqAbsDecimal_1Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqAbsDecimal_1Call {
            left,
            right,
            maxDelta,
            decimals,
            error,
        } = args;
        if let Err(e) = uint_assert_approx_eq_abs(left, right, maxDelta) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_abs_decimal2(
        &self,
        args: Vm::assertApproxEqAbsDecimal_2Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqAbsDecimal_2Call {
            left,
            right,
            maxDelta,
            decimals,
        } = args;
        if let Err(e) = int_assert_approx_eq_abs(left, right, maxDelta) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_abs_decimal3(
        &self,
        args: Vm::assertApproxEqAbsDecimal_3Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqAbsDecimal_3Call {
            left,
            right,
            maxDelta,
            decimals,
            error,
        } = args;
        if let Err(e) = int_assert_approx_eq_abs(left, right, maxDelta) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_rel0(
        &self,
        args: Vm::assertApproxEqRel_0Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqRel_0Call {
            left,
            right,
            maxPercentDelta,
        } = args;
        if let Err(e) = uint_assert_approx_eq_rel(left, right, maxPercentDelta) {
            assert_msg.replace(format!("assertion failed: {}", e));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_rel1(
        &self,
        args: Vm::assertApproxEqRel_1Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqRel_1Call {
            left,
            right,
            maxPercentDelta,
            error,
        } = args;
        if let Err(e) = uint_assert_approx_eq_rel(left, right, maxPercentDelta) {
            assert_msg.replace(format!("{}: {}", error, e));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_rel2(
        &self,
        args: Vm::assertApproxEqRel_2Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqRel_2Call {
            left,
            right,
            maxPercentDelta,
        } = args;
        if let Err(e) = int_assert_approx_eq_rel(left, right, maxPercentDelta) {
            assert_msg.replace(format!("assertion failed: {}", e));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_rel3(
        &self,
        args: Vm::assertApproxEqRel_3Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqRel_3Call {
            left,
            right,
            maxPercentDelta,
            error,
        } = args;
        if let Err(e) = int_assert_approx_eq_rel(left, right, maxPercentDelta) {
            assert_msg.replace(format!("{}: {}", error, e));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_rel_decimal0(
        &self,
        args: Vm::assertApproxEqRelDecimal_0Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqRelDecimal_0Call {
            left,
            right,
            maxPercentDelta,
            decimals,
        } = args;
        if let Err(e) = uint_assert_approx_eq_rel(left, right, maxPercentDelta) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_rel_decimal1(
        &self,
        args: Vm::assertApproxEqRelDecimal_1Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqRelDecimal_1Call {
            left,
            right,
            maxPercentDelta,
            decimals,
            error,
        } = args;
        if let Err(e) = uint_assert_approx_eq_rel(left, right, maxPercentDelta) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_rel_decimal2(
        &self,
        args: Vm::assertApproxEqRelDecimal_2Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqRelDecimal_2Call {
            left,
            right,
            maxPercentDelta,
            decimals,
        } = args;
        if let Err(e) = int_assert_approx_eq_rel(left, right, maxPercentDelta) {
            assert_msg.replace(format!("assertion failed: {}", e.format_with_decimals(&decimals)));
        }
        None
    }

    #[inline]
    pub fn assert_approx_eq_rel_decimal3(
        &self,
        args: Vm::assertApproxEqRelDecimal_3Call,
        assert_msg: &mut Option<String>,
    ) -> Option<Vec<u8>> {
        let Vm::assertApproxEqRelDecimal_3Call {
            left,
            right,
            maxPercentDelta,
            decimals,
            error,
        } = args;
        if let Err(e) = int_assert_approx_eq_rel(left, right, maxPercentDelta) {
            assert_msg.replace(format!("{}: {}", error, e.format_with_decimals(&decimals)));
        }
        None
    }
}

fn assert_eq<'a, T: PartialEq>(left: &'a T, right: &'a T) -> ComparisonResult<'a, T> {
    if left == right {
        Ok(Default::default())
    } else {
        Err(ComparisonAssertionError::Eq { left, right })
    }
}

fn assert_not_eq<'a, T: PartialEq>(left: &'a T, right: &'a T) -> ComparisonResult<'a, T> {
    if left != right {
        Ok(Default::default())
    } else {
        Err(ComparisonAssertionError::Ne { left, right })
    }
}

fn get_delta_uint(left: U256, right: U256) -> U256 {
    if left > right {
        left - right
    } else {
        right - left
    }
}

fn get_delta_int(left: I256, right: I256) -> U256 {
    let (left_sign, left_abs) = left.into_sign_and_abs();
    let (right_sign, right_abs) = right.into_sign_and_abs();

    if left_sign == right_sign {
        if left_abs > right_abs {
            left_abs - right_abs
        } else {
            right_abs - left_abs
        }
    } else {
        left_abs + right_abs
    }
}

fn uint_assert_approx_eq_abs(
    left: U256,
    right: U256,
    max_delta: U256,
) -> Result<Vec<u8>, Box<EqAbsAssertionError<U256, U256>>> {
    let delta = get_delta_uint(left, right);

    if delta <= max_delta {
        Ok(Default::default())
    } else {
        Err(Box::new(EqAbsAssertionError {
            left,
            right,
            max_delta,
            real_delta: delta,
        }))
    }
}

fn int_assert_approx_eq_abs(
    left: I256,
    right: I256,
    max_delta: U256,
) -> Result<Vec<u8>, Box<EqAbsAssertionError<I256, U256>>> {
    let delta = get_delta_int(left, right);

    if delta <= max_delta {
        Ok(Default::default())
    } else {
        Err(Box::new(EqAbsAssertionError {
            left,
            right,
            max_delta,
            real_delta: delta,
        }))
    }
}

fn uint_assert_approx_eq_rel(left: U256, right: U256, max_delta: U256) -> Result<Vec<u8>, EqRelAssertionError<U256>> {
    if right.is_zero() && !left.is_zero() {
        return Err(EqRelAssertionError::Failure(Box::new(EqRelAssertionFailure {
            left,
            right,
            max_delta,
            real_delta: EqRelDelta::Undefined,
        })));
    }

    let delta = get_delta_uint(left, right)
        .checked_mul(U256::pow(U256::from(10), EQ_REL_DELTA_RESOLUTION))
        .ok_or(EqRelAssertionError::Overflow)? /
        right;

    if delta <= max_delta {
        Ok(Default::default())
    } else {
        Err(EqRelAssertionError::Failure(Box::new(EqRelAssertionFailure {
            left,
            right,
            max_delta,
            real_delta: EqRelDelta::Defined(delta),
        })))
    }
}

fn int_assert_approx_eq_rel(left: I256, right: I256, max_delta: U256) -> Result<Vec<u8>, EqRelAssertionError<I256>> {
    if right.is_zero() && !left.is_zero() {
        return Err(EqRelAssertionError::Failure(Box::new(EqRelAssertionFailure {
            left,
            right,
            max_delta,
            real_delta: EqRelDelta::Undefined,
        })));
    }

    let (_, abs_right) = right.into_sign_and_abs();
    let delta = get_delta_int(left, right)
        .checked_mul(U256::pow(U256::from(10), EQ_REL_DELTA_RESOLUTION))
        .ok_or(EqRelAssertionError::Overflow)? /
        abs_right;

    if delta <= max_delta {
        Ok(Default::default())
    } else {
        Err(EqRelAssertionError::Failure(Box::new(EqRelAssertionFailure {
            left,
            right,
            max_delta,
            real_delta: EqRelDelta::Defined(delta),
        })))
    }
}

fn assert_gt<'a, T: PartialOrd>(left: &'a T, right: &'a T) -> ComparisonResult<'a, T> {
    if left > right {
        Ok(Default::default())
    } else {
        Err(ComparisonAssertionError::Gt { left, right })
    }
}

fn assert_ge<'a, T: PartialOrd>(left: &'a T, right: &'a T) -> ComparisonResult<'a, T> {
    if left >= right {
        Ok(Default::default())
    } else {
        Err(ComparisonAssertionError::Ge { left, right })
    }
}

fn assert_lt<'a, T: PartialOrd>(left: &'a T, right: &'a T) -> ComparisonResult<'a, T> {
    if left < right {
        Ok(Default::default())
    } else {
        Err(ComparisonAssertionError::Lt { left, right })
    }
}

fn assert_le<'a, T: PartialOrd>(left: &'a T, right: &'a T) -> ComparisonResult<'a, T> {
    if left <= right {
        Ok(Default::default())
    } else {
        Err(ComparisonAssertionError::Le { left, right })
    }
}

type ComparisonResult<'a, T> = Result<Vec<u8>, ComparisonAssertionError<'a, T>>;

#[derive(thiserror::Error, Debug)]
enum ComparisonAssertionError<'a, T> {
    Ne { left: &'a T, right: &'a T },
    Eq { left: &'a T, right: &'a T },
    Ge { left: &'a T, right: &'a T },
    Gt { left: &'a T, right: &'a T },
    Le { left: &'a T, right: &'a T },
    Lt { left: &'a T, right: &'a T },
}

macro_rules! format_values {
    ($self:expr, $format_fn:expr) => {
        match $self {
            Self::Ne { left, right } => format!("{} == {}", $format_fn(left), $format_fn(right)),
            Self::Eq { left, right } => format!("{} != {}", $format_fn(left), $format_fn(right)),
            Self::Ge { left, right } => format!("{} < {}", $format_fn(left), $format_fn(right)),
            Self::Gt { left, right } => format!("{} <= {}", $format_fn(left), $format_fn(right)),
            Self::Le { left, right } => format!("{} > {}", $format_fn(left), $format_fn(right)),
            Self::Lt { left, right } => format!("{} >= {}", $format_fn(left), $format_fn(right)),
        }
    };
}

impl<'a, T: Display> ComparisonAssertionError<'a, T> {
    fn format_for_values(&self) -> String {
        format_values!(self, T::to_string)
    }
}

impl<'a, T: Display> ComparisonAssertionError<'a, Vec<T>> {
    fn format_for_arrays(&self) -> String {
        let formatter = |v: &Vec<T>| format!("[{}]", v.iter().format(", "));
        format_values!(self, formatter)
    }
}

impl<'a> ComparisonAssertionError<'a, U256> {
    fn format_with_decimals(&self, decimals: &U256) -> String {
        let formatter = |v: &U256| format_units_uint(v, decimals);
        format_values!(self, formatter)
    }
}

impl<'a> ComparisonAssertionError<'a, I256> {
    fn format_with_decimals(&self, decimals: &U256) -> String {
        let formatter = |v: &I256| format_units_int(v, decimals);
        format_values!(self, formatter)
    }
}

pub fn format_units_int(x: &I256, decimals: &U256) -> String {
    let (sign, x) = x.into_sign_and_abs();
    format!("{sign}{}", format_units_uint(&x, decimals))
}

pub fn format_units_uint(x: &U256, decimals: &U256) -> String {
    match alloy_primitives::utils::Unit::new(decimals.saturating_to::<u8>()) {
        Some(units) => alloy_primitives::utils::ParseUnits::U256(*x).format_units(units),
        None => x.to_string(),
    }
}

#[derive(thiserror::Error, Debug)]
#[error("{left} !~= {right} (max delta: {max_delta}, real delta: {real_delta})")]
struct EqAbsAssertionError<T, D> {
    left: T,
    right: T,
    max_delta: D,
    real_delta: D,
}

impl EqAbsAssertionError<U256, U256> {
    fn format_with_decimals(&self, decimals: &U256) -> String {
        format!(
            "{} !~= {} (max delta: {}, real delta: {})",
            format_units_uint(&self.left, decimals),
            format_units_uint(&self.right, decimals),
            format_units_uint(&self.max_delta, decimals),
            format_units_uint(&self.real_delta, decimals),
        )
    }
}

impl EqAbsAssertionError<I256, U256> {
    fn format_with_decimals(&self, decimals: &U256) -> String {
        format!(
            "{} !~= {} (max delta: {}, real delta: {})",
            format_units_int(&self.left, decimals),
            format_units_int(&self.right, decimals),
            format_units_uint(&self.max_delta, decimals),
            format_units_uint(&self.real_delta, decimals),
        )
    }
}

fn format_delta_percent(delta: &U256) -> String {
    format!(
        "{}%",
        format_units_uint(delta, &(EQ_REL_DELTA_RESOLUTION - U256::from(2)))
    )
}

#[derive(thiserror::Error, Debug)]
#[error(
    "{left} !~= {right} (max delta: {}, real delta: {})",
    format_delta_percent(max_delta),
    real_delta
)]
struct EqRelAssertionFailure<T> {
    left: T,
    right: T,
    max_delta: U256,
    real_delta: EqRelDelta,
}

#[derive(thiserror::Error, Debug)]
enum EqRelAssertionError<T> {
    #[error(transparent)]
    Failure(Box<EqRelAssertionFailure<T>>),
    #[error("overflow in delta calculation")]
    Overflow,
}

impl EqRelAssertionError<U256> {
    fn format_with_decimals(&self, decimals: &U256) -> String {
        match self {
            Self::Failure(f) => format!(
                "{} !~= {} (max delta: {}, real delta: {})",
                format_units_uint(&f.left, decimals),
                format_units_uint(&f.right, decimals),
                format_delta_percent(&f.max_delta),
                &f.real_delta,
            ),
            Self::Overflow => self.to_string(),
        }
    }
}

impl EqRelAssertionError<I256> {
    fn format_with_decimals(&self, decimals: &U256) -> String {
        match self {
            Self::Failure(f) => format!(
                "{} !~= {} (max delta: {}, real delta: {})",
                format_units_int(&f.left, decimals),
                format_units_int(&f.right, decimals),
                format_delta_percent(&f.max_delta),
                &f.real_delta,
            ),
            Self::Overflow => self.to_string(),
        }
    }
}

#[derive(Debug)]
enum EqRelDelta {
    Defined(U256),
    Undefined,
}

impl Display for EqRelDelta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Defined(delta) => write!(f, "{}", format_delta_percent(delta)),
            Self::Undefined => write!(f, "undefined"),
        }
    }
}
