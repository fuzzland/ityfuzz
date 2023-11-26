use super::types::EVMU512;

pub mod arb_call;
pub mod echidna;
pub mod erc20;
pub mod function;
pub mod invariant;
pub mod reentrancy;
pub mod selfdestruct;
pub mod state_comp;
pub mod typed_bug;
pub mod v2_pair;

pub static ERC20_BUG_IDX: u64 = 0;
pub static FUNCTION_BUG_IDX: u64 = 1;
pub static V2_PAIR_BUG_IDX: u64 = 2;
pub static TYPED_BUG_BUG_IDX: u64 = 4;
pub static SELFDESTRUCT_BUG_IDX: u64 = 5;
pub static ECHIDNA_BUG_IDX: u64 = 6;
pub static STATE_COMP_BUG_IDX: u64 = 7;
pub static ARB_CALL_BUG_IDX: u64 = 8;
pub static REENTRANCY_BUG_IDX: u64 = 9;
pub static INVARIANT_BUG_IDX: u64 = 10;
pub static INTEGER_OVERFLOW_BUG_IDX: u64 = 11;

/// Divide a U512 by another U512 and return a string with the decimal point at
/// the correct position For example, 1000 / 3 = 333.333, then a = 1000e6, b =
/// 3, fp = 6
pub fn u512_div_float(a: EVMU512, b: EVMU512, fp: usize) -> String {
    let mut res = format!("{}", a / b);
    if res.len() <= fp {
        res.insert_str(0, &"0".repeat(fp - res.len() + 1));
    }
    res.insert(res.len() - fp, '.');
    res
}

#[macro_export]
macro_rules! oracle_should_skip {
    ($ctx: expr, $key: expr) => {{
        let mut res = false;
        if let Some(meta) = $ctx.fuzz_state.metadata_map().get::<BugMetadata>() {
            res = meta.known_bugs.contains(&$key);
        }
        res
    }};
}
