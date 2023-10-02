pub mod echidna;
pub mod erc20;
pub mod function;
pub mod selfdestruct;
pub mod typed_bug;
pub mod v2_pair;
pub mod state_comp;
pub mod arb_call;

pub static ERC20_BUG_IDX: u64 = 0;
pub static FUNCTION_BUG_IDX: u64 = 1;
pub static V2_PAIR_BUG_IDX: u64 = 2;
pub static TYPED_BUG_BUG_IDX: u64 = 4;
pub static SELFDESTRUCT_BUG_IDX: u64 = 5;
pub static ECHIDNA_BUG_IDX: u64 = 6;
pub static STATE_COMP_BUG_IDX: u64 = 7;
pub static ARB_CALL_BUG_IDX: u64 = 8;