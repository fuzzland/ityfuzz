pub mod erc20;
pub mod function;
pub mod v2_pair;
pub mod bug;
pub mod typed_bug;
pub mod selfdestruct;

pub static ERC20_BUG_IDX: u64 = 0;
pub static FUNCTION_BUG_IDX: u64 = 1;
pub static V2_PAIR_BUG_IDX: u64 = 2;
pub static BUG_BUG_IDX: u64 = 3;
pub static TYPED_BUG_BUG_IDX: u64 = 4;
