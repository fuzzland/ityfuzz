use std::{collections::HashMap, fmt::Debug};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub trait VMStateT: Clone + Debug + Default + Serialize + DeserializeOwned {
    fn get_hash(&self) -> u64;
    fn has_post_execution(&self) -> bool;
    fn get_post_execution_needed_len(&self) -> usize;
    fn get_post_execution_pc(&self) -> usize;
    fn get_post_execution_len(&self) -> usize;
    #[cfg(feature = "full_trace")]
    fn get_flashloan(&self) -> String;
    fn as_any(&self) -> &dyn std::any::Any;
    fn eq(&self, other: &Self) -> bool;
    fn is_subset_of(&self, other: &Self) -> bool;

    // optional methods

    /// map<swap_type, swap_info>
    fn get_swap_data(&self) -> HashMap<String, SwapInfo> {
        HashMap::new()
    }
}

/// Generic swap info.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SwapInfo {
    /// swap type (deposit, buy, sell, ...)
    pub ty: String,
    /// target address
    pub target: String,
    /// swap path
    pub path: Vec<String>,
}
