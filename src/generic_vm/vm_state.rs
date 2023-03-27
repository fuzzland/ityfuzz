use crate::evm::vm::PostExecutionCtx;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;

pub trait VMStateT: Clone + Debug + Default + Serialize + DeserializeOwned {
    fn get_hash(&self) -> u64;
    fn has_post_execution(&self) -> bool;
    fn get_post_execution_needed_len(&self) -> usize;
    fn get_post_execution_pc(&self) -> usize;
    #[cfg(feature = "full_trace")]
    fn get_flashloan(&self) -> String;
    fn as_any(&self) -> &dyn std::any::Any;
}
