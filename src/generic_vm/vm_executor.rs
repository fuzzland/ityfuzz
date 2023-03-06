use std::fmt::Debug;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state_input::StagedVMState;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;

pub const MAP_SIZE: usize = 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionResult<Loc, Addr, VS>
where
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug,
    Loc: Serialize + DeserializeOwned + Debug,
{
    pub output: Vec<u8>,
    pub reverted: bool,
    #[serde(deserialize_with = "StagedVMState::deserialize")]
    pub new_state: StagedVMState<Loc, Addr, VS>,
}

impl<Loc, Addr, VS> ExecutionResult<Loc, Addr, VS>
where
    VS: Default + VMStateT + 'static,
    Addr: Serialize + DeserializeOwned + Debug,
    Loc: Serialize + DeserializeOwned + Debug,
{
    pub fn empty_result() -> Self {
        Self {
            output: vec![],
            reverted: false,
            new_state: StagedVMState::new_uninitialized(),
        }
    }
}

pub trait GenericVM<VS, Code, By, Loc, Addr, SlotTy, I, S> {
    fn deploy(
        &mut self,
        code: Code,
        constructor_args: Option<By>,
        deployed_address: Addr,
    ) -> Option<Addr>;
    fn execute(&mut self, input: &I, state: Option<&mut S>) -> ExecutionResult<Loc, Addr, VS>
    where
        VS: VMStateT,
        Addr: Serialize + DeserializeOwned + Debug,
        Loc: Serialize + DeserializeOwned + Debug;

    // all these method should be implemented via a global variable, instead of getting data from
    // the `self`. `self` here is only to make the trait object work.
    fn get_jmp(&self) -> &'static mut [u8; MAP_SIZE];
    fn get_read(&self) -> &'static mut [bool; MAP_SIZE];
    fn get_write(&self) -> &'static mut [u8; MAP_SIZE];
    fn get_cmp(&self) -> &'static mut [SlotTy; MAP_SIZE];
    fn state_changed(&self) -> bool;
}
