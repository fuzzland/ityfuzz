use std::fmt::Debug;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{generic_vm::vm_state::VMStateT, input::ConciseSerde, state_input::StagedVMState};

pub const MAP_SIZE: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionResult<Loc, Addr, VS, Out, CI>
where
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug,
    Loc: Serialize + DeserializeOwned + Debug,
    Out: Default + Into<Vec<u8>> + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    pub output: Out,
    pub reverted: bool,
    #[serde(deserialize_with = "StagedVMState::deserialize")]
    pub new_state: StagedVMState<Loc, Addr, VS, CI>,
    pub additional_info: Option<Vec<u8>>,
}

impl<Loc, Addr, VS, Out, CI> ExecutionResult<Loc, Addr, VS, Out, CI>
where
    VS: Default + VMStateT + 'static,
    Addr: Serialize + DeserializeOwned + Debug,
    Loc: Serialize + DeserializeOwned + Debug,
    Out: Default + Into<Vec<u8>> + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    pub fn empty_result() -> Self {
        Self {
            output: Default::default(),
            reverted: false,
            new_state: StagedVMState::new_uninitialized(),
            additional_info: None,
        }
    }
}

pub trait GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI> {
    fn deploy(
        &mut self,
        code: Code,
        constructor_args: Option<By>,
        deployed_address: Addr,
        state: &mut S,
    ) -> Option<Addr>;
    fn execute(&mut self, input: &I, state: &mut S) -> ExecutionResult<Loc, Addr, VS, Out, CI>
    where
        VS: VMStateT,
        Addr: Serialize + DeserializeOwned + Debug,
        Loc: Serialize + DeserializeOwned + Debug,
        Out: Default + Into<Vec<u8>> + Clone,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static;

    fn fast_static_call(&mut self, data: &[(Addr, By)], vm_state: &VS, state: &mut S) -> Vec<Out>
    where
        VS: VMStateT,
        Addr: Serialize + DeserializeOwned + Debug,
        Loc: Serialize + DeserializeOwned + Debug,
        Out: Default + Into<Vec<u8>> + Clone;

    fn fast_call(&mut self, data: &[(Addr, Addr, By)], vm_state: &VS, state: &mut S) -> (Vec<(Out, bool)>, VS)
    where
        VS: VMStateT,
        Addr: Serialize + DeserializeOwned + Debug,
        Loc: Serialize + DeserializeOwned + Debug,
        Out: Default + Into<Vec<u8>> + Clone;

    // all these method should be implemented via a global variable, instead of
    // getting data from the `self`. `self` here is only to make the trait
    // object work.
    fn get_jmp(&self) -> &'static mut [u8; MAP_SIZE];
    fn get_read(&self) -> &'static mut [bool; MAP_SIZE];
    fn get_write(&self) -> &'static mut [u8; MAP_SIZE];
    fn get_cmp(&self) -> &'static mut [SlotTy; MAP_SIZE];
    fn state_changed(&self) -> bool;

    fn as_any(&mut self) -> &mut dyn std::any::Any;
}
