use crate::generic_vm::vm_executor::GenericVM;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{FuzzState, HasItyState};
use crate::state_input::StagedVMState;
use hex;
use libafl::prelude::{tuple_list, HasCorpus, HasMetadata, SerdeAnyMap};
use libafl::state::State;
use std::marker::PhantomData;

pub struct OracleCtx<'a, VS, Addr, Code, By, Loc, SlotTy, I, S: 'static>
where
    I: VMInputT<VS, Addr>,
    VS: Default + VMStateT,
{
    pub fuzz_state: &'a S,
    pub pre_state: &'a VS,
    pub post_state: &'a VS,
    pub metadata: SerdeAnyMap,
    pub executor: &'a Box<dyn GenericVM<VS, Code, By, Loc, SlotTy, I, S>>,
    pub input: &'a I,
    pub phantom: PhantomData<(Addr)>,
}

impl<'a, VS, Addr, Code, By, Loc, SlotTy, I, S> OracleCtx<'a, VS, Addr, Code, By, Loc, SlotTy, I, S>
where
    I: VMInputT<VS, Addr> + 'static,
    S: State + HasCorpus<I> + HasMetadata,
    VS: Default + VMStateT,
{
    pub fn new(
        fuzz_state: &'a S,
        pre_state: &'a VS,
        post_state: &'a VS,
        executor: &'a Box<dyn GenericVM<VS, Code, By, Loc, SlotTy, I, S>>,
        input: &'a I,
    ) -> Self {
        Self {
            fuzz_state,
            pre_state,
            post_state,
            metadata: SerdeAnyMap::new(),
            executor,
            input,
            phantom: Default::default(),
        }
    }
    //
    // fn call_pre(&mut self, contract_address: H160, address: H160, data: Option<BoxedABI>) -> ExecutionResult {
    //     self.executor.execute(
    //         &VMInput {
    //             caller: address,
    //             contract: contract_address,
    //             data,
    //             sstate: StagedVMState {
    //                 state: self.pre_state.clone(),
    //                 stage: vec![],
    //                 initialized: false,
    //                 trace: Default::default()
    //             },
    //             sstate_idx: 0,
    //             txn_value: Some(0),
    //             step: false
    //         },
    //         None
    //     )
    // }
    //
    // fn call_post(&mut self, contract_address: H160, address: H160, data: Option<BoxedABI>) -> ExecutionResult {
    //     self.executor.execute(
    //         &VMInput {
    //             caller: address,
    //             contract: contract_address,
    //             data,
    //             sstate: StagedVMState {
    //                 state: self.post_state.clone(),
    //                 stage: vec![],
    //                 initialized: false,
    //                 trace: Default::default()
    //             },
    //             sstate_idx: 0,
    //             txn_value: Some(0),
    //             step: false
    //         },
    //         None
    //     )
    // }
}

pub trait Oracle<VS, Addr, Code, By, Loc, SlotTy, I, S>
where
    I: VMInputT<VS, Addr>,
    VS: Default + VMStateT,
{
    fn transition(
        &self,
        ctx: &mut OracleCtx<VS, Addr, Code, By, Loc, SlotTy, I, S>,
        stage: u64,
    ) -> u64;
    fn oracle(
        &self,
        ctx: &mut OracleCtx<VS, Addr, Code, By, Loc, SlotTy, I, S>,
        stage: u64,
    ) -> bool;
}
