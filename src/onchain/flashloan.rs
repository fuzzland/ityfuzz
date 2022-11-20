// on_call
// when approval, balanceof, give 2000e18 token
// when transfer, transferFrom, and src is our, return success, add owed
// when transfer, transferFrom, and src is not our, return success, reduce owed

use crate::middleware::{CanHandleDeferredActions, Middleware, MiddlewareOp, MiddlewareType};
use bytes::Bytes;
use libafl::impl_serdeany;
use libafl::prelude::State;
use libafl::state::HasMetadata;
use primitive_types::U256;
use revm::Interpreter;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fmt::Debug;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct Flashloan<S> {
    phantom: PhantomData<S>,
}

impl<S> Middleware for Flashloan<S>
where
    S: State + Debug + Clone + 'static,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter) -> Vec<MiddlewareOp> {
        let offset_of_arg_offset: usize = match *interp.instruction_pointer {
            0xf1 | 0xf2 => 3,
            0xf4 | 0xfa => 2,
            _ => {
                return vec![];
            }
        };
        let offset = interp.stack.peek(offset_of_arg_offset).unwrap();
        let size = interp.stack.peek(offset_of_arg_offset + 1).unwrap();
        if size < U256::from(4) {
            return vec![];
        }
        let data = interp.memory.get_slice(offset.as_usize(), 4);

        match data {
            // balanceOf
            [0x70, 0xa0, 0x82, 0x31] => {
                vec![MiddlewareOp::MakeSubsequentCallSuccess(Bytes::from(
                    vec![0xff; 32],
                ))]
            }
            _ => {
                vec![]
            }
        }
    }

    fn get_type(&self) -> MiddlewareType {
        return MiddlewareType::Flashloan;
    }

    fn box_clone(&self) -> Box<dyn Middleware> {
        return Box::new(self.clone());
    }

    fn as_any(&mut self) -> &mut (dyn Any + 'static) {
        return self;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlashloanData {
    pub owed: U256,
    pub earned: U256,
}

impl_serdeany!(FlashloanData);

impl<S> CanHandleDeferredActions<S> for Flashloan<S>
where
    S: HasMetadata,
{
    fn handle_deferred_actions(&self, op: &MiddlewareOp, state: &mut S) {
        // todo(shou): move init to else where to avoid overhead
        if !state.has_metadata::<FlashloanData>() {
            state.add_metadata(FlashloanData {
                owed: U256::from(0),
                earned: U256::from(0),
            });
        }
        match op {
            MiddlewareOp::Owed(.., amount) => {
                let mut data = state.metadata_mut().get_mut::<FlashloanData>();
                data.as_mut().unwrap().owed += U256::from(*amount);
            }
            MiddlewareOp::Earned(.., amount) => {
                let mut data = state.metadata_mut().get_mut::<FlashloanData>();
                data.as_mut().unwrap().earned += U256::from(*amount);
            }
            _ => {}
        }
    }
}
