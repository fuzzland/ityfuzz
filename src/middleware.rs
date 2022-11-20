use crate::evm::FuzzHost;
use crate::input::{VMInput, VMInputT};
use bytes::Bytes;
use libafl::corpus::{Corpus, Testcase};
use libafl::state::State;
use primitive_types::{H160, U256};
use revm::{Bytecode, Interpreter};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::clone::Clone;
use std::fmt::Debug;
use std::time::Duration;

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Copy)]
pub enum MiddlewareType {
    OnChain,
    Concolic,
    Flashloan,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Copy)]
pub enum ExecutionStage {
    Call,
    Create,
    Log,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallMiddlewareReturn {
    Continue,
    ReturnRevert,
    ReturnSuccess(Bytes),
}

#[derive(Clone, Debug)]
pub enum MiddlewareOp {
    UpdateSlot(MiddlewareType, H160, U256, U256),
    UpdateCode(MiddlewareType, H160, Bytecode),
    AddCorpus(MiddlewareType, VMInput),
    Owed(MiddlewareType, usize),
    Earned(MiddlewareType, usize),
    MakeSubsequentCallSuccess(Bytes),
}

impl MiddlewareOp {
    pub fn execute(&self, host: &mut FuzzHost) {
        match self {
            MiddlewareOp::UpdateSlot(.., addr, slot, val) => match host.data.get_mut(&addr) {
                Some(data) => {
                    data.insert(*slot, *val);
                }
                None => {
                    let mut data = std::collections::HashMap::new();
                    data.insert(*slot, *val);
                    host.data.insert(*addr, data);
                }
            },
            MiddlewareOp::UpdateCode(.., addr, code) => {
                host.set_code(*addr, code.clone());
            }
            MiddlewareOp::AddCorpus(middleware, ..)
            | MiddlewareOp::Owed(middleware, ..)
            | MiddlewareOp::Earned(middleware, ..) => {
                host.middlewares_deferred_actions
                    .get_mut(middleware)
                    .expect("Middleware not found")
                    .push(self.clone());
            }
            MiddlewareOp::MakeSubsequentCallSuccess(data) => {
                host.middlewares_latent_call_actions
                    .push(CallMiddlewareReturn::ReturnSuccess(data.clone()));
            }
        }
    }
}

pub trait CanHandleDeferredActions<S> {
    fn handle_deferred_actions(&self, op: &MiddlewareOp, state: &mut S);
}

pub trait Middleware: Debug {
    unsafe fn on_step(&mut self, interp: &mut Interpreter) -> Vec<MiddlewareOp>;
    fn get_type(&self) -> MiddlewareType;
    fn box_clone(&self) -> Box<dyn Middleware>;
    fn as_any(&mut self) -> &mut (dyn Any + 'static);
}
