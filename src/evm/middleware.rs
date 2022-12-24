use crate::evm::vm::{FuzzHost, IntermediateExecutionResult};
use crate::input::VMInputT;
use bytes::Bytes;
use libafl::corpus::{Corpus, Testcase};
use libafl::state::State;
use primitive_types::{H160, U256, U512};
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
    AddCorpus(MiddlewareType, String, H160),
    AddCaller(MiddlewareType, H160),
    AddAddress(MiddlewareType, H160),
    AddBlacklist(MiddlewareType, H160),
    Owed(MiddlewareType, U512),
    Earned(MiddlewareType, U512),
    MakeSubsequentCallSuccess(Bytes),
}

impl MiddlewareOp {
    pub fn execute(&self, host: &mut FuzzHost) {
        match self {
            MiddlewareOp::UpdateSlot(.., addr, slot, val) => match host.data.get_mut(&addr) {
                Some(data) => {
                    if data.get(&slot).is_none() {
                        data.insert(*slot, *val);
                    }
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
            MiddlewareOp::AddCaller(middleware, addr) => {
                // todo: find a better way to handle this
                // this ensures that a newly inserted address by flashloan V2 is never fetched as contract again
                host.middlewares_deferred_actions
                    .get_mut(&MiddlewareType::OnChain)
                    .expect("Middleware not found")
                    .push(MiddlewareOp::AddBlacklist(MiddlewareType::OnChain, addr.clone()));
                host.middlewares_deferred_actions
                    .get_mut(middleware)
                    .expect("Middleware not found")
                    .push(self.clone());
            }
            MiddlewareOp::AddAddress(middleware, addr) => {
                host.middlewares_deferred_actions
                    .get_mut(&MiddlewareType::OnChain)
                    .expect("Middleware not found")
                    .push(MiddlewareOp::AddBlacklist(MiddlewareType::OnChain, addr.clone()));
                host.middlewares_deferred_actions
                    .get_mut(middleware)
                    .expect("Middleware not found")
                    .push(self.clone());
            }
            MiddlewareOp::AddBlacklist(middleware, ..) => {
                host.middlewares_deferred_actions
                    .get_mut(middleware)
                    .expect("Middleware not found")
                    .push(self.clone());
            }
        }
    }
}

pub trait CanHandleDeferredActions<VS, S> {
    fn handle_deferred_actions(
        &mut self,
        op: &MiddlewareOp,
        state: &mut S,
        result: &mut IntermediateExecutionResult,
    );
}

pub trait Middleware: Debug {
    unsafe fn on_step(&mut self, interp: &mut Interpreter) -> Vec<MiddlewareOp>;
    fn get_type(&self) -> MiddlewareType;
    fn as_any(&mut self) -> &mut (dyn Any + 'static);
}
