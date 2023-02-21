use crate::evm::FuzzHost;
use crate::input::{VMInput, VMInputT};
use libafl::corpus::{Corpus, Testcase};
use libafl::prelude::HasCorpus;
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
}

#[derive(Clone, Debug)]
pub enum MiddlewareOp {
    UpdateSlot(MiddlewareType, H160, U256, U256),
    UpdateCode(MiddlewareType, H160, Bytecode),
    AddCorpus(MiddlewareType, VMInput),
}

impl MiddlewareOp {
    pub fn execute(&self, host: &mut FuzzHost) {
        match self {
            MiddlewareOp::UpdateSlot(.., addr, slot, val) => {
                match host.data.get_mut(&addr) {
                    Some(data) => {
                        data.insert(*slot, *val);
                    }
                    None => {
                        let mut data = std::collections::HashMap::new();
                        data.insert(*slot, *val);
                        host.data.insert(*addr, data);
                    }
                }
            }
            MiddlewareOp::UpdateCode(.., addr, code) => {
                host.set_code(*addr, code.clone());
            }
            MiddlewareOp::AddCorpus(middleware, ..) => {
                host.middlewares_deferred_actions
                    .get_mut(middleware)
                    .expect("Middleware not found")
                    .push(self.clone());
            }
        }
    }

    pub fn execute_with_state<I, S, M>(&self, host: &mut FuzzHost, state: &mut S, middleware: M)
    where
        I: VMInputT + From<VMInput>,
        S: State + HasCorpus<I>,
        M: Middleware + CanHandleDeferredActions<S>,
    {
        middleware.handle_deferred_actions(self, state);
        // match self {
        //     MiddlewareOp::AddCorpus(input, ..) => {
        //         let mut tc = Testcase::new(input.clone());
        //         tc.set_exec_time(Duration::from_secs(0));
        //         let idx = state.corpus_mut().add(tc).expect("failed to add");
        //         // todo: add to corpus
        //         // scheduler
        //         //     .on_add(self, idx)
        //         //     .expect("failed to call scheduler on_add");
        //     }
        //     _ => {
        //         panic!("MiddlewareOp::execute_with_state called with invalid op");
        //     }
        // }
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
