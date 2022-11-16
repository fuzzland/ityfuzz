use crate::evm::FuzzHost;
use crate::input::{VMInput, VMInputT};
use libafl::corpus::{Corpus, Testcase};
use libafl::prelude::HasCorpus;
use libafl::state::State;
use primitive_types::{H160, U256};
use revm::{Bytecode, Interpreter};
use serde::{Deserialize, Serialize};
use std::clone::Clone;
use std::fmt::Debug;
use std::time::Duration;

#[derive(Clone, Debug)]
pub enum MiddlewareOp {
    UpdateSlot(H160, U256, U256),
    UpdateCode(H160, Bytecode),
    AddCorpus(VMInput),
}

impl MiddlewareOp {
    pub fn execute(&self, host: &mut FuzzHost) {
        match self {
            MiddlewareOp::UpdateSlot(addr, slot, val) => {
                host.data.get_mut(&addr).unwrap().insert(*slot, *val);
            }
            MiddlewareOp::UpdateCode(addr, code) => {
                host.set_code(*addr, code.clone());
            }
            _ => {
                host.middlewares_deferred_actions.push(self.clone());
            }
        }
    }

    pub fn execute_with_state<I, S>(&self, host: &mut FuzzHost, state: &mut S)
    where
        I: VMInputT + From<VMInput>,
        S: State + HasCorpus<I>,
    {
        match self {
            MiddlewareOp::AddCorpus(input) => {
                let mut tc = Testcase::new(input.clone());
                tc.set_exec_time(Duration::from_secs(0));
                let idx = state.corpus_mut().add(tc).expect("failed to add");
                // todo: add to corpus
                // scheduler
                //     .on_add(self, idx)
                //     .expect("failed to call scheduler on_add");
            }
            _ => {
                panic!("MiddlewareOp::execute_with_state called with invalid op");
            }
        }
    }
}

pub trait Middleware: Debug {
    unsafe fn on_step(&mut self, interp: &mut Interpreter) -> Vec<MiddlewareOp>;
}
