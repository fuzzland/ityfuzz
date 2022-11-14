use crate::evm::FuzzHost;
use primitive_types::{H160, U256};
use revm::{Bytecode, Interpreter};
use serde::{Deserialize, Serialize};
use std::clone::Clone;
use std::fmt::Debug;

#[derive(Clone, Debug)]
pub enum MiddlewareOp {
    UpdateSlot(H160, U256, U256),
    UpdateCode(H160, Bytecode),
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
        }
    }
}

pub trait Middleware: Debug {
    unsafe fn on_step(&mut self, interp: &mut Interpreter) -> Vec<MiddlewareOp>;
}
