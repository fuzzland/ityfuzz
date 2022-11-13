use revm::Interpreter;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::clone::Clone;

pub trait Middleware: Debug + serde_traitobject::Serialize + serde_traitobject::Deserialize {
    unsafe fn on_step(&mut self, interp: &mut Interpreter);
}