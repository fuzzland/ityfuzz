use revm::Interpreter;
use serde::{Deserialize, Serialize};
use std::clone::Clone;
use std::fmt::Debug;

pub trait Middleware:
    Debug + serde_traitobject::Serialize + serde_traitobject::Deserialize
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter);
}
