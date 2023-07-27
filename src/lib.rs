#![feature(downcast_unchecked)]
#![feature(let_chains)]
#![feature(unchecked_math)]
extern crate core;

pub mod cache;
pub mod r#const;
pub mod evm;
pub mod executor;
pub mod feedback;
pub mod fuzzer;
pub mod fuzzers;
pub mod generic_vm;
pub mod indexed_corpus;
pub mod input;
mod r#move;
pub mod oracle;
pub mod scheduler;
pub mod state;
pub mod state_input;
pub mod telemetry;
pub mod tracer;
pub mod mutation_utils;