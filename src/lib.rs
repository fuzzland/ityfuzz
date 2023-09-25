#![feature(downcast_unchecked)]
#![feature(let_chains)]
#![feature(unchecked_math)]
#![feature(trait_alias)]

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
pub mod oracle;
pub mod scheduler;
pub mod state;
pub mod state_input;
pub mod tracer;
pub mod mutation_utils;


#[cfg(feature = "sui_support")]
pub mod r#move;