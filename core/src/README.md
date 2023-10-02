# Description
This directory contains source code of the project.

# Workflow
todo


# Structure

Folders: 
- `generic_vm` - traits representing VM of any smart contracts
- `evm` - Implementation of `generic_vm` for Ethereum Virtual Machine using revm. 
- `move` - Implementation of `generic_vm` for MoveVM.
- `fuzzers` - Definition of fuzzers for each VM.

Files:
- `executor.rs` - definition of `Executor` trait from LibAFL.
- `feedback.rs` - definition of `Feedback` trait from LibAFL for collecting and analyzing feedback like coverage and comparison.
- `indexed_corpus.rs` - just a corpus that has self-increment ID for each testcase.
- `input.rs` - definition of `Input` trait from LibAFL.
- `oracle.rs` - definition of `Oracle` trait.
- `scheduler.rs` - definition of `Scheduler` trait from LibAFL, implements infant scheduler proposed in paper.
- `state.rs` - definition of `State` trait from LibAFL that supports infant corpus proposed in paper.
- `state_input.rs` - implementation of `Input` trait for VM states.
- `tracer.rs` - traces of the snapshot of the state, used for regenerating the transactions leading to the VM state.

Utils:
- `rand_utils.rs` - random utilities.
- `types.rs` - utilities for type conversion.
- `telemetry.rs` - utilities for reporting fuzzing campaign telemetry information.
- `const.rs` - constants used in the project.

