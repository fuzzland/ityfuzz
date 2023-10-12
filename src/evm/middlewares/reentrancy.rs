use std::collections::{HashMap, HashSet};
use std::fmt::{Debug};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::ops::AddAssign;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use bytes::Bytes;
use itertools::Itertools;
use libafl::inputs::Input;
use libafl::prelude::{HasCorpus, HasMetadata, State};
use libafl::schedulers::Scheduler;
use revm_interpreter::Interpreter;
use revm_interpreter::opcode::{INVALID, JUMPDEST, JUMPI, REVERT, STOP};
use revm_primitives::Bytecode;
use serde::{Serialize, Deserialize};
use crate::evm::host::FuzzHost;
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT};
use crate::evm::middlewares::middleware::{Middleware, MiddlewareType};
use crate::evm::srcmap::parser::{decode_instructions, pretty_print_source_map, pretty_print_source_map_single, SourceMapAvailability, SourceMapLocation, SourceMapWithCode};
use crate::evm::srcmap::parser::SourceMapAvailability::Available;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasItyState};
use crate::evm::types::{EVMAddress, is_zero, ProjectSourceMapTy, EVMU256};
use crate::evm::vm::{IN_DEPLOY, EVMState};
use serde_json;
use crate::evm::blaz::builder::ArtifactInfoMetadata;
use crate::evm::bytecode_iterator::{all_bytecode, walk_bytecode};

#[derive(Serialize, Debug, Clone)]
pub struct ReentrancyTracer;

impl ReentrancyTracer {
    pub fn new() -> Self {
        ReentrancyTracer {}
    }
}


#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ReentrancyData {
    pub reads: HashMap<(EVMAddress, EVMU256), Vec<u32>>,
    pub need_writes: HashMap<(EVMAddress, EVMU256), Vec<u32>>,
    pub found: HashSet<(EVMAddress, EVMU256)>,
}

fn merge_sorted_vec_dedup(dst: &mut Vec<u32>, another_one: &Vec<u32>) {
    // Create iterators for both vectors.
    let mut dst_iter = dst.iter();
    let mut another_iter = another_one.iter();

    // Holders for the next items from the iterators.
    let mut next_from_dst = dst_iter.next();
    let mut next_from_another = another_iter.next();

    // Prepare a new vector to hold the merged result.
    let mut merged = Vec::with_capacity(dst.len() + another_one.len());

    // Loop until both iterators are exhausted.
    while next_from_dst.is_some() || next_from_another.is_some() {
        // Determine the next value to push to the merged vector based on the current items from the iterators.
        match (next_from_dst, next_from_another) {
            (Some(&val_dst), Some(&val_another)) => {
                if val_dst < val_another {
                    merged.push(val_dst);
                    next_from_dst = dst_iter.next();
                } else if val_dst > val_another {
                    merged.push(val_another);
                    next_from_another = another_iter.next();
                } else {
                    // If equal, push one value and advance both iterators to avoid duplicates.
                    merged.push(val_dst);
                    next_from_dst = dst_iter.next();
                    next_from_another = another_iter.next();
                }
            },
            (Some(&val_dst), None) => {
                merged.push(val_dst);
                next_from_dst = dst_iter.next();
            },
            (None, Some(&val_another)) => {
                merged.push(val_another);
                next_from_another = another_iter.next();
            },
            (None, None) => break
        }
    }

    // Replace the contents of 'dst' with the 'merged' vector.
    *dst = merged;
}



// Reentrancy: Read, Read, Write
impl<I, VS, S, SC> Middleware<VS, I, S, SC> for ReentrancyTracer
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    VS: VMStateT,
    S: State
    + HasCaller<EVMAddress>
    + HasCorpus
    + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
    + HasMetadata
    + HasCurrentInputIdx
    + Debug
    + Clone,
    SC: Scheduler<State = S> + Clone,
{
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S, SC>,
        state: &mut S,
    ) {
        
        match *interp.instruction_pointer {
            0x54 => {
                let depth = host.evmstate.post_execution.len() as u32; 
                let slot_idx = interp.stack.peek(0).unwrap();

                // set up reads
                let entry = host.evmstate.reentrancy_metadata.reads.entry((interp.contract.address, slot_idx)).or_default();
                let total_size = entry.len();
                if total_size == 0 {
                    entry.push(depth);
                }
                let mut nth = 0;
                let mut should_insert = true;
                let mut found_smaller = Vec::new();

                // entry is sorted ascendingly
                for i in entry.iter() {
                    if *i == depth {
                        should_insert = false;
                        break;
                    }
                    if *i > depth {
                        break;
                    }
                    if *i < depth {
                        found_smaller.push(*i);
                    }
                    nth += 1;
                }
                if should_insert {
                    entry.insert(nth, depth);
                }

                // set up need writes
                if found_smaller.len() == 0 {
                    return;
                }
                let write_entry = host.evmstate.reentrancy_metadata.need_writes.entry((interp.contract.address, slot_idx)).or_default();
                merge_sorted_vec_dedup(write_entry, &found_smaller);
            }

            0x55 => {
                let depth = host.evmstate.post_execution.len() as u32; 
                let slot_idx = interp.stack.peek(0).unwrap();
                let write_entry = host.evmstate.reentrancy_metadata.need_writes.entry((interp.contract.address, slot_idx)).or_default();
                for i in write_entry.iter() {
                    if depth == *i {
                        // panic!("Reentrancy found at depth: {}, slot: {}", depth, slot_idx);
                        host.evmstate.reentrancy_metadata.found.insert((interp.contract.address, slot_idx));
                        return;
                    }
                }
            }
            _ => {}
        }
        
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::Reentrancy
    }

    unsafe fn before_execute(
        &mut self,
        interp: Option<&mut Interpreter>,
        host: &mut FuzzHost<VS, I, S, SC>,
        state: &mut S,
        is_step: bool,
        data: &mut Bytes,
        evm_state: &mut EVMState,
    ) { 
        if !is_step {
            return;
        }
        // otherwise, we clean up the writes and reads with depth larger than current depth
        let depth = evm_state.post_execution.len() as u32 - 1;
        for (_, depths) in &mut evm_state.reentrancy_metadata.need_writes {
            depths.retain(|&x| x <= depth);
        }
    }
}


mod test {
    use super::*;
    #[test]
    fn test_merge() {
        let mut vec1 = vec![1, 4, 5, 6, 7];
        let mut vec2 = vec![2, 3, 4, 6, 8, 10];
        merge_sorted_vec_dedup(&mut vec2, &vec1);
        assert_eq!(vec2, vec![1, 2, 3, 4, 5, 6, 7, 8, 10]);
    }
}

