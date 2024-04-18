use std::{
    any,
    collections::{HashMap, HashSet},
    fmt::Debug,
};

use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::Interpreter;
use serde::{Deserialize, Serialize};

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::{EVMAddress, EVMFuzzState, EVMU256},
    vm::EVMState,
};

#[derive(Serialize, Debug, Clone, Default)]
pub struct ReentrancyTracer;

impl ReentrancyTracer {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ReentrancyData {
    pub reads: HashMap<(EVMAddress, EVMU256), Vec<u32>>,
    pub need_writes: HashMap<(EVMAddress, EVMU256), Vec<u32>>,
    pub found: HashSet<(EVMAddress, EVMU256)>,
}

fn merge_sorted_vec_dedup(dst: &mut Vec<u32>, another_one: &[u32]) {
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
        // Determine the next value to push to the merged vector based on the current
        // items from the iterators.
        match (next_from_dst, next_from_another) {
            (Some(&val_dst), Some(&val_another)) if val_dst < val_another => {
                merged.push(val_dst);
                next_from_dst = dst_iter.next();
            }
            (Some(&val_dst), Some(&val_another)) if val_dst > val_another => {
                merged.push(val_another);
                next_from_another = another_iter.next();
            }
            (Some(&val_dst), Some(_val_another)) => {
                // If equal, push one value and advance both iterators to avoid duplicates.
                merged.push(val_dst);
                next_from_dst = dst_iter.next();
                next_from_another = another_iter.next();
            }
            (Some(&val_dst), None) => {
                merged.push(val_dst);
                next_from_dst = dst_iter.next();
            }
            (None, Some(&val_another)) => {
                merged.push(val_another);
                next_from_another = another_iter.next();
            }
            (None, None) => break,
        }
    }

    // Replace the contents of 'dst' with the 'merged' vector.
    *dst = merged;
}

// Reentrancy: Read, Read, Write
impl<SC> Middleware<SC> for ReentrancyTracer
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) {
        match *interp.instruction_pointer {
            0x54 => {
                let depth = host.evmstate.post_execution.len() as u32;
                let slot_idx = interp.stack.peek(0).unwrap();

                // set up reads
                let entry = host
                    .evmstate
                    .reentrancy_metadata
                    .reads
                    .entry((interp.contract.address, slot_idx))
                    .or_default();

                let mut found_smaller = Vec::new();
                // entry is sorted ascendingly
                for (idx, element) in entry.iter().enumerate() {
                    match element.cmp(&depth) {
                        std::cmp::Ordering::Less => {
                            found_smaller.push(*element);
                        }
                        std::cmp::Ordering::Equal => {
                            break;
                        }
                        std::cmp::Ordering::Greater => {
                            entry.insert(idx, depth);
                            break;
                        }
                    }
                }
                if entry.is_empty() || *entry.last().unwrap() < depth {
                    entry.push(depth);
                }

                // set up need writes
                if found_smaller.is_empty() {
                    return;
                }
                let write_entry = host
                    .evmstate
                    .reentrancy_metadata
                    .need_writes
                    .entry((interp.contract.address, slot_idx))
                    .or_default();
                merge_sorted_vec_dedup(write_entry, &found_smaller);
            }

            0x55 => {
                let depth = host.evmstate.post_execution.len() as u32;
                let slot_idx = interp.stack.peek(0).unwrap();
                let write_entry = host
                    .evmstate
                    .reentrancy_metadata
                    .need_writes
                    .entry((interp.contract.address, slot_idx))
                    .or_default();
                for i in write_entry.iter() {
                    if depth == *i {
                        // panic!("Reentrancy found at depth: {}, slot: {}", depth, slot_idx);
                        host.evmstate
                            .reentrancy_metadata
                            .found
                            .insert((interp.contract.address, slot_idx));
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

    #[allow(unused_variables)]
    unsafe fn before_execute(
        &mut self,
        interp: Option<&mut Interpreter>,
        host: &mut FuzzHost<SC>,
        state: &mut EVMFuzzState,
        is_step: bool,
        data: &mut Bytes,
        evm_state: &mut EVMState,
    ) {
        if !is_step {
            return;
        }
        // otherwise, we clean up the writes and reads with depth larger than current
        // depth
        let depth = evm_state.post_execution.len() as u32 - 1;
        evm_state
            .reentrancy_metadata
            .need_writes
            .iter_mut()
            .for_each(|(_, depths)| {
                depths.retain(|&x| x <= depth);
            });
    }
    fn as_any(&self) -> &dyn any::Any {
        self
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_merge() {
        let vec1 = vec![1, 4, 5, 6, 7];
        let mut vec2 = vec![2, 3, 4, 6, 8, 10];
        merge_sorted_vec_dedup(&mut vec2, &vec1);
        assert_eq!(vec2, vec![1, 2, 3, 4, 5, 6, 7, 8, 10]);
    }
}
