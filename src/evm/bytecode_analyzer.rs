/// Analysis passes for EVM bytecode

use crate::mutation_utils::ConstantPoolMetadata;
use libafl::state::{HasMetadata, State};

use revm_primitives::Bytecode;
use std::collections::HashSet;

/// Find all constants in the bytecode by observing PUSH instructions.
///
/// Check tests below for usage.
pub fn find_constants(bytecode: &Bytecode) -> HashSet<Vec<u8>> {
    let mut idx = 0;
    let bytecode_len = bytecode.len();
    let mut constants = HashSet::new();
    let bytes = bytecode.bytes();
    loop {
        if idx >= bytecode_len {
            break;
        }
        let op = bytes[idx];

        match op {
            // hook all PUSH instruction
            0x60..=0x7f => {
                // get next opcode
                let next_op = if idx + op as usize - 0x5e < bytecode_len {
                    Some(bytes[idx + op as usize - 0x5e])
                } else {
                    None
                };

                if bytecode_len < idx + op as usize - 0x5e {
                    // we get inside padding bytecode
                    break;
                }
                // check if next opcode is JUMPI
                let should_skip = match next_op {
                    Some(next_op) => {
                        if next_op == 0x57 {
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                };

                // next op is not JUMPI
                if !should_skip {
                    // sufficient long
                    if op as usize - 0x60 + 1 >= 2 {
                        let mut data = vec![0u8; op as usize - 0x60 + 1];
                        let mut i = 0;
                        while i < op - 0x60 + 1 {
                            let offset = i as usize;
                            data[offset] = bytes[idx + offset + 1];
                            i += 1;
                        }
                        constants.insert(data);
                    }
                }
                idx += op as usize - 0x5e;
            }
            _ => {
                idx += 1;
            }
        }
    }
    constants
}

/// Add constants in smart contract to the global state's [`ConstantPoolMetadata`]
/// this can be costly, ensure sampling to be cheap
pub fn add_analysis_result_to_state<S>(bytecode: &Bytecode, state: &mut S)
where
    S: HasMetadata + State,
{
    let constants = find_constants(bytecode);
    match state.metadata_mut().get_mut::<ConstantPoolMetadata>() {
        Some(meta) => {
            for constant in constants {
                if !meta.constants.contains(&constant) {
                    meta.constants.push(constant);
                }
            }
        }
        None => {
            state.metadata_mut().insert(ConstantPoolMetadata {
                constants: constants.into_iter().collect(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use revm_primitives::Bytecode;

    #[test]
    fn test_find_constants() {
        let bytecode = Bytecode::new_raw(Bytes::from(
            hex::decode("73ccef237d1d745fba9114a4c8c7c1effb9edc87d830146080604052600080fdfea26469706673582212205377adc79bb987de03049c655529acbf51a3f7d36bb14c89a2d2f790fee54d6064736f6c63430008110033").unwrap()
        ));
        let constants = find_constants(&bytecode);
        println!(
            "{:?}",
            constants
                .iter()
                .map(|x| hex::encode(x))
                .collect::<Vec<String>>()
        );
    }
}
