use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug};
use std::fs::OpenOptions;
use std::io::Write;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};
use itertools::Itertools;
use libafl::inputs::Input;
use libafl::prelude::{HasCorpus, HasMetadata, State};
use revm_interpreter::Interpreter;
use revm_interpreter::opcode::JUMPI;
use revm_primitives::Bytecode;
use crate::evm::host::FuzzHost;
use crate::evm::input::EVMInputT;
use crate::evm::middlewares::middleware::{Middleware, MiddlewareType};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasItyState};
use crate::evm::types::{as_u64, EVMAddress, EVMU256};


#[derive(Clone, Debug)]
pub struct Sha3TaintAnalysis {
    pub dirty_memory: Vec<bool>,
    pub dirty_storage: HashMap<EVMU256, bool>,
    pub dirty_stack: Vec<bool>,

    pub tainted_jumpi: HashSet<usize>
}


impl Sha3TaintAnalysis {
    pub fn new() -> Self {
        Self {
            dirty_memory: vec![],
            dirty_storage: HashMap::new(),
            dirty_stack: vec![],
            tainted_jumpi: HashSet::new()
        }
    }
}


impl<I, VS, S> Middleware<VS, I, S> for Sha3TaintAnalysis
    where
        I: Input + VMInputT<VS, EVMAddress, EVMAddress> + EVMInputT + 'static,
        VS: VMStateT,
        S: State
        + HasCaller<EVMAddress>
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS>
        + HasMetadata
        + HasCurrentInputIdx
        + Debug
        + Clone,
{
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S>,
        state: &mut S,
    ) {
        macro_rules! pop_push {
            ($pop_cnt: expr,$push_cnt: expr) => {
                {
                    let mut res = false;
                    for _ in 0..$pop_cnt {
                        res |= self.dirty_stack.pop().expect("stack is empty");
                    }
                    for _ in 0..$push_cnt {
                        self.dirty_stack.push(res);
                    }
                }
            };
        }

        macro_rules! stack_pop_n {
            ($pop_cnt: expr) => {
                for _ in 0..$pop_cnt {
                    self.dirty_stack.pop().expect("stack is empty");
                }
            }

        }

        macro_rules! push_false {
            () => {
                self.dirty_stack.push(false);
            };
        }

        macro_rules! ensure_size {
            ($t: expr, $size: expr) => {
                if $t.len() < $size {
                    $t.resize($size, false);
                }
            };
        }

        macro_rules! setup_mem {
            () => {
                {
                    stack_pop_n!(3);
                    let mem_offset = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                    let len = as_u64(interp.stack.peek(2).expect("stack is empty")) as usize;
                    ensure_size!(self.dirty_memory, mem_offset + len);
                    self.dirty_memory[mem_offset..mem_offset + len].copy_from_slice(vec![false; len as usize].as_slice());
                }
            };
        }



        match *interp.instruction_pointer {
            0x01..=0x7 => { pop_push!(2, 1) },
            0x08..=0x0a => { pop_push!(3, 1) },
            0x0b | 0x10..=0x14 => { pop_push!(2, 1); }
            0x16..=0x18 => { pop_push!(2, 1); }
            0x1a..=0x1d => { pop_push!(2, 1); }
            0x20 => {
                // sha3
                stack_pop_n!(2);
                self.dirty_stack.push(true);
            }
            0x30 => push_false!(),
            // ORIGIN
            0x32 =>  push_false!(),
            // CALLER
            0x33 =>  push_false!(),
            // CALLVALUE
            0x34 =>  push_false!(),
            // CALLDATASIZE
            0x36 => push_false!(),
            // CALLDATACOPY
            0x37 => setup_mem!(),
            // CODESIZE
            0x38 => push_false!(),
            // CODECOPY
            0x39 => setup_mem!(),
            // GASPRICE
            0x3a => push_false!(),
            // EXTCODECOPY
            0x3c => setup_mem!(),
            // RETURNDATASIZE
            0x3d => push_false!(),
            // RETURNDATACOPY
            0x3e => setup_mem!(),
            // COINBASE
            0x41..=0x48 => push_false!(),
            // POP
            0x50 => {
                self.dirty_stack.pop();
            }
            // MLOAD
            0x51 => {
                self.dirty_stack.pop();
                let mem_offset = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                ensure_size!(self.dirty_memory, mem_offset + 32);
                let is_dirty = self.dirty_memory[mem_offset..mem_offset + 32].iter().any(|x| *x);
                self.dirty_stack.push(is_dirty);
            }
            // MSTORE
            0x52 => {
                stack_pop_n!(1);
                let mem_offset = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                let is_dirty = self.dirty_stack.pop().expect("stack is empty");
                ensure_size!(self.dirty_memory, mem_offset + 256);
                self.dirty_memory[mem_offset..mem_offset + 256].copy_from_slice(vec![is_dirty; 256].as_slice());
            }
            // MSTORE8
            0x53 => {
                stack_pop_n!(1);
                let mem_offset = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                let is_dirty = self.dirty_stack.pop().expect("stack is empty");
                ensure_size!(self.dirty_memory, mem_offset + 32);
                self.dirty_memory[mem_offset..mem_offset + 32].copy_from_slice(vec![is_dirty; 32].as_slice());
            }
            // SLOAD
            0x54 => {
                self.dirty_stack.pop();
                let key = interp.stack.peek(0).expect("stack is empty");
                let is_dirty = self.dirty_storage.get(&key).unwrap_or(&false);
                self.dirty_stack.push(*is_dirty);
            }
            // SSTORE
            0x55 => {
                self.dirty_stack.pop();
                let is_dirty = self.dirty_stack.pop().expect("stack is empty");
                let key = interp.stack.peek(0).expect("stack is empty");
                self.dirty_storage.insert(key, is_dirty);
            }
            // JUMP
            0x56 => {
                self.dirty_stack.pop();
            }
            // JUMPI
            0x57 => {
                self.dirty_stack.pop();
                let v = self.dirty_stack.pop().expect("stack is empty");
                if v {
                    self.tainted_jumpi.insert(interp.program_counter());
                }
            }
            // PC
            0x58 | 0x59 | 0x5a => {
                push_false!();
            }
            // PUSH
            0x5f..=0x7f => {
                push_false!();
            }
            // DUP
            0x80..=0x8f => {
                let _n = (*interp.instruction_pointer) - 0x80 + 1;
                self.dirty_stack.push(self.dirty_stack[self.dirty_stack.len() - _n as usize]);
            }
            // SWAP
            0x90..=0x9f => {
                let _n = (*interp.instruction_pointer) - 0x90 + 2;
                let _l = self.dirty_stack.len();
                let tmp = self.dirty_stack[_l - _n as usize];
                self.dirty_stack[_l - _n as usize] = self.dirty_stack[_l - 1];
                self.dirty_stack[_l - 1] = tmp;
            }
            // LOG
            0xa0..=0xa4 => {
                let _n = (*interp.instruction_pointer) - 0xa0 + 2;
                stack_pop_n!(_n);
            }
            0xf0 => {
                pop_push!(3, 1);
            }
            0xf1 => {
                pop_push!(7, 1);
            }
            0xf2 => {
                pop_push!(7, 1);
            }
            0xf3 => {
                stack_pop_n!(2);
            }
            0xf4 => {
                pop_push!(6, 1);
            }
            0xf5 => {
                pop_push!(4, 1);
            }
            0xfa => {
                pop_push!(6, 1);
            }
            0xfd => {
                pop_push!(2, 0);
            }
            0xff => {
                stack_pop_n!(1);
            }
            _ => {}

        }
    }

    unsafe fn on_insert(&mut self, bytecode: &mut Bytecode, address: EVMAddress, host: &mut FuzzHost<VS, I, S>, state: &mut S) {
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::Sha3TaintAnalysis
    }
}


#[derive(Debug)]
pub struct Sha3Bypass {
    pub sha3_taints: Rc<RefCell<Sha3TaintAnalysis>>,
}

impl Sha3Bypass {
    pub fn new(sha3_taints: Rc<RefCell<Sha3TaintAnalysis>>) -> Self {
        Self {
            sha3_taints,
        }
    }
}


impl<I, VS, S> Middleware<VS, I, S> for Sha3Bypass
    where
        I: Input + VMInputT<VS, EVMAddress, EVMAddress> + EVMInputT + 'static,
        VS: VMStateT,
        S: State
        + HasCaller<EVMAddress>
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS>
        + HasMetadata
        + HasCurrentInputIdx
        + Debug
        + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<VS, I, S>, state: &mut S) {
        if *interp.instruction_pointer == JUMPI {
            let jumpi = interp.program_counter();
            if self.sha3_taints.borrow().tainted_jumpi.contains(&jumpi) {
                let stack_len = interp.stack.len();
                interp.stack.data[stack_len - 2] = EVMU256::from((jumpi + host.randomness[0] as usize) % 2);
            }
        }
    }

    unsafe fn on_insert(&mut self, bytecode: &mut Bytecode, address: EVMAddress, host: &mut FuzzHost<VS, I, S>, state: &mut S) {
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::Sha3Bypass
    }
}


mod tests {
    use std::cell::RefCell;
    use std::path::Path;
    use std::rc::Rc;
    use std::sync::Arc;
    use bytes::Bytes;
    use libafl::schedulers::StdScheduler;
    use revm_interpreter::analysis::to_analysed;
    use revm_interpreter::BytecodeLocked;
    use revm_interpreter::opcode::{ADD, EQ, JUMPDEST, JUMPI, MSTORE, PUSH0, PUSH1, SHA3, STOP};
    use crate::evm::input::{EVMInput, EVMInputTy};
    use crate::evm::mutator::AccessPattern;
    use crate::evm::types::{EVMFuzzState, generate_random_address};
    use crate::evm::vm::{EVMExecutor, EVMState};
    use crate::generic_vm::vm_executor::GenericVM;
    use crate::state::FuzzState;
    use crate::state_input::StagedVMState;
    use super::*;

    fn execute(bys: Bytes, code: Bytes) -> Vec<usize> {
        let mut state: EVMFuzzState = FuzzState::new(0);
        let path = Path::new("work_dir");
        if !path.exists() {
            std::fs::create_dir(path);
        }
        let mut evm_executor: EVMExecutor<EVMInput, EVMFuzzState, EVMState> = EVMExecutor::new(
            FuzzHost::new(Arc::new(StdScheduler::new()), "work_dir".to_string()),
            generate_random_address(&mut state),
        );

        let target_addr = generate_random_address(&mut state);
        evm_executor.host.code.insert(
            target_addr.clone(),
            Arc::new(BytecodeLocked::try_from(
                to_analysed(Bytecode::new_raw(code))
            ).unwrap()),
        );

        let sha3 = Rc::new(RefCell::new(Sha3TaintAnalysis::new()));
        evm_executor.host.add_middlewares(sha3.clone());

        let input = EVMInput {
            caller: generate_random_address(&mut state),
            contract: target_addr,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            #[cfg(feature = "flashloan_v2")]
            liquidation_percent: 0,
            direct_data: bys,
            #[cfg(feature = "flashloan_v2")]
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
        };

        let res = evm_executor.execute(&input, &mut state);
        assert!(!res.reverted);
        return sha3.borrow().tainted_jumpi.iter().cloned().collect_vec();
    }

    #[test]
    fn test_hash_none() {
        let bys = vec![
            PUSH1, 0x2,
            PUSH0,
            ADD, // stack = [2]
            PUSH1, 0x7, // stack = [2, 7]
            JUMPI,
            JUMPDEST,
            STOP
        ];
        let taints = execute(
            Bytes::new(),
            Bytes::from(bys)
        );
        assert_eq!(taints.len(), 0);
    }

    #[test]
    fn test_hash_simple() {
        let bys = vec![
            PUSH0,
            PUSH1, 0x42,
            MSTORE,
            PUSH0,
            PUSH1, 0x1,
            SHA3,
            PUSH1, 0x2,
            EQ,
            PUSH1, 0xe,
            JUMPI,
            JUMPDEST,
            STOP
        ];
        let taints = execute(
            Bytes::new(),
            Bytes::from(bys)
        );
        assert_eq!(taints.len(), 1);
        assert_eq!(taints[0], 0xd);
    }


    #[test]
    fn test_hash_simple_none() {
        let bys = vec![
            PUSH0,
            PUSH1, 0x42,
            MSTORE,
            PUSH0,
            PUSH1, 0x1,
            SHA3,
            PUSH1, 0x2,
            EQ,
            PUSH0,
            PUSH1, 0xf,
            JUMPI,
            JUMPDEST,
            STOP
        ];
        let taints = execute(
            Bytes::new(),
            Bytes::from(bys)
        );
        assert_eq!(taints.len(), 0);
    }

    #[test]
    fn test_hash_complex_1() {
        // contract Test {
        //     mapping (uint256=>bytes32) a;
        //
        //     fallback(bytes calldata x) external payable returns (bytes memory) {
        //         a[1] = keccak256(x);
        //
        //         if (a[1] == hex"cccc") {
        //             return "cccc";
        //         } else {
        //             return "dddd";
        //         }
        //     }
        // }
        let taints = execute(
            Bytes::new(),
            Bytes::from(hex::decode("608060405260003660608282604051610019929190610132565b604051809103902060008060018152602001908152602001600020819055507fcccc0000000000000000000000000000000000000000000000000000000000006000806001815260200190815260200160002054036100af576040518060400160405280600481526020017f636363630000000000000000000000000000000000000000000000000000000081525090506100e8565b6040518060400160405280600481526020017f646464640000000000000000000000000000000000000000000000000000000081525090505b915050805190602001f35b600081905092915050565b82818337600083830152505050565b600061011983856100f3565b93506101268385846100fe565b82840190509392505050565b600061013f82848661010d565b9150819050939250505056fea26469706673582212200b9b2e1716d1b88774664613e1e244bbf62489a4aded40c5a9118d1f302068e364736f6c63430008130033").unwrap())
        );
        assert_eq!(taints.len(), 1);
        println!("{:?}", taints);
    }

    #[test]
    fn test_hash_complex_2() {
        // contract Test {
        //     mapping (uint256=>bytes32) a;
        //
        //     fallback(bytes calldata x) external payable returns (bytes memory) {
        //         a[1] = keccak256(x);
        //         a[1] = hex"cccc";
        //
        //         if (a[1] == hex"cccc") {
        //             return "cccc";
        //         } else {
        //             return "dddd";
        //         }
        //     }
        // }
        let taints = execute(
            Bytes::new(),
            Bytes::from(hex::decode("60806040526000366060828260405161001992919061016a565b604051809103902060008060018152602001908152602001600020819055507fcccc00000000000000000000000000000000000000000000000000000000000060008060018152602001908152602001600020819055507fcccc0000000000000000000000000000000000000000000000000000000000006000806001815260200190815260200160002054036100e7576040518060400160405280600481526020017f63636363000000000000000000000000000000000000000000000000000000008152509050610120565b6040518060400160405280600481526020017f646464640000000000000000000000000000000000000000000000000000000081525090505b915050805190602001f35b600081905092915050565b82818337600083830152505050565b6000610151838561012b565b935061015e838584610136565b82840190509392505050565b6000610177828486610145565b9150819050939250505056fea2646970667358221220be5565ccdf8b6a6e6c8b6d9113d6643155245741374ccd9bac3a434cff27515f64736f6c63430008130033").unwrap())
        );
        assert_eq!(taints.len(), 0);
    }

    #[test]
    fn test_hash_complex_3() {
        // contract Test {
        //     mapping (uint256=>bytes32) a;
        //
        //     fallback(bytes calldata x) external payable returns (bytes memory) {
        //         a[1] = keccak256(x);
        //         a[2] = a[1] ^ hex"aaaa";
        //
        //         if (uint(a[2]) + 123 > 1) {
        //             return "cccc";
        //         } else {
        //             return "dddd";
        //         }
        //     }
        // }
        let taints = execute(
            Bytes::new(),
            Bytes::from(hex::decode("608060405260003660608282604051610019929190610170565b604051809103902060008060018152602001908152602001600020819055507faaaa00000000000000000000000000000000000000000000000000000000000060008060018152602001908152602001600020541860008060028152602001908152602001600020819055506001607b600080600281526020019081526020016000205460001c6100aa91906101c2565b11156100ed576040518060400160405280600481526020017f63636363000000000000000000000000000000000000000000000000000000008152509050610126565b6040518060400160405280600481526020017f646464640000000000000000000000000000000000000000000000000000000081525090505b915050805190602001f35b600081905092915050565b82818337600083830152505050565b60006101578385610131565b935061016483858461013c565b82840190509392505050565b600061017d82848661014b565b91508190509392505050565b6000819050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006101cd82610189565b91506101d883610189565b92508282019050808211156101f0576101ef610193565b5b9291505056fea26469706673582212204d99e1e8876b38e211054a692fb1e98d19a40c8ef970e16a43602abed56a693164736f6c63430008130033").unwrap())
        );
        println!("{:?}", taints);
        assert_eq!(taints.len(), 2);
    }
}
