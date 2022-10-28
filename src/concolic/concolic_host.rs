use crate::evm::ExecutionResult;
use bytes::Bytes;
use primitive_types::{H160, H256, U256};
use revm::db::BenchmarkDB;
use revm::Return::Continue;
use revm::{
    Bytecode, CallInputs, CreateInputs, Env, Gas, Host, Interpreter, Return, SelfDestructResult,
    Spec,
};
use std::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;
use std::ops::{Add, Mul, Sub};
use std::str::FromStr;
use z3::ast::{Bool, BV};
use z3::{ast, ast::Ast, Config, Context, Solver};

pub struct ConcolicHost<'a> {
    env: Env,
    data: HashMap<H160, HashMap<U256, U256>>,
    code: HashMap<H160, Bytecode>,
    solver: Solver<'a>,
    ctx: Context,
    symbolic_stack: Vec<Option<BV<'a>>>,
    shadow_inputs: Option<BV<'a>>,
    bits: u32,
}

impl<'a> ConcolicHost<'a> {
    pub fn new(solver: Solver<'a>, ctx: Context, bytes: u32) -> Self {
        Self {
            env: Env::default(),
            data: HashMap::new(),
            code: HashMap::new(),
            solver,
            ctx,
            symbolic_stack: Vec::new(),
            shadow_inputs: None,
            bits: 8 * bytes,
        }
    }

    pub fn set_shadow_inputs(&'a mut self) {
        self.shadow_inputs = Some(BV::new_const(&self.ctx, "shadow_inputs", self.bits));
    }

    // pub fn get_bv_from_stack(&self, index: usize, interp: &mut Interpreter) -> BV {
    //
    // }

    pub unsafe fn on_step(&'a mut self, interp: &mut Interpreter) {
        // println!("{}", *interp.instruction_pointer);
        macro_rules! bv_from_u256 {
            ($val:expr) => {{
                let u64x4 = $val.0;
                let bv = BV::from_u64(&self.ctx, u64x4[0], 64);
                let bv = bv.concat(&BV::from_u64(&self.ctx, u64x4[1], 64));
                let bv = bv.concat(&BV::from_u64(&self.ctx, u64x4[2], 64));
                let bv = bv.concat(&BV::from_u64(&self.ctx, u64x4[3], 64));
                bv
            }};
        }
        macro_rules! stack_bv {
            ($idx:expr) => {{
                match self.symbolic_stack[$idx].borrow() {
                    Some(bv) => bv.clone(),
                    None => {
                        let u256 = interp.stack.peek($idx).expect("stack underflow");
                        bv_from_u256!(u256)
                    }
                }
            }};
        }

        let bv = match *interp.instruction_pointer {
            // ADD
            0x01 => {
                vec![Some(stack_bv!(0).add(stack_bv!(1)))]
            }
            // MUL
            0x02 => {
                vec![Some(stack_bv!(0).mul(stack_bv!(1)))]
            }
            // SUB
            0x03 => {
                vec![Some(stack_bv!(0).sub(stack_bv!(1)))]
            }
            // DIV - is this signed?
            0x04 => {
                vec![Some(stack_bv!(0).bvsdiv(&stack_bv!(1)))]
            }
            // SDIV
            0x05 => {
                vec![Some(stack_bv!(0).bvsdiv(&stack_bv!(1)))]
            }
            // MOD
            0x06 => {
                vec![Some(stack_bv!(0).bvurem(&stack_bv!(1)))]
            }
            // SMOD
            0x07 => {
                vec![Some(stack_bv!(0).bvsrem(&stack_bv!(1)))]
            }
            // ADDMOD
            0x08 => {
                vec![Some(stack_bv!(0).add(stack_bv!(1)).bvsrem(&stack_bv!(2)))]
            }
            // MULMOD
            0x09 => {
                vec![Some(stack_bv!(0).mul(stack_bv!(1)).bvsrem(&stack_bv!(2)))]
            }
            // EXP - we can't support, cuz z3 is bad at it
            0x0a => {
                vec![None]
            }
            // SIGNEXTEND - need to check
            0x0b => {
                // let bv = stack_bv!(0);
                // let bv = bv.bvshl(&self.ctx.bv_val(248, 256));
                // let bv = bv.bvashr(&self.ctx.bv_val(248, 256));
                vec![None]
            }
            // LT
            0x10 => {
                self.solver.assert(
                    &stack_bv!(0)
                        .bvult(&stack_bv!(1))
                        ._eq(&Bool::from_bool(&self.ctx, true)),
                );
                vec![None]
            }
            // GT
            0x11 => {
                self.solver.assert(
                    &stack_bv!(0)
                        .bvugt(&stack_bv!(1))
                        ._eq(&Bool::from_bool(&self.ctx, true)),
                );
                vec![None]
            }
            // SLT
            0x12 => {
                self.solver.assert(
                    &stack_bv!(0)
                        .bvslt(&stack_bv!(1))
                        ._eq(&Bool::from_bool(&self.ctx, true)),
                );
                vec![None]
            }
            // SGT
            0x13 => {
                self.solver.assert(
                    &stack_bv!(0)
                        .bvsgt(&stack_bv!(1))
                        ._eq(&Bool::from_bool(&self.ctx, true)),
                );
                vec![None]
            }
            // EQ
            0x14 => {
                self.solver.assert(&stack_bv!(0)._eq(&stack_bv!(1)));
                vec![None]
            }
            // ISZERO
            0x15 => {
                self.solver
                    .assert(&stack_bv!(0)._eq(&BV::from_u64(&self.ctx, 0, 256)));
                vec![None]
            }
            // AND
            0x16 => {
                vec![Some(stack_bv!(0).bvand(&stack_bv!(1)))]
            }
            // OR
            0x17 => {
                vec![Some(stack_bv!(0).bvor(&stack_bv!(1)))]
            }
            // XOR
            0x18 => {
                vec![Some(stack_bv!(0).bvxor(&stack_bv!(1)))]
            }
            // NOT
            0x19 => {
                vec![Some(stack_bv!(0).bvnot())]
            }
            // BYTE
            0x1a => {
                // wtf is this
                vec![None]
            }
            // SHL
            0x1b => {
                vec![Some(stack_bv!(0).bvshl(&stack_bv!(1)))]
            }
            // SHR
            0x1c => {
                vec![Some(stack_bv!(0).bvlshr(&stack_bv!(1)))]
            }
            // SAR
            0x1d => {
                vec![Some(stack_bv!(0).bvashr(&stack_bv!(1)))]
            }
            // SHA3
            0x20 => {
                vec![None]
            }
            // ADDRESS
            0x30 => {
                vec![None]
            }
            // BALANCE
            0x31 => {
                vec![Some(BV::new_const(&self.ctx, "balance", 256))]
            }
            // ORIGIN
            0x32 => {
                vec![None]
            }
            // CALLER
            0x33 => {
                vec![None]
            }
            // CALLVALUE
            0x34 => {
                vec![Some(BV::new_const(&self.ctx, "callvalue", 256))]
            }
            // CALLDATALOAD
            0x35 => {
                // TODO(@shangying): can you please help me with this?
                // basically, we need to get a new sub-BV from shadow input, which starts from
                // `interp.stack.peek(0).unwrap().0[0] * 8` to that + 32 * 8 (32 bytes)
                vec![None]
            }
            // CALLDATASIZE
            0x36 => {
                vec![None]
            }
            // CALLDATACOPY
            0x37 => {
                vec![None]
            }
            // CODESIZE
            0x38 => {
                vec![None]
            }
            // CODECOPY
            0x39 => {
                vec![None]
            }
            // GASPRICE
            0x3a => {
                vec![None]
            }
            // EXTCODESIZE
            0x3b => {
                vec![None]
            }
            // EXTCODECOPY
            0x3c => {
                vec![None]
            }
            // RETURNDATASIZE
            0x3d => {
                vec![None]
            }
            // RETURNDATACOPY
            0x3e => {
                vec![None]
            }
            // BLOCKHASH
            0x40 => {
                vec![None]
            }
            // COINBASE
            0x41 => {
                vec![None]
            }
            // TIMESTAMP
            0x42 => {
                vec![None]
            }
            // NUMBER
            0x43 => {
                vec![None]
            }
            // PREVRANDAO
            0x44 => {
                vec![None]
            }
            // GASLIMIT
            0x45 => {
                vec![None]
            }
            // CHAINID
            0x46 => {
                vec![None]
            }
            // SELFBALANCE
            0x47 => {
                vec![None]
            }
            // BASEFEE
            0x48 => {
                vec![None]
            }
            // POP
            0x50 => {
                vec![None]
            }
            // MLOAD
            0x51 => {
                vec![None]
            }
            // MSTORE
            0x52 => {
                vec![None]
            }
            // MSTORE8
            0x53 => {
                vec![None]
            }
            // SLOAD
            0x54 => {
                vec![None]
            }
            // SSTORE
            0x55 => {
                vec![None]
            }
            // JUMP
            0x56 => {
                vec![None]
            }
            // JUMPI
            0x57 => {
                vec![None]
            }
            // PC
            0x58 => {
                vec![None]
            }
            // MSIZE
            0x59 => {
                vec![None]
            }
            // GAS
            0x5a => {
                vec![None]
            }
            // JUMPDEST
            0x5b => {
                vec![]
            }
            // PUSH
            0x60..=0x7f => {
                // push n bytes into stack
                let n = (*interp.instruction_pointer) - 0x60 + 1;
                // let mut data = vec![];
                // for i in 0..n {
                // data.push(
                //     interp.contract().bytecode.bytecode()
                //         [interp.program_counter() + i as usize + 1],
                // );
                // }

                vec![

                    //todo!
                ]
            }
            // DUP
            0x80..=0x8f => {
                let n = (*interp.instruction_pointer) - 0x80 + 1;
                vec![
                    //todo!
                ]
            }
            // SWAP
            0x90..=0x9f => {
                let n = (*interp.instruction_pointer) - 0x90 + 1;
                vec![
                    //todo!
                ]
            }
            // LOG
            0xa0..=0xa4 => {
                vec![]
            }

            _ => {
                vec![]
            }
        };
        for v in bv {
            self.symbolic_stack.push(v.clone());
        }
    }
}

impl<'a> ConcolicHost<'a> {
    const INSPECT: bool = true;
    // type DB = BenchmarkDB;

    fn step(&'a mut self, interp: &mut Interpreter, is_static: bool) -> Return {
        unsafe {
            // self.symbolic_stack.push(Some(BV::from_u64(&self.ctx, 1, 2)))
            self.on_step(interp);
        }

        return Continue;
    }

    fn step_end(&mut self, interp: &mut Interpreter, is_static: bool, ret: Return) -> Return {
        return Continue;
    }

    fn env(&mut self) -> &mut Env {
        return &mut self.env;
    }

    fn load_account(&mut self, address: H160) -> Option<(bool, bool)> {
        // todo: exist second param
        unsafe {
            println!("load account {}", address);
        }
        Some((
            true,
            self.data.contains_key(&address) || self.code.contains_key(&address),
        ))
    }

    fn block_hash(&mut self, number: U256) -> Option<H256> {
        println!("blockhash {}", number);

        Some(
            H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        )
    }

    fn balance(&mut self, address: H160) -> Option<(U256, bool)> {
        println!("balance");

        Some((U256::max_value(), true))
    }

    fn code(&mut self, address: H160) -> Option<(Bytecode, bool)> {
        println!("code");
        match self.code.get(&address) {
            Some(code) => Some((code.clone(), true)),
            None => Some((Bytecode::new(), true)),
        }
    }

    fn code_hash(&mut self, address: H160) -> Option<(H256, bool)> {
        Some((
            H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            true,
        ))
    }

    fn sload(&mut self, address: H160, index: U256) -> Option<(U256, bool)> {
        unsafe {
            println!("sload");
        }
        match self.data.get(&address) {
            Some(account) => Some((account.get(&index).unwrap_or(&U256::zero()).clone(), true)),
            None => Some((U256::zero(), true)),
        }
    }

    fn sstore(
        &mut self,
        address: H160,
        index: U256,
        value: U256,
    ) -> Option<(U256, U256, U256, bool)> {
        // unsafe {
        //     // println!("sstore");
        // }
        match self.data.get_mut(&address) {
            Some(account) => account.insert(index, value),
            None => None,
        };
        Some((U256::from(0), U256::from(0), U256::from(0), true))
    }

    fn log(&mut self, address: H160, topics: Vec<H256>, data: Bytes) {}

    fn selfdestruct(&mut self, address: H160, target: H160) -> Option<SelfDestructResult> {
        return Some(SelfDestructResult::default());
    }

    fn create<SPEC: Spec>(
        &mut self,
        inputs: &mut CreateInputs,
    ) -> (Return, Option<H160>, Gas, Bytes) {
        unsafe {
            println!("create");
        }
        return (
            Continue,
            Some(H160::from_str("0x0000000000000000000000000000000000000000").unwrap()),
            Gas::new(0),
            Bytes::new(),
        );
    }

    fn call<SPEC: Spec>(&mut self, input: &mut CallInputs) -> (Return, Gas, Bytes) {
        unsafe {
            println!("call");
        }
        return (Continue, Gas::new(0), Bytes::new());
    }
}
