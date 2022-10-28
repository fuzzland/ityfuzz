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
    symbolic_stack: Vec<Option<z3::ast::BV<'a>>>,
}

impl<'a> ConcolicHost<'a> {
    pub fn new(solver: Solver<'a>, ctx: Context) -> Self {
        Self {
            env: Env::default(),
            data: HashMap::new(),
            code: HashMap::new(),
            solver,
            ctx,
            symbolic_stack: Vec::new(),
        }
    }

    pub fn get_solver_mut(&mut self) -> &mut Solver<'a> {
        self.solver.borrow_mut()
    }

    pub fn get_bv_from_stack(&self, index: usize, interp: &mut Interpreter) -> BV {
        match self.symbolic_stack[index].borrow() {
            Some(bv) => bv.clone(),
            None => {
                let u256 = interp.stack.peek(index).expect("stack underflow");
                let u64x4 = u256.0;

                let bv = BV::from_u64(&self.ctx, u64x4[0], 64);
                let bv = bv.concat(&BV::from_u64(&self.ctx, u64x4[1], 64));
                let bv = bv.concat(&BV::from_u64(&self.ctx, u64x4[2], 64));
                let bv = bv.concat(&BV::from_u64(&self.ctx, u64x4[3], 64));
                bv
            }
        }
    }

    pub unsafe fn on_step(&mut self, interp: &mut Interpreter) -> Vec<Option<BV>> {
        // println!("{}", *interp.instruction_pointer);
        match *interp.instruction_pointer {
            // ADD
            0x01 => {
                vec![Some(
                    self.get_bv_from_stack(0, interp)
                        .add(self.get_bv_from_stack(1, interp)),
                )]
            }
            // MUL
            0x02 => {
                vec![Some(
                    self.get_bv_from_stack(0, interp)
                        .mul(self.get_bv_from_stack(1, interp)),
                )]
            }
            // SUB
            0x03 => {
                vec![Some(
                    self.get_bv_from_stack(0, interp)
                        .sub(self.get_bv_from_stack(1, interp)),
                )]
            }
            // DIV - is this signed?
            0x04 => {
                vec![Some(
                    self.get_bv_from_stack(0, interp)
                        .bvsdiv(&self.get_bv_from_stack(1, interp)),
                )]
            }
            // SDIV
            0x05 => {
                vec![Some(
                    self.get_bv_from_stack(0, interp)
                        .bvsdiv(&self.get_bv_from_stack(1, interp)),
                )]
            }
            // MOD
            0x06 => {
                vec![Some(
                    self.get_bv_from_stack(0, interp)
                        .bvurem(&self.get_bv_from_stack(1, interp)),
                )]
            }
            // SMOD
            0x07 => {
                vec![Some(
                    self.get_bv_from_stack(0, interp)
                        .bvsrem(&self.get_bv_from_stack(1, interp)),
                )]
            }
            // ADDMOD
            0x08 => {
                vec![Some(
                    self.get_bv_from_stack(0, interp)
                        .add(&self.get_bv_from_stack(1, interp))
                        .bvsrem(&self.get_bv_from_stack(2, interp)),
                )]
            }
            // MULMOD
            0x09 => {
                vec![Some(
                    self.get_bv_from_stack(0, interp)
                        .mul(&self.get_bv_from_stack(1, interp))
                        .bvsrem(&self.get_bv_from_stack(2, interp)),
                )]
            }
            // EXP - we can't support, cuz z3 is bad at it
            0x0a => {
                vec![None]
            }
            // SIGNEXTEND - need to check
            0x0b => {
                // let bv = self.get_bv_from_stack(0, interp);
                // let bv = bv.bvshl(&self.ctx.bv_val(248, 256));
                // let bv = bv.bvashr(&self.ctx.bv_val(248, 256));
                vec![None]
            }
            // LT
            0x10 => {
                self.solver.assert(
                    &self
                        .get_bv_from_stack(0, interp)
                        .bvult(&self.get_bv_from_stack(1, interp))
                        ._eq(&Bool::from_bool(&self.ctx, true)),
                );
                vec![None]
            }
            // GT
            0x11 => {
                self.solver.assert(
                    &self
                        .get_bv_from_stack(0, interp)
                        .bvugt(&self.get_bv_from_stack(1, interp))
                        ._eq(&Bool::from_bool(&self.ctx, true)),
                );
                vec![None]
            }
            // SLT
            0x12 => {
                self.solver.assert(
                    &self
                        .get_bv_from_stack(0, interp)
                        .bvslt(&self.get_bv_from_stack(1, interp))
                        ._eq(&Bool::from_bool(&self.ctx, true)),
                );
                vec![None]
            }
            // SGT
            0x13 => {
                self.solver.assert(
                    &self
                        .get_bv_from_stack(0, interp)
                        .bvsgt(&self.get_bv_from_stack(1, interp))
                        ._eq(&Bool::from_bool(&self.ctx, true)),
                );
                vec![None]
            }
            // EQ
            0x14 => {
                self.solver.assert(
                    &self
                        .get_bv_from_stack(0, interp)
                        ._eq(&self.get_bv_from_stack(1, interp)),
                );
                vec![None]
            }
            // ISZERO
            0x15 => {
                self.solver.assert(
                    &self
                        .get_bv_from_stack(0, interp)
                        ._eq(&BV::from_u64(&self.ctx, 0, 256)),
                );
                vec![None]
            }
            // AND
            0x16 => {
                vec![Some(
                    self.get_bv_from_stack(0, interp)
                        .bvand(&self.get_bv_from_stack(1, interp)),
                )]
            }
            // OR
            0x17 => {
                vec![Some(
                    self.get_bv_from_stack(0, interp)
                        .bvor(&self.get_bv_from_stack(1, interp)),
                )]
            }
            // XOR
            0x18 => {
                vec![Some(
                    self.get_bv_from_stack(0, interp)
                        .bvxor(&self.get_bv_from_stack(1, interp)),
                )]
            }
            // NOT
            0x19 => {
                vec![Some(self.get_bv_from_stack(0, interp).bvnot())]
            }
            // BYTE
            0x1a => {
                // wtf is this
                vec![None]
            }
            // SHL
            0x1b => {
                vec![Some(
                    self.get_bv_from_stack(0, interp)
                        .bvshl(&self.get_bv_from_stack(1, interp)),
                )]
            }
            // SHR
            0x1c => {
                vec![Some(
                    self.get_bv_from_stack(0, interp)
                        .bvlshr(&self.get_bv_from_stack(1, interp)),
                )]
            }
            // SAR
            0x1d => {
                vec![Some(
                    self.get_bv_from_stack(0, interp)
                        .bvashr(&self.get_bv_from_stack(1, interp)),
                )]
            }
            // SHA3
            0x20 => {
                // TODO
                vec![None]
            }
            // ADDRESS
            0x30 => {
                vec![None]
            }
            // BALANCE
            0x31 => {
                vec![None]
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
                vec![None]
            }
            // CALLDATALOAD
            0x35 => {
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

            _ => {
                vec![None]
            }
        }
        // bv.iter().for_each(|x| {
        //     self.symbolic_stack.push(x.clone());
        // });
    }

    pub unsafe fn build_stack(&mut self, interp: &mut Interpreter) {
        for v in self.on_step(interp) {
            // self.symbolic_stack.push(v);
        }
    }
}

impl<'a> Host for ConcolicHost<'a> {
    const INSPECT: bool = true;
    type DB = BenchmarkDB;

    fn step(&mut self, interp: &mut Interpreter, is_static: bool) -> Return {
        unsafe {
            // self.build_stack(interp);
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
