use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::ops::{Add, Mul};
use std::str::FromStr;
use bytes::Bytes;
use primitive_types::{H160, H256, U256};
use revm::db::BenchmarkDB;
use revm::{Bytecode, CallInputs, CreateInputs, Env, Gas, Host, Interpreter, Return, SelfDestructResult, Spec};
use revm::Return::Continue;
use z3::{ast, ast::Ast, Config, Context, Solver};
use z3::ast::BV;


pub struct FuzzHost<'a> {
    env: Env,
    data: HashMap<H160, HashMap<U256, U256>>,
    code: HashMap<H160, Bytecode>,
    solver: Solver<'a>,
    ctx: Context,
    symbolic_stack: Vec<Option<z3::ast::BV<'a>>>,
}

impl<'a> FuzzHost<'a> {
    pub fn new() -> Self {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        Self {
            env: Env::default(),
            data: HashMap::new(),
            code: HashMap::new(),
            solver,
            ctx,
            symbolic_stack: Vec::new(),
        }
    }

    pub fn get_bv_from_stack(&self, index: usize, interp: &mut Interpreter) -> &mut BV<'a> {
        match self.symbolic_stack[index].borrow_mut() {
            Some(bv) => bv,
            None => {
                let u256 = interp.stack.peek(index).expect("stack underflow");
                let u64x4 = u256.0;
                let bv = self.ctx.bv_val(u64x4[0], 64);
                let bv = bv.concat(&self.ctx.bv_val(u64x4[1], 64));
                let bv = bv.concat(&self.ctx.bv_val(u64x4[2], 64));
                let bv = bv.concat(&self.ctx.bv_val(u64x4[3], 64));
                bv
            }
        }

    }
}

impl Host for FuzzHost {
    const INSPECT: bool = true;
    type DB = BenchmarkDB;

    fn step(&mut self, interp: &mut Interpreter, is_static: bool) -> Return {
        unsafe {
            // println!("{}", *interp.instruction_pointer);
            let bv = match *interp.instruction_pointer {
                // ADD
                0x01 => {
                    Some(self.get_bv_from_stack(0, interp).add(
                            self.get_bv_from_stack(1, interp)
                    ))
                }
                // MUL
                0x02 => {
                    Some(self.get_bv_from_stack(0, interp).mul(
                            self.get_bv_from_stack(1, interp)
                    ))
                }
                // SUB
                0x03 => {
                    Some(self.get_bv_from_stack(0, interp) -
                            self.get_bv_from_stack(1, interp))
                }
                // DIV
                0x04 => {
                    Some(self.get_bv_from_stack(0, interp) /
                            self.get_bv_from_stack(1, interp))
                }
                // SDIV
                0x05 => {
                    Some(self.get_bv_from_stack(0, interp).bvsdiv(
                        &self.get_bv_from_stack(1, interp)
                    ))
                }
                // MOD
                0x06 => {
                    Some(self.get_bv_from_stack(0, interp).bvurem(
                        &self.get_bv_from_stack(1, interp)
                    ))
                }
                // SMOD
                0x07 => {
                    Some(self.get_bv_from_stack(0, interp).bvsrem(
                        &self.get_bv_from_stack(1, interp)
                    ))
                }
                // ADDMOD
                0x08 => {
                    Some(self.get_bv_from_stack(0, interp).add(
                        &self.get_bv_from_stack(1, interp)
                    ).bvsrem(&self.get_bv_from_stack(2, interp)))
                }
                // MULMOD
                0x09 => {
                    Some(self.get_bv_from_stack(0, interp).mul(
                        &self.get_bv_from_stack(1, interp)
                    ).bvsrem(&self.get_bv_from_stack(2, interp)))
                }
                // EXP - we can't support, cuz z3 is bad at it
                0x0a => {
                    // self.get_bv_from_stack(0, interp)(
                    //     &self.get_bv_from_stack(1, interp)
                    // )
                    None
                }
                // SIGNEXTEND - need to check
                0x0b => {
                    let bv = self.get_bv_from_stack(0, interp);
                    let bv = bv.bvshl(&self.ctx.bv_val(248, 256));
                    let bv = bv.bvashr(&self.ctx.bv_val(248, 256));
                    Some(bv)
                }
                // LT
                0x10 => {
                    Some(self.get_bv_from_stack(0, interp).bvult(
                        &self.get_bv_from_stack(1, interp)
                    ))
                }
                // GT
                0x11 => {
                    Some(self.get_bv_from_stack(0, interp).bvugt(
                        &self.get_bv_from_stack(1, interp)
                    ))
                }
                // SLT
                0x12 => {
                    Some(self.get_bv_from_stack(0, interp).bvslt(
                        &self.get_bv_from_stack(1, interp)
                    ))
                }
                // SGT
                0x13 => {
                    Some(self.get_bv_from_stack(0, interp).bvsgt(
                        &self.get_bv_from_stack(1, interp)
                    ))
                }
                // EQ
                0x14 => {
                    Some(self.get_bv_from_stack(0, interp).eq(
                        &self.get_bv_from_stack(1, interp)
                    ))
                }
                // ISZERO
                0x15 => {
                    Some(self.get_bv_from_stack(0, interp).eq(
                        &self.ctx.bv_val(0, 256)
                    ))
                }
                // AND
                0x16 => {
                    Some(self.get_bv_from_stack(0, interp).bvand(
                        &self.get_bv_from_stack(1, interp)
                    ))
                }
                // OR
                0x17 => {
                    Some(self.get_bv_from_stack(0, interp).bvor(
                        &self.get_bv_from_stack(1, interp)
                    ))
                }
                // XOR
                0x18 => {
                    Some(self.get_bv_from_stack(0, interp).bvxor(
                        &self.get_bv_from_stack(1, interp)
                    ))
                }
                // NOT
                0x19 => {
                    Some(self.get_bv_from_stack(0, interp).bvnot())
                }
                // BYTE
                0x1a => {
                    // wtf is this
                }
                // SHL
                0x1b => {
                    Some(self.get_bv_from_stack(0, interp).bvshl(
                        &self.get_bv_from_stack(1, interp)
                    ))
                }
                // SHR
                0x1c => {
                    Some(self.get_bv_from_stack(0, interp).bvlshr(
                        &self.get_bv_from_stack(1, interp)
                    ))
                }
                // SAR
                0x1d => {
                    Some(self.get_bv_from_stack(0, interp).bvashr(
                        &self.get_bv_from_stack(1, interp)
                    ))
                }
                // SHA3
                0x20 => {
                    // TODO
                    None
                }
                // ADDRESS
                0x30 => {
                    None
                }
                // BALANCE
                0x31 => {
                    None
                }
                // ORIGIN
                0x32 => {
                    None
                }
                // CALLER
                0x33 => {
                    None
                }
                // CALLVALUE
                0x34 => {
                    None
                }
                // CALLDATALOAD
                0x35 => {
                    None
                }
                // CALLDATASIZE
                0x36 => {
                    None
                }
                // CALLDATACOPY
                0x37 => {
                    None
                }
                // CODESIZE
                0x38 => {
                    None
                }
                // CODECOPY
                0x39 => {
                    None
                }
                // GASPRICE
                0x3a => {
                    None
                }
                // EXTCODESIZE
                0x3b => {
                    None
                }


                _ => {}
            }
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