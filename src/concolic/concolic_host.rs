use crate::evm::ExecutionResult;
use bytes::Bytes;
use primitive_types::{H160, H256, U256};
use revm::db::BenchmarkDB;
use revm::opcode::CALL;
use revm::Return::Continue;
use revm::{
    Bytecode, CallInputs, CreateInputs, Env, Gas, Host, Interpreter, Return, SelfDestructResult,
    Spec,
};
use std::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;
use std::ops::{Add, Deref, Mul, Sub};
use std::str::FromStr;
use z3::ast::{Bool, BV};
use z3::{ast, ast::Ast, Config, Context, Solver};

#[derive(Clone)]
enum ConcolicOp {
    U256,
    ADD,
    DIV,
    MUL,
    SUB,
    SDIV,
    SMOD,
    UREM,
    SREM,
    AND,
    OR,
    XOR,
    NOT,
    SHL,
    SHR,
    SAR,
    INPUT,
    SLICEDINPUT,
    BALANCE,
    CALLVALUE,
}

pub enum ConstraintOp {
    EQ,
    LT,
    SLT,
    GT,
    SGT,
}

#[derive(Clone)]
pub struct BVBox {
    lhs: Option<Box<BVBox>>,
    rhs: Option<Box<BVBox>>,
    concrete: Option<U256>,
    op: ConcolicOp,
}

pub struct Constraint {
    pub lhs: Box<BVBox>,
    pub rhs: Box<BVBox>,
    pub op: ConstraintOp,
}

macro_rules! box_bv {
    ($lhs:expr, $rhs:expr, $op:expr) => {
        Box::new(BVBox {
            lhs: Some(Box::new($lhs)),
            rhs: Some($rhs),
            concrete: None,
            op: $op,
        })
    };
}

macro_rules! bv_from_u256 {
    ($val:expr, $ctx:expr) => {{
        let u64x4 = $val.0;
        let bv = BV::from_u64(&$ctx, u64x4[0], 64);
        let bv = bv.concat(&BV::from_u64(&$ctx, u64x4[1], 64));
        let bv = bv.concat(&BV::from_u64(&$ctx, u64x4[2], 64));
        let bv = bv.concat(&BV::from_u64(&$ctx, u64x4[3], 64));
        bv
    }};
}

impl BVBox {
    pub fn new_input() -> Self {
        BVBox {
            lhs: None,
            rhs: None,
            concrete: None,
            op: ConcolicOp::INPUT,
        }
    }

    pub fn new_sliced_input(idx: U256) -> Self {
        BVBox {
            lhs: None,
            rhs: None,
            concrete: Some(idx),
            op: ConcolicOp::SLICEDINPUT,
        }
    }

    pub fn new_balance() -> Self {
        BVBox {
            lhs: None,
            rhs: None,
            concrete: None,
            op: ConcolicOp::BALANCE,
        }
    }

    pub fn new_callvalue() -> Self {
        BVBox {
            lhs: None,
            rhs: None,
            concrete: None,
            op: ConcolicOp::CALLVALUE,
        }
    }

    pub fn div(self, rhs: Box<BVBox>) -> Box<BVBox> {
        box_bv!(self, rhs, ConcolicOp::DIV)
    }
    pub fn mul(self, rhs: Box<BVBox>) -> Box<BVBox> {
        box_bv!(self, rhs, ConcolicOp::MUL)
    }
    pub fn add(self, rhs: Box<BVBox>) -> Box<BVBox> {
        box_bv!(self, rhs, ConcolicOp::ADD)
    }
    pub fn sub(self, rhs: Box<BVBox>) -> Box<BVBox> {
        box_bv!(self, rhs, ConcolicOp::SUB)
    }
    pub fn bvsdiv(self, rhs: Box<BVBox>) -> Box<BVBox> {
        box_bv!(self, rhs, ConcolicOp::SDIV)
    }
    pub fn bvsmod(self, rhs: Box<BVBox>) -> Box<BVBox> {
        box_bv!(self, rhs, ConcolicOp::SMOD)
    }
    pub fn bvurem(self, rhs: Box<BVBox>) -> Box<BVBox> {
        box_bv!(self, rhs, ConcolicOp::UREM)
    }
    pub fn bvsrem(self, rhs: Box<BVBox>) -> Box<BVBox> {
        box_bv!(self, rhs, ConcolicOp::SREM)
    }
    pub fn bvand(self, rhs: Box<BVBox>) -> Box<BVBox> {
        box_bv!(self, rhs, ConcolicOp::ADD)
    }
    pub fn bvor(self, rhs: Box<BVBox>) -> Box<BVBox> {
        box_bv!(self, rhs, ConcolicOp::OR)
    }
    pub fn bvxor(self, rhs: Box<BVBox>) -> Box<BVBox> {
        box_bv!(self, rhs, ConcolicOp::XOR)
    }
    pub fn bvnot(self) -> Box<BVBox> {
        Box::new(BVBox {
            lhs: Some(Box::new(self)),
            rhs: None,
            concrete: None,
            op: ConcolicOp::NOT,
        })
    }
    pub fn bvshl(self, rhs: Box<BVBox>) -> Box<BVBox> {
        box_bv!(self, rhs, ConcolicOp::SHL)
    }
    pub fn bvlshr(self, rhs: Box<BVBox>) -> Box<BVBox> {
        box_bv!(self, rhs, ConcolicOp::SHR)
    }
    pub fn bvsar(self, rhs: Box<BVBox>) -> Box<BVBox> {
        box_bv!(self, rhs, ConcolicOp::SAR)
    }

    pub fn bvult(self, rhs: Box<BVBox>) -> Constraint {
        Constraint {
            lhs: Box::new(self),
            rhs,
            op: ConstraintOp::LT,
        }
    }
    pub fn bvugt(self, rhs: Box<BVBox>) -> Constraint {
        Constraint {
            lhs: Box::new(self),
            rhs,
            op: ConstraintOp::GT,
        }
    }

    pub fn bvslt(self, rhs: Box<BVBox>) -> Constraint {
        Constraint {
            lhs: Box::new(self),
            rhs,
            op: ConstraintOp::SLT,
        }
    }
    pub fn bvsgt(self, rhs: Box<BVBox>) -> Constraint {
        Constraint {
            lhs: Box::new(self),
            rhs,
            op: ConstraintOp::SGT,
        }
    }

    pub fn eq(self, rhs: Box<BVBox>) -> Constraint {
        Constraint {
            lhs: Box::new(self),
            rhs,
            op: ConstraintOp::EQ,
        }
    }
}

pub struct Solving<'a> {
    input: &'a BV<'a>,
    balance: &'a BV<'a>,
    calldatavalue: &'a BV<'a>,
    solver: &'a Solver<'a>,
}

impl<'a> Solving<'a> {
    fn new(
        input: &'a BV<'a>,
        balance: &'a BV<'a>,
        calldatavalue: &'a BV<'a>,
        solver: &'a Solver<'a>,
    ) -> Self {
        Solving {
            input,
            balance,
            calldatavalue,
            solver,
        }
    }
}

impl<'a> Solving<'a> {
    pub fn generate_z3_bv(&mut self, bv: &BVBox, ctx: &'a Context) -> BV<'a> {
        macro_rules! binop {
            ($lhs:expr, $rhs:expr, $op:ident) => {
                self.generate_z3_bv($lhs.as_ref().unwrap(), ctx)
                    .$op(&self.generate_z3_bv($rhs.as_ref().unwrap(), ctx))
            };
        }
        match bv.op {
            ConcolicOp::U256 => {
                bv_from_u256!(bv.concrete.unwrap(), ctx)
            }
            ConcolicOp::ADD => {
                binop!(bv.lhs, bv.rhs, bvadd)
            }
            ConcolicOp::DIV => {
                binop!(bv.lhs, bv.rhs, bvudiv)
            }
            ConcolicOp::MUL => {
                binop!(bv.lhs, bv.rhs, bvmul)
            }
            ConcolicOp::SUB => {
                binop!(bv.lhs, bv.rhs, bvsub)
            }
            ConcolicOp::SDIV => {
                binop!(bv.lhs, bv.rhs, bvsdiv)
            }
            ConcolicOp::SMOD => {
                binop!(bv.lhs, bv.rhs, bvsmod)
            }
            ConcolicOp::UREM => {
                binop!(bv.lhs, bv.rhs, bvurem)
            }
            ConcolicOp::SREM => {
                binop!(bv.lhs, bv.rhs, bvsrem)
            }
            ConcolicOp::AND => {
                binop!(bv.lhs, bv.rhs, bvand)
            }
            ConcolicOp::OR => {
                binop!(bv.lhs, bv.rhs, bvor)
            }
            ConcolicOp::XOR => {
                binop!(bv.lhs, bv.rhs, bvxor)
            }
            ConcolicOp::NOT => self.generate_z3_bv(bv.lhs.as_ref().unwrap(), ctx).bvnot(),
            ConcolicOp::SHL => {
                binop!(bv.lhs, bv.rhs, bvshl)
            }
            ConcolicOp::SHR => {
                binop!(bv.lhs, bv.rhs, bvlshr)
            }
            ConcolicOp::SAR => {
                binop!(bv.lhs, bv.rhs, bvashr)
            }
            ConcolicOp::INPUT => self.input.clone(),
            ConcolicOp::SLICEDINPUT => {
                let idx = bv.concrete.unwrap().0[0] as u32;
                self.input.extract(idx * 8 + 32, idx * 8)
            }
            ConcolicOp::BALANCE => self.balance.clone(),
            ConcolicOp::CALLVALUE => self.calldatavalue.clone(),
        }
    }
}

pub struct ConcolicHost {
    env: Env,
    data: HashMap<H160, HashMap<U256, U256>>,
    code: HashMap<H160, Bytecode>,
    symbolic_stack: Vec<Option<Box<BVBox>>>,
    shadow_inputs: Option<BVBox>,
    constraints: Vec<Constraint>,
    bits: u32,
}

impl ConcolicHost {
    pub fn new(bytes: u32) -> Self {
        Self {
            env: Env::default(),
            data: HashMap::new(),
            code: HashMap::new(),
            symbolic_stack: Vec::new(),
            shadow_inputs: Some(BVBox::new_input()),
            constraints: vec![],
            bits: 8 * bytes,
        }
    }

    pub unsafe fn on_step(&mut self, interp: &mut Interpreter) {
        macro_rules! stack_bv {
            ($idx:expr) => {{
                match self.symbolic_stack[$idx].borrow() {
                    Some(bv) => bv.clone(),
                    None => {
                        let u256 = interp.stack.peek($idx).expect("stack underflow");
                        Box::new(BVBox {
                            lhs: None,
                            rhs: None,
                            concrete: Some(u256),
                            op: ConcolicOp::U256,
                        })
                    }
                }
            }};
        }

        let bv: Vec<Option<Box<BVBox>>> = match *interp.instruction_pointer {
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
                vec![Some(stack_bv!(0).bvsdiv(stack_bv!(1)))]
            }
            // SDIV
            0x05 => {
                vec![Some(stack_bv!(0).bvsdiv(stack_bv!(1)))]
            }
            // MOD
            0x06 => {
                vec![Some(stack_bv!(0).bvurem(stack_bv!(1)))]
            }
            // SMOD
            0x07 => {
                vec![Some(stack_bv!(0).bvsrem(stack_bv!(1)))]
            }
            // ADDMOD
            0x08 => {
                vec![Some(stack_bv!(0).add(stack_bv!(1)).bvsrem(stack_bv!(2)))]
            }
            // MULMOD
            0x09 => {
                vec![Some(stack_bv!(0).mul(stack_bv!(1)).bvsrem(stack_bv!(2)))]
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
                self.constraints.push(stack_bv!(0).bvult(stack_bv!(1)));
                vec![None]
            }
            // GT
            0x11 => {
                self.constraints.push(stack_bv!(0).bvugt(stack_bv!(1)));
                vec![None]
            }
            // SLT
            0x12 => {
                self.constraints.push(stack_bv!(0).bvslt(stack_bv!(1)));
                vec![None]
            }
            // SGT
            0x13 => {
                self.constraints.push(stack_bv!(0).bvsgt(stack_bv!(1)));
                vec![None]
            }
            // EQ
            0x14 => {
                self.constraints.push(stack_bv!(0).eq(stack_bv!(1)));
                vec![None]
            }
            // ISZERO
            0x15 => {
                self.constraints.push(stack_bv!(0).eq(Box::new(BVBox {
                    lhs: None,
                    rhs: None,
                    concrete: Some(U256::from(0)),
                    op: ConcolicOp::U256,
                })));
                vec![None]
            }
            // AND
            0x16 => {
                vec![Some(stack_bv!(0).bvand(stack_bv!(1)))]
            }
            // OR
            0x17 => {
                vec![Some(stack_bv!(0).bvor(stack_bv!(1)))]
            }
            // XOR
            0x18 => {
                vec![Some(stack_bv!(0).bvxor(stack_bv!(1)))]
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
                vec![Some(stack_bv!(0).bvshl(stack_bv!(1)))]
            }
            // SHR
            0x1c => {
                vec![Some(stack_bv!(0).bvlshr(stack_bv!(1)))]
            }
            // SAR
            0x1d => {
                vec![Some(stack_bv!(0).bvsar(stack_bv!(1)))]
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
                vec![Some(Box::new(BVBox::new_balance()))]
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
                vec![Some(Box::new(BVBox::new_callvalue()))]
            }
            // CALLDATALOAD
            0x35 => {
                vec![Some(Box::new(BVBox::new_sliced_input(
                    interp.stack.peek(0).unwrap(),
                )))]
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
            self.symbolic_stack.push(v);
        }
    }

    pub fn solve(&self) {
        let context = Context::new(&Config::default());
        let mut solver = Solver::new(&context);
        let input = BV::new_const(&context, "input", self.bits);
        let callvalue = BV::new_const(&context, "callvalue", 256);
        let balance = BV::new_const(&context, "balance", 256);

        let mut solving = Solving::new(&input, &balance, &callvalue, &solver);
        for cons in &self.constraints {
            let bv: BV = solving.generate_z3_bv(&cons.lhs, &context);
            solver.assert(&match cons.op {
                ConstraintOp::GT => bv.bvugt(&solving.generate_z3_bv(&cons.rhs, &context)),
                ConstraintOp::SGT => bv.bvsgt(&solving.generate_z3_bv(&cons.rhs, &context)),
                ConstraintOp::EQ => bv._eq(&solving.generate_z3_bv(&cons.rhs, &context)),
                ConstraintOp::LT => bv.bvult(&solving.generate_z3_bv(&cons.rhs, &context)),
                ConstraintOp::SLT => bv.bvslt(&solving.generate_z3_bv(&cons.rhs, &context)),
            });
        }
    }
}

impl Host for ConcolicHost {
    const INSPECT: bool = true;
    type DB = BenchmarkDB;
    // type DB = BenchmarkDB;

    fn step(&mut self, interp: &mut Interpreter, is_static: bool) -> Return {
        unsafe {
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
