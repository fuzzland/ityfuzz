use bytes::Bytes;

use crate::evm::abi::BoxedABI;
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT, EVMInputTy};
use crate::evm::middlewares::middleware::MiddlewareType::Concolic;
use crate::evm::middlewares::middleware::{add_corpus, Middleware, MiddlewareType};

use crate::evm::host::{FuzzHost, JMP_MAP};
use crate::generic_vm::vm_executor::MAP_SIZE;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasItyState};
use either::Either;
use libafl::prelude::{Corpus, HasMetadata, Input};

use libafl::state::{HasCorpus, State};

use revm_interpreter::{Interpreter, Host};
use revm_primitives::{Bytecode, HashMap};

use serde::{Deserialize, Serialize};
use std::borrow::Borrow;

use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::{Add, Mul, Not, Sub};
use std::sync::Arc;
use itertools::Itertools;

use z3::ast::{Bool, BV};
use z3::{ast::Ast, Config, Context, Solver};
use crate::evm::types::{as_u64, EVMAddress, EVMU256, is_zero};

pub static mut CONCOLIC_MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];

#[derive(Clone, Debug, Serialize, Deserialize)]
enum ConcolicOp {
    EVMU256(EVMU256),
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
    SLICEDINPUT(EVMU256),
    BALANCE,
    CALLVALUE,
    // symbolic byte
    SYMBYTE(String),
    // helper OP for input slicing (not in EVM)
    CONSTBYTE(u8),
    // (start, end) in bytes, end is not included
    FINEGRAINEDINPUT(u32, u32),
    // constraint OP here
    EQ,
    LT,
    SLT,
    GT,
    SGT,
    LNOT,

    SELECT(u32),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Expr {
    lhs: Option<Box<Expr>>,
    rhs: Option<Box<Expr>>,
    // concrete should be used in constant folding
    // concrete: Option<EVMU256>,
    op: ConcolicOp,
}

// pub struct Constraint {
//     pub lhs: Box<Expr>,
//     pub rhs: Box<Expr>,
//     pub op: ConstraintOp,
// }

// TODO: if both operands are concrete we can do constant folding somewhere
macro_rules! box_bv {
    ($lhs:expr, $rhs:expr, $op:expr) => {
        Box::new(Expr {
            lhs: Some(Box::new($lhs)),
            rhs: Some($rhs),
            op: $op,
        })
    };
}

macro_rules! bv_from_u256 {
    ($val:expr, $ctx:expr) => {{
        let u64x4 = $val.as_limbs();
        let bv = BV::from_u64(&$ctx, u64x4[3], 64);
        let bv = bv.concat(&BV::from_u64(&$ctx, u64x4[2], 64));
        let bv = bv.concat(&BV::from_u64(&$ctx, u64x4[1], 64));
        let bv = bv.concat(&BV::from_u64(&$ctx, u64x4[0], 64));
        bv
    }};
}

impl Expr {
    pub fn new_sliced_input(idx: EVMU256) -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::SLICEDINPUT(idx),
        })
    }

    pub fn new_balance() -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::BALANCE,
        })
    }

    pub fn new_callvalue() -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::CALLVALUE,
        })
    }

    pub fn sliced_input(start: u32, end: u32) -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::FINEGRAINEDINPUT(start, end),
        })
    }

    pub fn div(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::DIV)
    }
    pub fn mul(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::MUL)
    }
    pub fn add(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::ADD)
    }
    pub fn sub(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SUB)
    }
    pub fn bvsdiv(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SDIV)
    }
    pub fn bvsmod(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SMOD)
    }
    pub fn bvurem(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::UREM)
    }
    pub fn bvsrem(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SREM)
    }
    pub fn bvand(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::AND)
    }
    pub fn bvor(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::OR)
    }
    pub fn bvxor(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::XOR)
    }
    pub fn bvnot(self) -> Box<Expr> {
        Box::new(Expr {
            lhs: Some(Box::new(self)),
            rhs: None,
            op: ConcolicOp::NOT,
        })
    }
    pub fn bvshl(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SHL)
    }
    pub fn bvlshr(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SHR)
    }
    pub fn bvsar(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SAR)
    }

    pub fn bvult(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::LT)
    }

    pub fn bvugt(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::GT)
    }

    pub fn bvslt(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SLT)
    }

    pub fn bvsgt(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::SGT)
    }

    pub fn eq(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::EQ)
    }

    pub fn sym_byte(s: String) -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::SYMBYTE(s),
        })
    }

    pub fn const_byte(b: u8) -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::CONSTBYTE(b),
        })
    }

    // logical not
    pub fn lnot(self) -> Box<Expr> {
        Box::new(Expr {
            lhs: Some(Box::new(self)),
            rhs: None,
            op: ConcolicOp::LNOT,
        })
    }

    pub fn is_concrete(&self) -> bool {
        match (&self.lhs, &self.rhs) {
            (Some(l), Some(r)) => {
                l.is_concrete() && r.is_concrete()
            },
            (None, None) => {
                match self.op {
                    ConcolicOp::EVMU256(_) => true,
                    ConcolicOp::SLICEDINPUT(_) => false,
                    ConcolicOp::BALANCE => false,
                    ConcolicOp::CALLVALUE => false,
                    ConcolicOp::SYMBYTE(_) => false,
                    ConcolicOp::CONSTBYTE(_) => true,
                    ConcolicOp::FINEGRAINEDINPUT(_, _) => false,
                    _ => unreachable!()
                }
            }
            (Some(l), None) => l.is_concrete(),
            _ => unreachable!()
        }
    }
}

pub struct Solving<'a> {
    context: &'a Context,
    input: Vec<BV<'a>>,
    balance: &'a BV<'a>,
    calldatavalue: &'a BV<'a>,
    constraints: &'a Vec<Box<Expr>>,
}

impl<'a> Solving<'a> {
    fn new(
        context: &'a Context,
        input: &'a Vec<Box<Expr>>,
        balance: &'a BV<'a>,
        calldatavalue: &'a BV<'a>,
        constraints: &'a Vec<Box<Expr>>,
    ) -> Self {
        Solving {
            context,
            input: (*input).iter().enumerate().map(
                |(idx, x)| {
                    let bv = match &x.op {
                        ConcolicOp::SYMBYTE(name) => {
                            BV::new_const(context, name.clone(), 8)
                        }
                        ConcolicOp::CONSTBYTE(val) => {
                            BV::from_u64(context, *val as u64, 8)
                        }
                        _ => unreachable!("input should be symbolic or concrete"),
                    };
                    bv
                }
            ).collect_vec(),
            balance,
            calldatavalue,
            constraints,
        }
    }
}


pub enum SymbolicTy<'a> {
    BV(BV<'a>),
    Bool(Bool<'a>),
}

impl<'a> SymbolicTy<'a> {
    pub fn expect_bv(self) -> BV<'a> {
        match self {
            SymbolicTy::BV(bv) => bv,
            _ => panic!("expected bv"),
        }
    }

    pub fn expect_bool(self) -> Bool<'a> {
        match self {
            SymbolicTy::Bool(b) => b,
            _ => panic!("expected bool"),
        }
    }
}

impl<'a> Solving<'a> {
    pub fn slice_input(&self, start: u32, end: u32) -> BV<'a> {
        let start = start as usize;
        let end = end as usize;
        let mut slice = self.input[start].clone();
        for i in start + 1..end {
            slice = slice.concat(&self.input[i]);
        }
        slice
    }

    pub fn generate_z3_bv(&self, bv: &Expr, ctx: &'a Context) -> SymbolicTy<'a> {
        println!("[concolic] generate_z3_bv: {:?}", bv);
        macro_rules! binop {
            ($lhs:expr, $rhs:expr, $op:ident) => {
                {
                    let l = self.generate_z3_bv($lhs.as_ref().unwrap(), ctx)
                        .expect_bv();
                    let r = self.generate_z3_bv($rhs.as_ref().unwrap(), ctx)
                        .expect_bv();
                    println!("[concolic ]binop: {:?} {:?}", l, r);
                    l.$op(&r)
                }

            };
        }
        // println!("generate_z3_bv: {:?}", bv);

        macro_rules! comparisons2 {
            ($lhs:expr, $rhs:expr, $op:ident) => {
                {
                    let lhs = self.generate_z3_bv($lhs.as_ref().unwrap(), ctx);
                    let rhs = self.generate_z3_bv($rhs.as_ref().unwrap(), ctx);
                    match (lhs, rhs) {
                        (SymbolicTy::BV(lhs), SymbolicTy::BV(rhs)) => SymbolicTy::Bool(lhs.$op(&rhs)),
                        (SymbolicTy::Bool(lhs), SymbolicTy::Bool(rhs)) => SymbolicTy::Bool(lhs.$op(&rhs)),
                        _ => panic!("op {:?} not supported as operands", bv.op),
                    }
                }
            };
        }

        macro_rules! comparisons1 {
            ($lhs:expr, $rhs:expr, $op:ident) => {
                {
                    let lhs = self.generate_z3_bv($lhs.as_ref().unwrap(), ctx);
                    let rhs = self.generate_z3_bv($rhs.as_ref().unwrap(), ctx);
                    match (lhs, rhs) {
                        (SymbolicTy::BV(lhs), SymbolicTy::BV(rhs)) => SymbolicTy::Bool(lhs.$op(&rhs)),
                        _ => panic!("op {:?} not supported as operands", bv.op),
                    }
                }
            };
        }

        match &bv.op {
            ConcolicOp::EVMU256(constant) => SymbolicTy::BV(bv_from_u256!(constant, ctx)),
            ConcolicOp::ADD => SymbolicTy::BV(binop!(bv.lhs, bv.rhs, bvadd)),
            ConcolicOp::DIV => SymbolicTy::BV(binop!(bv.lhs, bv.rhs, bvudiv)),
            ConcolicOp::MUL => SymbolicTy::BV(binop!(bv.lhs, bv.rhs, bvmul)),
            ConcolicOp::SUB => SymbolicTy::BV(binop!(bv.lhs, bv.rhs, bvsub)),
            ConcolicOp::SDIV => SymbolicTy::BV(binop!(bv.lhs, bv.rhs, bvsdiv)),
            ConcolicOp::SMOD => SymbolicTy::BV(binop!(bv.lhs, bv.rhs, bvsmod)),
            ConcolicOp::UREM => SymbolicTy::BV(binop!(bv.lhs, bv.rhs, bvurem)),
            ConcolicOp::SREM => SymbolicTy::BV(binop!(bv.lhs, bv.rhs, bvsrem)),
            ConcolicOp::AND => SymbolicTy::BV(binop!(bv.lhs, bv.rhs, bvand)),
            ConcolicOp::OR => SymbolicTy::BV(binop!(bv.lhs, bv.rhs, bvor)),
            ConcolicOp::XOR => SymbolicTy::BV(binop!(bv.lhs, bv.rhs, bvxor)),
            ConcolicOp::NOT => {
                let lhs = self.generate_z3_bv(bv.lhs.as_ref().unwrap(), ctx);
                match lhs {
                    SymbolicTy::BV(lhs) => SymbolicTy::BV(lhs.bvnot()),
                    SymbolicTy::Bool(lhs) => SymbolicTy::Bool(lhs.not()),
                }
            }
            ConcolicOp::SHL => SymbolicTy::BV(binop!(bv.lhs, bv.rhs, bvshl)),
            ConcolicOp::SHR => SymbolicTy::BV(binop!(bv.lhs, bv.rhs, bvlshr)),
            ConcolicOp::SAR => SymbolicTy::BV(binop!(bv.lhs, bv.rhs, bvashr)),
            ConcolicOp::SLICEDINPUT(idx) => {
                let idx = idx.as_limbs()[0] as u32;
                let skv = self.slice_input(idx, idx + 32);
                println!("[concolic] SLICEDINPUT: {} {:?}", idx, skv);
                SymbolicTy::BV(skv)
            }
            ConcolicOp::BALANCE => SymbolicTy::BV(self.balance.clone()),
            ConcolicOp::CALLVALUE => SymbolicTy::BV(self.calldatavalue.clone()),
            ConcolicOp::FINEGRAINEDINPUT(start, end) => {
                SymbolicTy::BV(self.slice_input(*start, *end))
            }
            ConcolicOp::LNOT => {
                let lhs = self.generate_z3_bv(bv.lhs.as_ref().unwrap(), ctx);
                match lhs {
                    SymbolicTy::BV(lhs) => SymbolicTy::BV(lhs.not()),
                    SymbolicTy::Bool(lhs) => SymbolicTy::Bool(lhs.not()),
                }
            }
            ConcolicOp::CONSTBYTE(b) => SymbolicTy::BV(BV::from_u64(ctx, *b as u64, 8)),
            ConcolicOp::SYMBYTE(s) => SymbolicTy::BV(BV::new_const(ctx, s.clone(), 8)),
            ConcolicOp::EQ => comparisons2!(bv.lhs, bv.rhs, _eq),
            ConcolicOp::LT => comparisons1!(bv.lhs, bv.rhs, bvult),
            ConcolicOp::SLT => comparisons1!(bv.lhs, bv.rhs, bvslt),
            ConcolicOp::GT => comparisons1!(bv.lhs, bv.rhs, bvugt),
            ConcolicOp::SGT => comparisons1!(bv.lhs, bv.rhs, bvsgt),
            ConcolicOp::SELECT(idx) => {
                // let lhs = self.generate_z3_bv(bv.lhs.as_ref().unwrap(), ctx);
                // lhs.expect_bv().extract(*idx, *idx)
                todo!("SELECT")
            },

        }
    }

    pub fn solve(&mut self) -> Option<String> {
        let context = self.context;
        let solver = Solver::new(&context);
        for cons in self.constraints {
            // println!("Constraints: {:?}", cons);
            let bv = self.generate_z3_bv(&cons.lhs.as_ref().unwrap(), &context);
            solver.assert(&match cons.op {
                ConcolicOp::GT => bv.expect_bv().bvugt(
                    &self
                        .generate_z3_bv(&cons.rhs.as_ref().unwrap(), &context)
                        .expect_bv(),
                ),
                ConcolicOp::SGT => bv.expect_bv().bvsgt(
                    &self
                        .generate_z3_bv(&cons.rhs.as_ref().unwrap(), &context)
                        .expect_bv(),
                ),
                ConcolicOp::EQ => bv.expect_bv()._eq(
                    &self
                        .generate_z3_bv(&cons.rhs.as_ref().unwrap(), &context)
                        .expect_bv(),
                ),
                ConcolicOp::LT => bv.expect_bv().bvult(
                    &self
                        .generate_z3_bv(&cons.rhs.as_ref().unwrap(), &context)
                        .expect_bv(),
                ),
                ConcolicOp::SLT => bv.expect_bv().bvslt(
                    &self
                        .generate_z3_bv(&cons.rhs.as_ref().unwrap(), &context)
                        .expect_bv(),
                ),
                ConcolicOp::LNOT => match bv {
                    SymbolicTy::BV(bv) => bv._eq(&bv_from_u256!(EVMU256::ZERO, &context)),
                    SymbolicTy::Bool(bv) => bv.not(),
                },
                _ => panic!("{:?} not implemented for constraint solving", cons.op),
            });
        }

        // println!("Solver: {:?}", solver);
        let result = solver.check();
        match result {
            z3::SatResult::Sat => {
                let model = solver.get_model().unwrap();
                Some(
                    self.input
                        .iter()
                        .map(|x| model.eval(x, true).unwrap().to_string())
                        .collect::<Vec<_>>()
                        .join(""),
                )
            }
            z3::SatResult::Unsat => None,
            z3::SatResult::Unknown => todo!(),
        }
    }
}

// Note: To model concolic memory, we need to remember previous constraints as well.
// when solving a constraint involving persistant memory, if the persistant memory is not
// depenent on other non-persitent variables, this means that the persistant memory change
// might not be feasible, because the persistant memory cannot change it self.
// Example:
//     // in this case, even if we get the constraints for the memory element m[0]
//     // we cannot solve it (invert it), because the memory element is cannot change
//     // it self.
//     m = [0, 0, 0, 0]
//     fn f(a):
//         if m[0] == 0:
//             do something
//         else:
//             bug
//     // in this case, we can actually solve for m[0]!=0, becuase the memeory element
//     // is dependent on the input a.
//     fn g(a):
//         m[0] = a
//         if m[0] == 0:
//             do something
//         else:
//             bug

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct EVMInputConstraint {
//     // concrete data of EVM Input
//     data: Bytes,
//     input_constraints: Vec<Box<Expr>>,
// }

// impl EVMInputConstraint {
//     pub fn new(vm_input: BoxedABI) -> Self {
//         // TODO: build input constraints from ABI
//         let mut input_constraints = vec![];
//         // input_constraints.push()

//         Self {
//             data: Bytes::from(vm_input.get_bytes()),
//             input_constraints: input_constraints,
//         }
//     }

//     pub fn add_constraint(&mut self, constraint: Box<Expr>) {
//         self.input_constraints.push(constraint);
//     }

//     pub fn get_constraints(&self) -> &Vec<Box<Expr>> {
//         &self.input_constraints
//     }

//     pub fn get_data(&self) -> &Bytes {
//         &self.data
//     }
// }

// Q: Why do we need to make persistent memory symbolic?

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolicMemory {
    pub memory: Vec<Option<Box<Expr>>>
}

impl SymbolicMemory {
    pub fn new() -> Self {
        Self {
            memory: vec![]
        }
    }

    pub fn insert_256(&mut self, idx: EVMU256, val: Box<Expr>) {
        let idx = idx.as_limbs()[0] as usize;
        if idx >= self.memory.len() {
            self.memory.resize(idx + 1, None);
        }
        self.memory[idx] = Some(val);
    }

    pub fn insert_8(&mut self, idx: EVMU256, val: Box<Expr>) {
        // TODO: use SELECT instead of concrete value
        let idx = idx.as_limbs()[0] as usize;
        if idx >= self.memory.len() {
            self.memory.resize(idx + 1, None);
        }
        self.memory[idx] = None;
    }

    pub fn get_256(&self, idx: EVMU256) -> Option<Box<Expr>> {
        let idx = idx.as_limbs()[0] as usize;
        if idx >= self.memory.len() {
            return None;
        }
        self.memory[idx].clone()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConcolicHost<I, VS> {
    pub symbolic_stack: Vec<Option<Box<Expr>>>,
    pub symbolic_memory: SymbolicMemory,
    pub symbolic_state: HashMap<EVMU256, Option<Box<Expr>>>,
    pub input_bytes: Vec<Box<Expr>>,
    pub constraints: Vec<Box<Expr>>,
    pub caller: EVMAddress,
    pub testcase_ref: Arc<EVMInput>,
    pub phantom: PhantomData<(I, VS)>,
}

impl<I, VS> ConcolicHost<I, VS> {
    pub fn new(testcase_ref: Arc<EVMInput>) -> Self {
        Self {
            symbolic_stack: Vec::new(),
            symbolic_memory: SymbolicMemory::new(),
            symbolic_state: Default::default(),
            input_bytes: Self::construct_input_from_abi(testcase_ref.get_data_abi().expect("data abi not found")),
            constraints: vec![],
            caller: testcase_ref.caller,
            testcase_ref,
            phantom: Default::default(),
        }
    }

    fn construct_input_from_abi(vm_input: BoxedABI) -> Vec<Box<Expr>> {
        let res = vm_input.get_concolic();
        println!("[concolic] construct_input_from_abi: {:?}", res);
        res
    }

    fn string_to_bytes(s: &str) -> Vec<u8> {
        // s: #x....
        hex::decode(&s[2..]).unwrap()
    }

    pub fn solve(&self) -> Option<String> {
        let context = Context::new(&Config::default());
        // let input = (0..self.bytes)
        //     .map(|idx| BV::new_const(&context, format!("input_{}", idx), 8))
        //     .collect::<Vec<_>>();
        let callvalue = BV::new_const(&context, "callvalue", 256);
        let balance = BV::new_const(&context, "balance", 256);

        let mut solving = Solving::new(&context, &self.input_bytes, &balance, &callvalue, &self.constraints);
        let input_str = solving.solve();
        match input_str {
            Some(s) => {
                // let bytes = Self::string_to_bytes(&s);
                Some(s)
            }
            None => None,
        }
    }
}

// TODO: test this
fn str_to_bytes(s: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for c in s.chars() {
        bytes.push(c as u8);
    }
    bytes
}

impl<I, VS, S> Middleware<VS, I, S> for ConcolicHost<I, VS>
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    VS: VMStateT,
    S: State
        + HasCaller<EVMAddress>
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
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
        macro_rules! fast_peek {
            ($idx:expr) => {
                interp.stack.peek(interp.stack.len() - 1 - $idx)
            };
        }

        macro_rules! stack_bv {
            ($idx:expr) => {{
                let real_loc_sym = self.symbolic_stack.len() - 1 - $idx;
                match self.symbolic_stack[real_loc_sym].borrow() {
                    Some(bv) => bv.clone(),
                    None => {
                        let u256 = fast_peek!(real_loc_sym).expect("stack underflow");
                        Box::new(Expr {
                            lhs: None,
                            rhs: None,
                            op: ConcolicOp::EVMU256(u256),
                        })
                    }
                }
            }};
        }

        macro_rules! stack_concrete {
            ($idx:expr) => {{
                let real_loc_conc = interp.stack.len() - 1 - $idx;
                let u256 = interp.stack.peek(real_loc_conc).expect("stack underflow");
                u256
            }};
        }

        macro_rules! concrete_eval {
            ($in_cnt: expr, $out_cnt: expr) => {
                {
                    println!("[concolic] concrete_eval: {} {}", $in_cnt, $out_cnt);
                    for _ in 0..$in_cnt {
                        self.symbolic_stack.pop();
                    }
                    vec![None; $out_cnt]
                }
            };
        }


        let mut solutions = Vec::<String>::new();

        // TODO: Figure out the corresponding MiddlewareOp to add
        // We may need coverage map here to decide whether to add a new input to the
        // corpus or not.
        println!("[concolic] on_step @ {:x}: {:x}", interp.program_counter(), *interp.instruction_pointer);
        // println!("[concolic] stack: {:?}", interp.stack);
        // println!("[concolic] symbolic_stack: {:?}", self.symbolic_stack);


        for idx in 0..interp.stack.len() {
            let real = interp.stack.data[idx].clone();
            let sym = self.symbolic_stack[idx].clone();
            if sym.is_some() {
                match sym.unwrap().op {
                    ConcolicOp::EVMU256(v) => {
                        assert_eq!(real, v);
                    }
                    _ => {}
                }
            }
        }


        assert_eq!(interp.stack.len(), self.symbolic_stack.len());
        let bv: Vec<Option<Box<Expr>>> = match *interp.instruction_pointer {
            // ADD
            0x01 => {
                let res = Some(stack_bv!(0).add(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // MUL
            0x02 => {
                let res = Some(stack_bv!(0).mul(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SUB
            0x03 => {
                let res = Some(stack_bv!(0).sub(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // DIV - is this signed?
            0x04 => {
                let res = Some(stack_bv!(0).div(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SDIV
            0x05 => {
                let res = Some(stack_bv!(0).bvsdiv(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // MOD
            0x06 => {
                let res = Some(stack_bv!(0).bvurem(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SMOD
            0x07 => {
                let res = Some(stack_bv!(0).bvsmod(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // ADDMOD
            0x08 => {
                let res = Some(stack_bv!(0).add(stack_bv!(1)).bvsmod(stack_bv!(2)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // MULMOD
            0x09 => {
                let res = Some(stack_bv!(0).mul(stack_bv!(1)).bvsmod(stack_bv!(2)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // EXP - fallback to concrete due to poor Z3 performance support
            0x0a => {
                concrete_eval!(2, 1)
            }
            // SIGNEXTEND - FIXME: need to check
            0x0b => {
                concrete_eval!(2, 1)
            }
            // LT
            0x10 => {
                let res = Some(stack_bv!(0).bvult(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // GT
            0x11 => {
                let res = Some(stack_bv!(0).bvugt(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SLT
            0x12 => {
                let res = Some(stack_bv!(0).bvslt(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SGT
            0x13 => {
                let res = Some(stack_bv!(0).bvsgt(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // EQ
            0x14 => {
                let res = Some(stack_bv!(0).eq(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // ISZERO
            0x15 => {
                let res = Some(stack_bv!(0).eq(Box::new(Expr {
                    lhs: None,
                    rhs: None,
                    op: ConcolicOp::EVMU256(EVMU256::from(0)),
                })));
                self.symbolic_stack.pop();
                vec![res]
            }
            // AND
            0x16 => {
                let res = Some(stack_bv!(0).bvand(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // OR
            0x17 => {
                let res = Some(stack_bv!(0).bvor(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // XOR
            0x18 => {
                let res = Some(stack_bv!(0).bvxor(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // NOT
            0x19 => {
                let res = Some(stack_bv!(0).bvnot());
                self.symbolic_stack.pop();
                vec![res]
            }
            // BYTE
            // FIXME: support this
            0x1a => {
                concrete_eval!(2, 1)
            }
            // SHL
            0x1b => {
                let res = Some(stack_bv!(1).bvshl(stack_bv!(0)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SHR
            0x1c => {
                let res = Some(stack_bv!(1).bvlshr(stack_bv!(0)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SAR
            0x1d => {
                let res = Some(stack_bv!(1).bvsar(stack_bv!(0)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SHA3
            0x20 => {
                concrete_eval!(2, 1)
            }
            // ADDRESS
            0x30 => {
                vec![None]
            }
            // BALANCE
            // TODO: need to get value from a hashmap
            0x31 => {
                concrete_eval!(1, 1)
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
                vec![Some(Expr::new_callvalue())]
            }
            // CALLDATALOAD
            0x35 => {
                self.symbolic_stack.pop();
                vec![Some(Expr::new_sliced_input(interp.stack.peek(0).unwrap()))]
            }
            // CALLDATASIZE
            0x36 => {
                vec![None]
            }
            // CALLDATACOPY
            0x37 => {
                concrete_eval!(3, 0)
            }
            // CODESIZE
            0x38 => {
                vec![None]
            }
            // CODECOPY
            0x39 => {
                concrete_eval!(3, 0)
            }
            // GASPRICE
            0x3a => {
                vec![None]
            }
            // EXTCODESIZE
            0x3b => {
                concrete_eval!(1, 1)
            }
            // EXTCODECOPY
            0x3c => {
                concrete_eval!(4, 0)
            }
            // RETURNDATASIZE
            0x3d => {
                vec![None]
            }
            // RETURNDATACOPY
            0x3e => {
                concrete_eval!(3, 0)
            }
            // EXTCODEHASH
            0x3f => {
                concrete_eval!(1, 1)
            }
            // BLOCKHASH
            0x40 => {
                concrete_eval!(1, 1)
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
                self.symbolic_stack.pop();
                vec![]
            }
            // MLOAD
            0x51 => {
                println!("[concolic] MLOAD: {:?}", self.symbolic_stack);
                let offset = fast_peek!(0).expect("[Concolic] MLOAD stack error at 0");
                self.symbolic_stack.pop();
                vec![self.symbolic_memory.get_256(offset)]
            }
            // MSTORE
            0x52 => {
                let offset = fast_peek!(0).expect("[Concolic] MSTORE stack error at 1");
                let value = stack_bv!(1);
                self.symbolic_memory.insert_256(offset, value);
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![]
            }
            // MSTORE8
            0x53 => {
                let offset = fast_peek!(0).expect("[Concolic] MSTORE8 stack error at 1");
                let value = stack_bv!(1);
                self.symbolic_memory.insert_8(offset, value);
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![]
            }
            // SLOAD
            0x54 => {
                self.symbolic_stack.pop();
                let key = fast_peek!(0).expect("[Concolic] SLOAD stack error at 0");
                vec![match self.symbolic_state.get(&key) {
                    Some(v) => v.clone(),
                    None => None,
                }]
            }
            // SSTORE
            0x55 => {
                let key = fast_peek!(1).expect("[Concolic] SSTORE stack error at 1");
                let value = stack_bv!(0);
                self.symbolic_state.insert(key, Some(value));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![]
            }
            // JUMP
            0x56 => {
                concrete_eval!(1, 0)
            }
            // JUMPI
            0x57 => {
                // println!("{:?}", interp.stack);
                // println!("{:?}", self.symbolic_stack);
                // jump dest in concolic solving mode is the opposite of the concrete
                let jmp_dest = if !is_zero(fast_peek!(1)
                    .expect("[Concolic] JUMPI stack error at 1"))
                {
                    1
                } else {
                    as_u64(fast_peek!(0)
                        .expect("[Concolic] JUMPI stack error at 0"))
                };
                let idx = (interp.program_counter() * (jmp_dest as usize)) % MAP_SIZE;
                let path_constraint = stack_bv!(1);
                if JMP_MAP[idx] == 0 && !path_constraint.is_concrete() {
                    self.constraints.push(path_constraint.clone().lnot());
                    println!("[concolic] to solve {:?}", self.constraints);

                    match self.solve() {
                        Some(s) => solutions.push(s),
                        None => {}
                    };
                    println!("[concolic] Solutions: {:?}", solutions);
                    self.constraints.pop();
                }
                // jumping only happens if the second element is false
                if !path_constraint.is_concrete() {
                    self.constraints.push(path_constraint);
                }
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![]
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
                // Concolic push n bytes is equivalent to concrete push, because the bytes
                // being pushed are always concrete, we can just push None to the stack
                // and 'fallthrough' to concrete values later
                vec![None]
            }
            // DUP
            0x80..=0x8f => {
                let _n = (*interp.instruction_pointer) - 0x80 + 1;
                vec![Some(stack_bv!(usize::from(_n - 1)).clone())]
            }
            // SWAP
            0x90..=0x9f => {
                let _n = (*interp.instruction_pointer) - 0x90 + 1;
                let swapper = stack_bv!(usize::from(_n));
                let swappee = stack_bv!(0);
                let symbolic_stack_len = self.symbolic_stack.len();
                self.symbolic_stack[symbolic_stack_len - usize::from(_n) - 1] = Some(swapper);
                self.symbolic_stack[symbolic_stack_len - usize::from(_n) - 1] = Some(swappee);
                vec![]
            }
            // LOG
            0xa0..=0xa4 => {
                let _n = (*interp.instruction_pointer) - 0xa0;
                concrete_eval!(_n + 2, 0)
            }
            // CREATE
            0xf0 => {
                concrete_eval!(3, 1)
            }
            // CALL
            0xf1 => {
                concrete_eval!(7, 1)
            }
            // CALLCODE
            0xf2 => {
                concrete_eval!(7, 1)
            }
            // RETURN
            0xf3 => {
                concrete_eval!(2, 0)
            }
            // DELEGATECALL
            0xf4 => {
                concrete_eval!(6, 1)
            }
            // CREATE2
            0xf5 => {
                concrete_eval!(4, 1)
            }
            // STATICCALL
            0xfa => {
                concrete_eval!(6, 1)
            }
            // REVERT
            0xfd => {
                concrete_eval!(2, 0)
            }
            // INVALID
            0xfe => {
                vec![]
            }
            // SELFDESTRUCT
            0xff => {
                concrete_eval!(1, 0)
            }
            // STOP
            0x00 => {
                vec![]
            }
            _ => {
                panic!("Unsupported opcode: {:?}", *interp.instruction_pointer);
                vec![]
            }
        };
        // println!("[concolic] adding bv to stack {:?}", bv);
        for v in bv {
            self.symbolic_stack.push(v);
        }

        // let input = state
        //     .corpus()
        //     .get(state.get_current_input_idx())
        //     .unwrap()
        //     .borrow_mut()
        //     .load_input()
        //     .expect("Failed loading input")
        //     .clone();
        for s in solutions {
            println!("Solution: {:?}", s);
            // let mut new_input = input.clone();
            // new_input
            //     .get_data_abi_mut()
            //     .as_mut()
            //     .unwrap()
            //     .set_bytes(str_to_bytes(&s));
            // let new_evm_input = new_input.as_any().downcast_ref::<EVMInput>().unwrap();
            // add_corpus(host, state, &new_evm_input);
        }
    }

    unsafe fn on_insert(&mut self, bytecode: &mut Bytecode, address: EVMAddress, host: &mut FuzzHost<VS, I, S>, state: &mut S) {

    }

    fn get_type(&self) -> MiddlewareType {
        Concolic
    }
}
