use bytes::Bytes;
use primitive_types::{H160, H256, U256};
use revm::db::BenchmarkDB;
use std::any::Any;
use std::iter::Map;

use crate::evm::abi::{AEmpty, BoxedABI};
use crate::evm::middleware::MiddlewareType::Concolic;
use crate::evm::middleware::{add_corpus, Middleware, MiddlewareOp, MiddlewareType};
use crate::evm::vm::{jmp_map, IntermediateExecutionResult, FuzzHost};
use crate::generic_vm::vm_executor::MAP_SIZE;
use crate::generic_vm::vm_state::VMStateT;
use crate::state::{HasCaller, HasItyState};
use revm::Return::Continue;
use revm::{
    Bytecode, CallInputs, CreateInputs, Env, Gas, Host, Interpreter, Return, SelfDestructResult,
    Spec,
};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::{Add, Mul, Not, Sub};
use std::str::FromStr;
use std::sync::Arc;
use libafl::prelude::{HasMetadata, Input};
use libafl::schedulers::Scheduler;
use libafl::state::{HasCorpus, State};
use z3::ast::BV;
use z3::{ast::Ast, Config, Context, Solver};
use crate::evm::types::EVMFuzzState;
use crate::input::VMInputT;

pub static mut CONCOLIC_MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];

#[derive(Clone, Debug, Serialize, Deserialize)]
enum ConcolicOp {
    U256(U256),
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
    SLICEDINPUT(U256),
    BALANCE,
    CALLVALUE,
    // Represent a symbolic BV with width u32
    BVVAR(u32),
    // symbolic byte
    SYMBYTE(String),
    // helper OP for concrete btyes
    CONSTBYTES(Bytes),
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Expr {
    lhs: Option<Box<Expr>>,
    rhs: Option<Box<Expr>>,
    // concrete should be used in constant folding
    // concrete: Option<U256>,
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
        let u64x4 = $val.0;
        let bv = BV::from_u64(&$ctx, u64x4[0], 64);
        let bv = bv.concat(&BV::from_u64(&$ctx, u64x4[1], 64));
        let bv = bv.concat(&BV::from_u64(&$ctx, u64x4[2], 64));
        let bv = bv.concat(&BV::from_u64(&$ctx, u64x4[3], 64));
        bv
    }};
}

impl Expr {
    pub fn new_sliced_input(idx: U256) -> Box<Expr> {
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

    pub fn new_bv_with_width(width: u32) -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::BVVAR(width),
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
}

pub struct Solving<'a> {
    context: &'a Context,
    input: &'a Vec<BV<'a>>,
    balance: &'a BV<'a>,
    calldatavalue: &'a BV<'a>,
    constraints: &'a Vec<Box<Expr>>,
}

impl<'a> Solving<'a> {
    fn new(
        context: &'a Context,
        input: &'a Vec<BV<'a>>,
        balance: &'a BV<'a>,
        calldatavalue: &'a BV<'a>,
        constraints: &'a Vec<Box<Expr>>,
    ) -> Self {
        Solving {
            context,
            input,
            balance,
            calldatavalue,
            constraints,
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

    pub fn generate_z3_bv(&mut self, bv: &Expr, ctx: &'a Context) -> BV<'a> {
        macro_rules! binop {
            ($lhs:expr, $rhs:expr, $op:ident) => {
                self.generate_z3_bv($lhs.as_ref().unwrap(), ctx)
                    .$op(&self.generate_z3_bv($rhs.as_ref().unwrap(), ctx))
            };
        }
        // println!("generate_z3_bv: {:?}", bv);
        match &bv.op {
            ConcolicOp::U256(constant) => bv_from_u256!(constant, ctx),
            ConcolicOp::ADD => binop!(bv.lhs, bv.rhs, bvadd),
            ConcolicOp::DIV => binop!(bv.lhs, bv.rhs, bvudiv),
            ConcolicOp::MUL => binop!(bv.lhs, bv.rhs, bvmul),
            ConcolicOp::SUB => binop!(bv.lhs, bv.rhs, bvsub),
            ConcolicOp::SDIV => binop!(bv.lhs, bv.rhs, bvsdiv),
            ConcolicOp::SMOD => binop!(bv.lhs, bv.rhs, bvsmod),
            ConcolicOp::UREM => binop!(bv.lhs, bv.rhs, bvurem),
            ConcolicOp::SREM => binop!(bv.lhs, bv.rhs, bvsrem),
            ConcolicOp::AND => binop!(bv.lhs, bv.rhs, bvand),
            ConcolicOp::OR => binop!(bv.lhs, bv.rhs, bvor),
            ConcolicOp::XOR => binop!(bv.lhs, bv.rhs, bvxor),
            ConcolicOp::NOT => self.generate_z3_bv(bv.lhs.as_ref().unwrap(), ctx).bvnot(),
            ConcolicOp::SHL => binop!(bv.lhs, bv.rhs, bvshl),
            ConcolicOp::SHR => binop!(bv.lhs, bv.rhs, bvlshr),
            ConcolicOp::SAR => binop!(bv.lhs, bv.rhs, bvashr),
            ConcolicOp::SLICEDINPUT(idx) => {
                let idx = idx.0[0] as u32;
                self.slice_input(idx, idx + 4)
            }
            ConcolicOp::BALANCE => self.balance.clone(),
            ConcolicOp::CALLVALUE => self.calldatavalue.clone(),
            ConcolicOp::FINEGRAINEDINPUT(start, end) => self.slice_input(*start, *end),
            ConcolicOp::LNOT => self.generate_z3_bv(bv.lhs.as_ref().unwrap(), ctx).not(),
            ConcolicOp::CONSTBYTE(b) => BV::from_u64(ctx, *b as u64, 8),
            ConcolicOp::SYMBYTE(s) => BV::new_const(ctx, s.clone(), 8),
            ConcolicOp::EQ => self.generate_z3_bv(bv.lhs.as_ref().unwrap(), ctx),  // recursively solve lhs
            _ => panic!("op {:?} not supported as operands", bv.op),
        }
    }

    pub fn solve(&mut self) -> Option<String> {
        let context = self.context;
        let solver = Solver::new(&context);
        for cons in self.constraints {
            // println!("Constraints: {:?}", cons);
            let bv: BV = self.generate_z3_bv(&cons.lhs.as_ref().unwrap(), &context);
            solver.assert(&match cons.op {
                ConcolicOp::GT => {
                    bv.bvugt(&self.generate_z3_bv(&cons.rhs.as_ref().unwrap(), &context))
                }
                ConcolicOp::SGT => {
                    bv.bvsgt(&self.generate_z3_bv(&cons.rhs.as_ref().unwrap(), &context))
                }
                ConcolicOp::EQ => {
                    bv._eq(&self.generate_z3_bv(&cons.rhs.as_ref().unwrap(), &context))
                }
                ConcolicOp::LT => {
                    bv.bvult(&self.generate_z3_bv(&cons.rhs.as_ref().unwrap(), &context))
                }
                ConcolicOp::SLT => {
                    bv.bvslt(&self.generate_z3_bv(&cons.rhs.as_ref().unwrap(), &context))
                }
                _ => panic!("{:?} not implemented for constraint solving", cons.op),
            });
        }

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

#[derive(Debug, Serialize, Deserialize)]
pub struct ConcolicHost<I, VS> {
    symbolic_stack: Vec<Option<Box<Expr>>>,
    input_bytes: Vec<Box<Expr>>,
    constraints: Vec<Box<Expr>>,
    bytes: u32,
    caller: H160,
    phantom: PhantomData<(I, VS)>,
}

impl<I, VS> ConcolicHost<I, VS> {
    pub fn new(bytes: u32, vm_input: BoxedABI, caller: H160) -> Self {
        Self {
            symbolic_stack: Vec::new(),
            input_bytes: Self::construct_input_from_abi(vm_input),
            constraints: vec![],
            bytes,
            caller,
            phantom: Default::default()
        }
    }

    fn construct_input_from_abi(vm_input: BoxedABI) -> Vec<Box<Expr>> {
        vm_input.b.get_concolic()
    }

    fn string_to_bytes(s: &str) -> Vec<u8> {
        // s: #x....
        hex::decode(&s[2..]).unwrap()
    }

    pub fn solve(&self) -> Option<String> {
        let context = Context::new(&Config::default());
        let input = (0..self.bytes)
            .map(|idx| BV::new_const(&context, format!("input_{}", idx), 8))
            .collect::<Vec<_>>();
        let callvalue = BV::new_const(&context, "callvalue", 256);
        let balance = BV::new_const(&context, "balance", 256);

        let mut solving = Solving::new(&context, &input, &balance, &callvalue, &self.constraints);
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

impl<I, VS, S> Middleware<S> for ConcolicHost<I, VS>
    where
        I: Input + VMInputT<VS, H160, H160> + 'static,
        VS: VMStateT,
        S: State + HasCaller<H160> + HasCorpus<I> + HasItyState<H160, H160, VS> + HasMetadata + Debug + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<S>, state: &mut S) {
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
                        let u256 = fast_peek!($idx).expect("stack underflow");
                        Box::new(Expr {
                            lhs: None,
                            rhs: None,
                            op: ConcolicOp::U256(u256),
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

        let mut solutions = Vec::<String>::new();

        // TODO: Figure out the corresponding MiddlewareOp to add
        // We may need coverage map here to decide whether to add a new input to the
        // corpus or not.
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
            // FIXME: should we use bvsrem or bvsmod?
            0x07 => {
                let res = Some(stack_bv!(0).bvsrem(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // ADDMOD
            0x08 => {
                let res = Some(stack_bv!(0).add(stack_bv!(1)).bvsrem(stack_bv!(2)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // MULMOD
            0x09 => {
                let res = Some(stack_bv!(0).mul(stack_bv!(1)).bvsrem(stack_bv!(2)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // EXP - fallback to concrete due to poor Z3 performance support
            0x0a => {
                let res = stack_concrete!(0).pow(stack_concrete!(1));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![Some(Box::new(Expr {
                    lhs: None,
                    rhs: None,
                    op: ConcolicOp::U256(res),
                }))]
            }
            // SIGNEXTEND - FIXME: need to check
            0x0b => {
                // let bv = stack_bv!(0);
                // let bv = bv.bvshl(&self.ctx.bv_val(248, 256));
                // let bv = bv.bvashr(&self.ctx.bv_val(248, 256));
                vec![None]
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
                    op: ConcolicOp::U256(U256::from(0)),
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
            0x1a => {
                // wtf is this
                vec![None]
            }
            // SHL
            0x1b => {
                let res = Some(stack_bv!(0).bvshl(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SHR
            0x1c => {
                let res = Some(stack_bv!(0).bvlshr(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SAR
            0x1d => {
                let res = Some(stack_bv!(0).bvsar(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
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
            // TODO: need to get value from a hashmap
            0x31 => {
                vec![Some(Expr::new_balance())]
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
                vec![Some(Expr::new_sliced_input(interp.stack.peek(0).unwrap()))]
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
                // todo: write to symbolic memory
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![]
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
                self.symbolic_stack.pop();
                vec![]
            }
            // JUMPI
            0x57 => {
                // println!("{:?}", interp.stack);
                // println!("{:?}", self.symbolic_stack);
                // jump dest in concolic solving mode is the opposite of the concrete
                let jump_dest_concolic = if fast_peek!(1)
                    .expect("[Concolic] JUMPI stack error at 1")
                    .is_zero()
                {
                    1
                } else {
                    fast_peek!(0)
                        .expect("[Concolic] JUMPI stack error at 0")
                        .as_u64()
                };
                let idx = (interp.program_counter() * (jump_dest_concolic as usize)) % MAP_SIZE;
                if jmp_map[idx] == 0 {
                    let path_constraint = stack_bv!(1);
                    self.constraints.push(path_constraint.lnot().eq(Box::new(
                        Expr {
                            lhs: None,
                            rhs: None,
                            op: ConcolicOp::U256(U256::from(1))
                        }
                    )));
                    match self.solve() {
                        Some(s) => solutions.push(s),
                        None => {}
                    };
                    self.constraints.pop();
                }
                // jumping only happens if the second element is false
                self.constraints.push(stack_bv!(1));
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
                vec![
                    Some(stack_bv!(usize::from(_n - 1)).clone())
                ]
            }
            // SWAP
            0x90..=0x9f => {
                let _n = (*interp.instruction_pointer) - 0x90 + 1;
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


        for s in solutions {
            add_corpus(host, self.caller, &s.to_string(), state);
        }
    }

    fn get_type(&self) -> MiddlewareType {
        Concolic
    }

}
