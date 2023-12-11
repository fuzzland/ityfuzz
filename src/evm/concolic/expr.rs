use std::ops;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::evm::types::EVMU256;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum ConcolicOp {
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
    CALLER,
    ORIGIN,
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

    // high / low
    SELECT(u32, u32),
    CONCAT,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Expr {
    pub(crate) lhs: Option<Box<Expr>>,
    pub(crate) rhs: Option<Box<Expr>>,
    // concrete should be used in constant folding
    // concrete: Option<EVMU256>,
    pub(crate) op: ConcolicOp,
}

impl Expr {
    fn pretty_print_helper(&self, _paddings: usize) -> String {
        let mut s = String::new();
        let noop = self.lhs.is_none() && self.rhs.is_none();
        if noop {
            s.push_str(format!("{:?}", self.op).as_str());
        } else {
            s.push_str(format!("{:?}(", self.op).as_str());
            s.push_str(
                (match self.lhs {
                    Some(ref lhs) => format!("{},", lhs.pretty_print_helper(_paddings + 1)),
                    None => "".to_string(),
                })
                .to_string()
                .as_str(),
            );
            s.push_str(
                (match self.rhs {
                    Some(ref rhs) => rhs.pretty_print_helper(_paddings + 1),
                    None => "".to_string(),
                })
                .to_string()
                .as_str(),
            );
            s.push_str(")".to_string().as_str());
        }
        s
    }

    pub fn pretty_print(&self) {
        debug!("{}", self.pretty_print_helper(0));
    }

    pub fn pretty_print_str(&self) -> String {
        self.pretty_print_helper(0)
    }
}

// pub struct Constraint {
//     pub lhs: Box<Expr>,
//     pub rhs: Box<Expr>,
//     pub op: ConstraintOp,
// }

// TODO: if both operands are concrete we can do constant folding somewhere
#[macro_export]
macro_rules! box_bv {
    ($lhs:expr, $rhs:expr, $op:expr) => {
        Box::new(Expr {
            lhs: Some(Box::new($lhs)),
            rhs: Some($rhs),
            op: $op,
        })
    };
}

#[macro_export]
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

    pub fn new_caller() -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::CALLER,
        })
    }

    pub fn new_origin() -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::ORIGIN,
        })
    }

    pub fn sliced_input(start: u32, end: u32) -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::FINEGRAINEDINPUT(start, end),
        })
    }

    pub fn concat(self, rhs: Box<Expr>) -> Box<Expr> {
        box_bv!(self, rhs, ConcolicOp::CONCAT)
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

    pub fn equal(self, rhs: Box<Expr>) -> Box<Expr> {
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
            (Some(l), Some(r)) => l.is_concrete() && r.is_concrete(),
            (None, None) => match self.op {
                ConcolicOp::EVMU256(_) => true,
                ConcolicOp::SLICEDINPUT(_) => false,
                ConcolicOp::BALANCE => false,
                ConcolicOp::CALLVALUE => false,
                ConcolicOp::SYMBYTE(_) => false,
                ConcolicOp::CONSTBYTE(_) => true,
                ConcolicOp::FINEGRAINEDINPUT(_, _) => false,
                ConcolicOp::CALLER => false,
                ConcolicOp::ORIGIN => false,
                _ => unreachable!(),
            },
            (Some(l), None) => l.is_concrete(),
            _ => unreachable!(),
        }
    }

    pub fn depth(&self) -> u32 {
        if self.lhs.is_none() && self.rhs.is_none() {
            return 0;
        }

        let mut lhs_depth = 0;
        let mut rhs_depth = 0;

        if let Some(ref l) = self.lhs {
            lhs_depth = l.depth();
        }

        if let Some(ref r) = self.rhs {
            rhs_depth = r.depth();
        }

        std::cmp::max(lhs_depth, rhs_depth) + 1
    }
}

impl ops::Div<Box<Self>> for Expr {
    type Output = Box<Self>;

    fn div(self, rhs: Box<Self>) -> Self::Output {
        box_bv!(self, rhs, ConcolicOp::DIV)
    }
}

impl ops::Mul<Box<Self>> for Expr {
    type Output = Box<Self>;

    fn mul(self, rhs: Box<Self>) -> Self::Output {
        box_bv!(self, rhs, ConcolicOp::MUL)
    }
}

impl ops::Add<Box<Self>> for Expr {
    type Output = Box<Self>;

    fn add(self, rhs: Box<Self>) -> Self::Output {
        box_bv!(self, rhs, ConcolicOp::ADD)
    }
}

impl ops::Sub<Box<Self>> for Expr {
    type Output = Box<Self>;

    fn sub(self, rhs: Box<Self>) -> Self::Output {
        box_bv!(self, rhs, ConcolicOp::SUB)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConcatOptCtx {
    low: u32,
    high: u32,
    on_expr: Option<Box<Expr>>,
}

impl ConcatOptCtx {
    pub fn merge(&mut self, other: ConcatOptCtx) -> bool {
        if other.on_expr != self.on_expr || other.on_expr.is_none() || self.on_expr.is_none() {
            return false;
        }
        if self.low == other.high + 1 {
            self.low = other.low;
            true
        } else if self.high + 1 == other.low {
            self.high = other.high;
            true
        } else {
            false
        }
    }
}

#[allow(clippy::boxed_local)]
fn simplify_concat_select_helper(expr: Box<Expr>) -> (ConcatOptCtx, Box<Expr>) {
    let lhs_info = expr.lhs.map(simplify_concat_select_helper);
    let rhs_info = expr.rhs.map(simplify_concat_select_helper);
    let op = expr.op;
    let mut new_expr = Box::new(Expr {
        lhs: lhs_info.clone().map(|(_ctx, e)| e),
        rhs: rhs_info.clone().map(|(_ctx, e)| e),
        op: op.clone(),
    });

    let mut ctx = ConcatOptCtx {
        low: 0,
        high: 0,
        on_expr: None,
    };

    match op {
        ConcolicOp::CONCAT => {
            let (mut lhs_ctx, _) = lhs_info.unwrap();
            let (rhs_ctx, _) = rhs_info.unwrap();
            if lhs_ctx.merge(rhs_ctx.clone()) {
                ctx = lhs_ctx;
                new_expr = Box::new(Expr {
                    lhs: ctx.on_expr.clone(),
                    rhs: None,
                    op: ConcolicOp::SELECT(ctx.high, ctx.low),
                });
            }
        }
        ConcolicOp::SELECT(high, low) => {
            ctx.low = low;
            ctx.high = high;
            assert!(new_expr.lhs.is_some());
            ctx.on_expr = new_expr.lhs.clone();
        }

        _ => {}
    }
    (ctx, new_expr)
}

pub fn simplify_concat_select(expr: Box<Expr>) -> Box<Expr> {
    simplify_concat_select_helper(expr).1
}

pub fn simplify(expr: Box<Expr>) -> Box<Expr> {
    simplify_concat_select(expr)
}

#[cfg(test)]
mod test {
    use crate::evm::concolic::expr::{
        simplify_concat_select,
        ConcolicOp,
        ConcolicOp::{CONSTBYTE, SELECT},
        Expr,
    };

    #[test]
    fn test_simplify_concat_select_single() {
        let left_expr = Expr {
            lhs: Some(Box::new(Expr {
                lhs: None,
                rhs: None,
                op: CONSTBYTE(0x12),
            })),
            rhs: None,
            op: ConcolicOp::SELECT(7, 0),
        };

        let right_expr = Expr {
            lhs: Some(Box::new(Expr {
                lhs: None,
                rhs: None,
                op: CONSTBYTE(0x12),
            })),
            rhs: None,
            op: ConcolicOp::SELECT(15, 8),
        };

        let expr = Expr {
            lhs: Some(Box::new(left_expr)),
            rhs: Some(Box::new(right_expr)),
            op: ConcolicOp::CONCAT,
        };

        let new_expr = super::simplify_concat_select(Box::new(expr));
        assert_eq!(new_expr.op, ConcolicOp::SELECT(15, 0));
    }

    fn expression_builder(starting_expr: Expr) -> Box<Expr> {
        let mut current_expr = Box::new(Expr {
            lhs: Some(Box::new(starting_expr.clone())),
            rhs: None,
            op: ConcolicOp::SELECT(255, 248),
        });

        for i in 1..32 {
            current_expr = Box::new(Expr {
                lhs: Some(current_expr),
                rhs: Some(Box::new(Expr {
                    lhs: Some(Box::new(starting_expr.clone())),
                    rhs: None,
                    op: ConcolicOp::SELECT(256 - i * 8 - 1, 256 - i * 8 - 7 - 1),
                })),
                op: ConcolicOp::CONCAT,
            });
        }
        current_expr
    }

    #[test]
    fn test_simplify_concat_select_multi() {
        let starting_expr = Expr {
            lhs: None,
            rhs: None,
            op: CONSTBYTE(0x12),
        };
        let new_expr = super::simplify_concat_select(expression_builder(starting_expr));
        assert_eq!(new_expr.op, ConcolicOp::SELECT(255, 0));
    }

    #[test]
    fn test_simplify_concat_select_internal() {
        let starting_expr1 = Expr {
            lhs: None,
            rhs: None,
            op: CONSTBYTE(0x12),
        };

        let intermediate = Expr {
            lhs: Some(expression_builder(starting_expr1)),
            rhs: None,
            op: ConcolicOp::ADD,
        };

        let starting_expr2 = Expr {
            lhs: Some(Box::new(intermediate.clone())),
            rhs: Some(expression_builder(intermediate)),
            op: ConcolicOp::DIV,
        };

        let new_expr = super::simplify_concat_select(Box::new(Expr {
            lhs: Some(Box::new(starting_expr2)),
            rhs: None,
            op: ConcolicOp::ADD,
        }));

        new_expr.pretty_print();
    }

    #[test]
    fn test_simplify_concat_select_internal_with_concat() {
        let starting_expr1 = Expr {
            lhs: None,
            rhs: None,
            op: CONSTBYTE(0x12),
        };

        let starting_expr2 = Expr {
            lhs: Some(Box::new(starting_expr1.clone())),
            rhs: None,
            op: SELECT(88, 88),
        };

        let mut current_expr = Box::new(starting_expr2);

        for i in 1..3 {
            current_expr = Box::new(Expr {
                lhs: Some(current_expr),
                rhs: Some(Box::new(Expr {
                    lhs: Some(Box::new(starting_expr1.clone())),
                    rhs: None,
                    op: ConcolicOp::SELECT(256 - i * 8 - 1, 256 - i * 8 - 7 - 1),
                })),
                op: ConcolicOp::CONCAT,
            });
        }

        current_expr.pretty_print();

        simplify_concat_select(current_expr).pretty_print();
    }
}
