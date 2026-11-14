//! Drishti IR (spec §7.4): a small, typed, P-code-like intermediate
//! representation where every value has a bit width.
//!
//! This crate is milestone **B1**: the IR types, a pretty-printer and a
//! reference interpreter. The AArch64 / x86-64 lifters (B2) and the
//! Unicorn differential tests (B3) build on it. See `docs/IR.md`.
#![forbid(unsafe_code)]

mod interp;
pub use interp::{State, Step, StepError};

use serde::{Deserialize, Serialize};

/// A value's width in bits (8, 16, 32, 64, 1 for flags, up to 128).
pub type Width = u16;

/// A storage location ("varnode").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Var {
    /// A named machine register or flag, e.g. `("rax", 64)`, `("ZF", 1)`.
    Reg { name: String, width: Width },
    /// A lifter-local temporary.
    Temp { id: u32, width: Width },
    /// A constant of the given width.
    Const { value: u128, width: Width },
    /// A memory cell of `width` bits at the (little-endian) address that the
    /// `addr` varnode evaluates to.
    Mem { addr: Box<Var>, width: Width },
}

impl Var {
    pub fn width(&self) -> Width {
        match self {
            Var::Reg { width, .. }
            | Var::Temp { width, .. }
            | Var::Const { width, .. }
            | Var::Mem { width, .. } => *width,
        }
    }
    pub fn reg(name: &str, width: Width) -> Var {
        Var::Reg {
            name: name.to_string(),
            width,
        }
    }
    pub fn temp(id: u32, width: Width) -> Var {
        Var::Temp { id, width }
    }
    pub fn con(value: u128, width: Width) -> Var {
        Var::Const {
            value: mask(value, width),
            width,
        }
    }
    pub fn load(addr: Var, width: Width) -> Var {
        Var::Mem {
            addr: Box::new(addr),
            width,
        }
    }
}

/// Binary operators (two inputs → one output).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    // Integer arithmetic.
    Add,
    Sub,
    Mul,
    Udiv,
    Sdiv,
    Urem,
    Srem,
    // Bitwise.
    And,
    Or,
    Xor,
    Shl,
    Lshr,
    Ashr,
    // Comparison (result width 1).
    Eq,
    Ne,
    Ult,
    Ule,
    Slt,
    Sle,
    // Flag helpers (result width 1): carry/overflow/borrow of `a (op) b`.
    Carry,
    Scarry,
    Sborrow,
}

/// Unary operators (one input → one output).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnOp {
    Neg,
    Not,
    Popcount,
}

/// One IR operation. The destination (where present) fixes the result width.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    // Data movement.
    Copy {
        dst: Var,
        a: Var,
    },
    Load {
        dst: Var,
        addr: Var,
    },
    Store {
        addr: Var,
        a: Var,
    },
    // Computation.
    Bin {
        dst: Var,
        op: BinOp,
        a: Var,
        b: Var,
    },
    Un {
        dst: Var,
        op: UnOp,
        a: Var,
    },
    // Width changes.
    Zext {
        dst: Var,
        a: Var,
    },
    Sext {
        dst: Var,
        a: Var,
    },
    Trunc {
        dst: Var,
        a: Var,
    },
    /// `dst = (hi << width(lo)) | lo`.
    Concat {
        dst: Var,
        hi: Var,
        lo: Var,
    },
    /// `dst = bits [lo, hi) of a` (lo inclusive, hi exclusive).
    Extract {
        dst: Var,
        a: Var,
        lo: Width,
        hi: Width,
    },
    // Control flow (targets are machine addresses).
    Branch {
        target: u64,
    },
    CBranch {
        cond: Var,
        target: u64,
    },
    BranchInd {
        target: Var,
    },
    Call {
        target: u64,
    },
    CallInd {
        target: Var,
    },
    Return,
    // Escape hatch and unknown.
    Intrinsic {
        name: String,
        ins: Vec<Var>,
        out: Option<Var>,
    },
    Undef {
        dst: Var,
    },
}

/// One IR operation tagged with the machine address it was lifted from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Insn {
    pub addr: u64,
    pub op: Op,
}

impl Insn {
    pub fn new(addr: u64, op: Op) -> Insn {
        Insn { addr, op }
    }
}

/// Mask `v` to `width` low bits (width 0 or ≥128 leaves it unchanged).
pub fn mask(v: u128, width: Width) -> u128 {
    if width == 0 || width >= 128 {
        v
    } else {
        v & ((1u128 << width) - 1)
    }
}

/// Interpret `v` (width `w`) as a signed value sign-extended to i128.
pub fn sign_extend(v: u128, w: Width) -> i128 {
    if w == 0 || w >= 128 {
        return v as i128;
    }
    let shift = 128 - w as u32;
    ((v << shift) as i128) >> shift
}

// ---- Pretty-printer ---------------------------------------------------------

impl std::fmt::Display for Var {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Var::Reg { name, width } => write!(f, "{name}:{width}"),
            Var::Temp { id, width } => write!(f, "t{id}:{width}"),
            Var::Const { value, width } => write!(f, "{value:#x}:{width}"),
            Var::Mem { addr, width } => write!(f, "*[{addr}]:{width}"),
        }
    }
}

impl BinOp {
    pub fn name(self) -> &'static str {
        use BinOp::*;
        match self {
            Add => "ADD",
            Sub => "SUB",
            Mul => "MUL",
            Udiv => "UDIV",
            Sdiv => "SDIV",
            Urem => "UREM",
            Srem => "SREM",
            And => "AND",
            Or => "OR",
            Xor => "XOR",
            Shl => "SHL",
            Lshr => "LSHR",
            Ashr => "ASHR",
            Eq => "EQ",
            Ne => "NE",
            Ult => "ULT",
            Ule => "ULE",
            Slt => "SLT",
            Sle => "SLE",
            Carry => "CARRY",
            Scarry => "SCARRY",
            Sborrow => "SBORROW",
        }
    }
}

impl UnOp {
    pub fn name(self) -> &'static str {
        match self {
            UnOp::Neg => "NEG",
            UnOp::Not => "NOT",
            UnOp::Popcount => "POPCOUNT",
        }
    }
}

impl std::fmt::Display for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Op::*;
        match self {
            Copy { dst, a } => write!(f, "{dst} = {a}"),
            Load { dst, addr } => write!(f, "{dst} = LOAD [{addr}]"),
            Store { addr, a } => write!(f, "STORE [{addr}] = {a}"),
            Bin { dst, op, a, b } => write!(f, "{dst} = {} {a}, {b}", op.name()),
            Un { dst, op, a } => write!(f, "{dst} = {} {a}", op.name()),
            Zext { dst, a } => write!(f, "{dst} = ZEXT {a}"),
            Sext { dst, a } => write!(f, "{dst} = SEXT {a}"),
            Trunc { dst, a } => write!(f, "{dst} = TRUNC {a}"),
            Concat { dst, hi, lo } => write!(f, "{dst} = CONCAT {hi}, {lo}"),
            Extract { dst, a, lo, hi } => write!(f, "{dst} = EXTRACT {a}[{lo}:{hi}]"),
            Branch { target } => write!(f, "BRANCH {target:#x}"),
            CBranch { cond, target } => write!(f, "CBRANCH {cond}, {target:#x}"),
            BranchInd { target } => write!(f, "BRANCHIND {target}"),
            Call { target } => write!(f, "CALL {target:#x}"),
            CallInd { target } => write!(f, "CALLIND {target}"),
            Return => write!(f, "RETURN"),
            Intrinsic { name, ins, out } => {
                if let Some(o) = out {
                    write!(f, "{o} = ")?;
                }
                write!(f, "INTRINSIC {name}(")?;
                for (i, v) in ins.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{v}")?;
                }
                write!(f, ")")
            }
            Undef { dst } => write!(f, "{dst} = UNDEF"),
        }
    }
}

/// Pretty-print a sequence of IR instructions, one per line, address-tagged.
pub fn render(insns: &[Insn]) -> String {
    let mut s = String::new();
    for i in insns {
        s += &format!("{:#010x}: {}\n", i.addr, i.op);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_and_sign() {
        assert_eq!(mask(0x1ff, 8), 0xff);
        assert_eq!(sign_extend(0xff, 8), -1);
        assert_eq!(sign_extend(0x7f, 8), 127);
        assert_eq!(mask(0xdead, 64), 0xdead);
    }

    #[test]
    fn pretty() {
        let insns = vec![
            Insn::new(
                0x1000,
                Op::Copy {
                    dst: Var::temp(0, 64),
                    a: Var::reg("rax", 64),
                },
            ),
            Insn::new(
                0x1000,
                Op::Bin {
                    dst: Var::reg("rax", 64),
                    op: BinOp::Add,
                    a: Var::temp(0, 64),
                    b: Var::con(8, 64),
                },
            ),
        ];
        let text = render(&insns);
        assert!(text.contains("t0:64 = rax:64"));
        assert!(text.contains("rax:64 = ADD t0:64, 0x8:64"));
    }
}
