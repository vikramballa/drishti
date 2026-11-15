//! Drishti IR (spec §7.4): a small, typed, P-code-like intermediate
//! representation where every value has a bit width.
//!
//! Milestone **B1** (types, pretty-printer, reference interpreter), shrunk
//! before the lifters land (Day 2): registers are `u16` ids into a
//! per-architecture table, constants are `u64` with a rare boxed wide
//! variant, and destinations are a separate [`Place`] type (a register or a
//! temporary), so memory is only reached through `Load` / `Store`.
//! `Var` is 16 bytes and `Insn` 56 bytes, with no heap use except for wide
//! constants and intrinsics. See `docs/IR.md`.
#![forbid(unsafe_code)]

mod interp;
mod regs;
pub use interp::{State, Step, StepError};
pub use regs::{Arch, RegId, RegInfo};

use serde::{Deserialize, Serialize};

/// A value's width in bits (8, 16, 32, 64, 1 for flags, up to 128).
pub type Width = u16;

/// A value an operation reads: a register, a temporary or a constant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Var {
    /// A machine register or flag. A width below the register's own width
    /// reads its low bits (`w0` = `Reg { x0, 32 }`).
    Reg { id: RegId, width: Width },
    /// A lifter-local temporary.
    Temp { id: u32, width: Width },
    /// A constant of up to 64 bits.
    Const { value: u64, width: Width },
    /// A constant wider than 64 bits (rare: vector immediates).
    Wide { value: Box<u128>, width: Width },
}

/// Where an operation writes: a register or a temporary. Constants and
/// memory are not destinations (memory is written only by `Store`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Place {
    /// A width below the register's own width writes the low bits and
    /// zero-extends into the rest (AArch64 `W`/scalar-FP writes, x86-64
    /// 32-bit writes). Writes that keep the upper bits (x86 `ax`/`al`) are
    /// lifted explicitly.
    Reg {
        id: RegId,
        width: Width,
    },
    Temp {
        id: u32,
        width: Width,
    },
}

impl Var {
    pub fn width(&self) -> Width {
        match self {
            Var::Reg { width, .. }
            | Var::Temp { width, .. }
            | Var::Const { width, .. }
            | Var::Wide { width, .. } => *width,
        }
    }
    /// The whole register.
    pub fn reg(id: RegId) -> Var {
        Var::Reg {
            id,
            width: id.width(),
        }
    }
    /// The low `width` bits of a register.
    pub fn reg_w(id: RegId, width: Width) -> Var {
        Var::Reg { id, width }
    }
    pub fn temp(id: u32, width: Width) -> Var {
        Var::Temp { id, width }
    }
    /// A constant, masked to `width`. Widths above 64 use the boxed
    /// [`Var::Wide`] form.
    pub fn con(value: u128, width: Width) -> Var {
        let value = mask(value, width);
        if width <= 64 {
            Var::Const {
                value: value as u64,
                width,
            }
        } else {
            Var::Wide {
                value: Box::new(value),
                width,
            }
        }
    }
}

impl Place {
    pub fn width(&self) -> Width {
        match self {
            Place::Reg { width, .. } | Place::Temp { width, .. } => *width,
        }
    }
    /// The whole register.
    pub fn reg(id: RegId) -> Place {
        Place::Reg {
            id,
            width: id.width(),
        }
    }
    /// The low `width` bits of a register (upper bits are zeroed).
    pub fn reg_w(id: RegId, width: Width) -> Place {
        Place::Reg { id, width }
    }
    pub fn temp(id: u32, width: Width) -> Place {
        Place::Temp { id, width }
    }
}

impl From<Place> for Var {
    fn from(p: Place) -> Var {
        match p {
            Place::Reg { id, width } => Var::Reg { id, width },
            Place::Temp { id, width } => Var::Temp { id, width },
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

/// An operation with unknown or not-yet-modelled semantics. Boxed in
/// [`Op::Intrinsic`] so the common operations stay small.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intrinsic {
    pub name: String,
    pub ins: Vec<Var>,
    pub out: Option<Place>,
}

/// One IR operation. The destination (where present) fixes the result width.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    // Data movement.
    Copy {
        dst: Place,
        a: Var,
    },
    /// `dst = memory[addr]` (little-endian, `width(dst)` bits).
    Load {
        dst: Place,
        addr: Var,
    },
    /// `memory[addr] = a` (little-endian, `width(a)` bits).
    Store {
        addr: Var,
        a: Var,
    },
    // Computation.
    Bin {
        dst: Place,
        op: BinOp,
        a: Var,
        b: Var,
    },
    Un {
        dst: Place,
        op: UnOp,
        a: Var,
    },
    // Width changes.
    Zext {
        dst: Place,
        a: Var,
    },
    Sext {
        dst: Place,
        a: Var,
    },
    Trunc {
        dst: Place,
        a: Var,
    },
    /// `dst = (hi << width(lo)) | lo`.
    Concat {
        dst: Place,
        hi: Var,
        lo: Var,
    },
    /// `dst = bits [lo, hi) of a` (lo inclusive, hi exclusive).
    Extract {
        dst: Place,
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
    Intrinsic(Box<Intrinsic>),
    Undef {
        dst: Place,
    },
}

impl Op {
    /// An intrinsic (unknown semantics) operation.
    pub fn intrinsic(name: &str, ins: Vec<Var>, out: Option<Place>) -> Op {
        Op::Intrinsic(Box::new(Intrinsic {
            name: name.to_string(),
            ins,
            out,
        }))
    }
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
            Var::Reg { id, width } => write!(f, "{id}:{width}"),
            Var::Temp { id, width } => write!(f, "t{id}:{width}"),
            Var::Const { value, width } => write!(f, "{value:#x}:{width}"),
            Var::Wide { value, width } => write!(f, "{:#x}:{width}", **value),
        }
    }
}

impl std::fmt::Display for Place {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Var::from(*self).fmt(f)
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
            Intrinsic(i) => {
                if let Some(o) = &i.out {
                    write!(f, "{o} = ")?;
                }
                write!(f, "INTRINSIC {}(", i.name)?;
                for (n, v) in i.ins.iter().enumerate() {
                    if n > 0 {
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
    use std::fmt::Write;
    let mut s = String::new();
    for i in insns {
        let _ = writeln!(s, "{:#010x}: {}", i.addr, i.op);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x86(name: &str) -> RegId {
        Arch::X86_64.reg(name).expect("register in table")
    }

    #[test]
    fn mask_and_sign() {
        assert_eq!(mask(0x1ff, 8), 0xff);
        assert_eq!(sign_extend(0xff, 8), -1);
        assert_eq!(sign_extend(0x7f, 8), 127);
        assert_eq!(mask(0xdead, 64), 0xdead);
    }

    /// Day 2 budget: the IR must stay small before the lifter multiplies it
    /// by millions of instructions (was Var 32 B, Insn 128 B + heap).
    #[test]
    fn sizes() {
        use std::mem::size_of;
        eprintln!(
            "Var {} B, Place {} B, Op {} B, Insn {} B",
            size_of::<Var>(),
            size_of::<Place>(),
            size_of::<Op>(),
            size_of::<Insn>()
        );
        assert!(size_of::<Var>() <= 16, "Var is {} B", size_of::<Var>());
        assert!(size_of::<Place>() <= 8, "Place is {} B", size_of::<Place>());
        assert!(size_of::<Op>() <= 48, "Op is {} B", size_of::<Op>());
        assert!(size_of::<Insn>() <= 56, "Insn is {} B", size_of::<Insn>());
        assert_eq!(size_of::<RegId>(), 2);
    }

    #[test]
    fn constants() {
        assert_eq!(
            Var::con(0x1ff, 8),
            Var::Const {
                value: 0xff,
                width: 8
            }
        );
        // Above 64 bits a constant is boxed; it is still masked.
        let w = Var::con(u128::MAX, 100);
        assert!(matches!(&w, Var::Wide { value, width: 100 } if **value == (1u128 << 100) - 1));
        assert_eq!(w.to_string(), format!("{:#x}:100", (1u128 << 100) - 1));
    }

    #[test]
    fn pretty() {
        let rax = x86("rax");
        let insns = vec![
            Insn::new(
                0x1000,
                Op::Copy {
                    dst: Place::temp(0, 64),
                    a: Var::reg(rax),
                },
            ),
            Insn::new(
                0x1000,
                Op::Bin {
                    dst: Place::reg(rax),
                    op: BinOp::Add,
                    a: Var::temp(0, 64),
                    b: Var::con(8, 64),
                },
            ),
            Insn::new(
                0x1004,
                Op::intrinsic("cpuid", vec![Var::reg(rax)], Some(Place::reg(rax))),
            ),
        ];
        let text = render(&insns);
        assert!(text.contains("t0:64 = rax:64"));
        assert!(text.contains("rax:64 = ADD t0:64, 0x8:64"));
        assert!(text.contains("rax:64 = INTRINSIC cpuid(rax:64)"));
    }

    #[test]
    fn serde_roundtrip() {
        let i = Insn::new(
            0x40,
            Op::Store {
                addr: Var::reg(Arch::Aarch64.reg("sp").expect("sp")),
                a: Var::con(7, 128),
            },
        );
        let j = serde_json::to_string(&i).expect("serialise");
        assert_eq!(serde_json::from_str::<Insn>(&j).expect("parse"), i);
    }
}
