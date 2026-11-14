//! Reference interpreter for the IR (spec §7.4). It is the oracle the lifter's
//! differential tests (B3) compare against: deterministic, no host state.

use crate::{BinOp, Insn, Op, UnOp, Var, Width, mask, sign_extend};
use std::collections::HashMap;

/// Machine state: registers/flags by name, byte-addressed little-endian memory.
#[derive(Debug, Default, Clone)]
pub struct State {
    regs: HashMap<String, u128>,
    mem: HashMap<u64, u8>,
}

/// What executing one instruction does to control flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Continue with the next instruction.
    Next,
    /// Direct branch to a machine address.
    Branch(u64),
    /// Conditional branch not taken (falls through).
    NotTaken,
    /// Call a machine address (then continue after it).
    Call(u64),
    /// Indirect branch/call to a computed address.
    Indirect(u64),
    /// Return from the function.
    Return,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepError {
    /// A Store/Load used a destination that is not a memory cell, or a width
    /// mismatch the interpreter cannot honour.
    BadForm(String),
}

impl State {
    pub fn new() -> State {
        State::default()
    }

    pub fn set_reg(&mut self, name: &str, value: u128, width: Width) {
        self.regs.insert(name.to_string(), mask(value, width));
    }

    pub fn reg(&self, name: &str) -> u128 {
        self.regs.get(name).copied().unwrap_or(0)
    }

    pub fn load_byte(&self, addr: u64) -> u8 {
        self.mem.get(&addr).copied().unwrap_or(0)
    }

    pub fn store_byte(&mut self, addr: u64, b: u8) {
        self.mem.insert(addr, b);
    }

    fn load_mem(&self, addr: u64, width: Width) -> u128 {
        let bytes = (width as u32).div_ceil(8);
        let mut v: u128 = 0;
        for i in 0..bytes {
            v |= (self.load_byte(addr.wrapping_add(i as u64)) as u128) << (8 * i);
        }
        mask(v, width)
    }

    fn store_mem(&mut self, addr: u64, value: u128, width: Width) {
        let bytes = (width as u32).div_ceil(8);
        for i in 0..bytes {
            self.store_byte(addr.wrapping_add(i as u64), (value >> (8 * i)) as u8);
        }
    }

    /// Evaluate a varnode to its (unsigned, masked) value.
    pub fn eval(&self, v: &Var) -> u128 {
        match v {
            Var::Const { value, width } => mask(*value, *width),
            Var::Reg { name, width } => mask(self.reg(name), *width),
            Var::Temp { id, width } => mask(self.reg(&temp_key(*id)), *width),
            Var::Mem { addr, width } => {
                let a = self.eval(addr) as u64;
                self.load_mem(a, *width)
            }
        }
    }

    /// Assign `value` to a destination varnode.
    fn assign(&mut self, dst: &Var, value: u128) -> Result<(), StepError> {
        match dst {
            Var::Reg { name, width } => self.set_reg(name, value, *width),
            Var::Temp { id, width } => self.set_reg(&temp_key(*id), value, *width),
            Var::Mem { addr, width } => {
                let a = self.eval(addr) as u64;
                self.store_mem(a, value, *width);
            }
            Var::Const { .. } => {
                return Err(StepError::BadForm("cannot assign to a constant".into()));
            }
        }
        Ok(())
    }

    /// Execute one instruction, updating state and returning the control step.
    pub fn exec(&mut self, insn: &Insn) -> Result<Step, StepError> {
        match &insn.op {
            Op::Copy { dst, a } => {
                let v = self.eval(a);
                self.assign(dst, v)?;
                Ok(Step::Next)
            }
            Op::Load { dst, addr } => {
                let a = self.eval(addr) as u64;
                let v = self.load_mem(a, dst.width());
                self.assign(dst, v)?;
                Ok(Step::Next)
            }
            Op::Store { addr, a } => {
                let at = self.eval(addr) as u64;
                let v = self.eval(a);
                self.store_mem(at, v, a.width());
                Ok(Step::Next)
            }
            Op::Bin { dst, op, a, b } => {
                let v = self.bin(*op, a, b, dst.width());
                self.assign(dst, v)?;
                Ok(Step::Next)
            }
            Op::Un { dst, op, a } => {
                let w = dst.width();
                let x = self.eval(a);
                let v = match op {
                    UnOp::Neg => mask(0u128.wrapping_sub(x), w),
                    UnOp::Not => mask(!x, w),
                    UnOp::Popcount => (x & lowmask(a.width())).count_ones() as u128,
                };
                self.assign(dst, v)?;
                Ok(Step::Next)
            }
            Op::Zext { dst, a } => {
                let v = mask(self.eval(a), dst.width());
                self.assign(dst, v)?;
                Ok(Step::Next)
            }
            Op::Sext { dst, a } => {
                let s = sign_extend(self.eval(a), a.width());
                self.assign(dst, mask(s as u128, dst.width()))?;
                Ok(Step::Next)
            }
            Op::Trunc { dst, a } => {
                let v = mask(self.eval(a), dst.width());
                self.assign(dst, v)?;
                Ok(Step::Next)
            }
            Op::Concat { dst, hi, lo } => {
                let lo_w = lo.width();
                let v = (self.eval(hi) << lo_w) | self.eval(lo);
                self.assign(dst, mask(v, dst.width()))?;
                Ok(Step::Next)
            }
            Op::Extract { dst, a, lo, hi } => {
                let x = self.eval(a);
                let w = hi.saturating_sub(*lo);
                let v = mask(x >> *lo, w);
                self.assign(dst, mask(v, dst.width()))?;
                Ok(Step::Next)
            }
            Op::Branch { target } => Ok(Step::Branch(*target)),
            Op::CBranch { cond, target } => {
                if self.eval(cond) & 1 == 1 {
                    Ok(Step::Branch(*target))
                } else {
                    Ok(Step::NotTaken)
                }
            }
            Op::BranchInd { target } => Ok(Step::Indirect(self.eval(target) as u64)),
            Op::Call { target } => Ok(Step::Call(*target)),
            Op::CallInd { target } => Ok(Step::Indirect(self.eval(target) as u64)),
            Op::Return => Ok(Step::Return),
            Op::Intrinsic { out, .. } => {
                // Unknown semantics: leave the output undefined (unchanged).
                let _ = out;
                Ok(Step::Next)
            }
            Op::Undef { dst } => {
                // Undefined value; model as zero to stay deterministic.
                self.assign(dst, 0)?;
                Ok(Step::Next)
            }
        }
    }

    fn bin(&self, op: BinOp, a: &Var, b: &Var, w: Width) -> u128 {
        let x = self.eval(a);
        let y = self.eval(b);
        let xs = sign_extend(x, a.width());
        let ys = sign_extend(y, b.width());
        use BinOp::*;
        match op {
            Add => mask(x.wrapping_add(y), w),
            Sub => mask(x.wrapping_sub(y), w),
            Mul => mask(x.wrapping_mul(y), w),
            Udiv => mask(if y == 0 { 0 } else { x / y }, w),
            Urem => mask(if y == 0 { 0 } else { x % y }, w),
            Sdiv => mask(if ys == 0 { 0 } else { xs.wrapping_div(ys) } as u128, w),
            Srem => mask(if ys == 0 { 0 } else { xs.wrapping_rem(ys) } as u128, w),
            And => mask(x & y, w),
            Or => mask(x | y, w),
            Xor => mask(x ^ y, w),
            Shl => mask(x.checked_shl(y as u32).unwrap_or(0), w),
            Lshr => mask(
                (x & lowmask(a.width())).checked_shr(y as u32).unwrap_or(0),
                w,
            ),
            Ashr => {
                let sh = (y as u32).min(a.width().saturating_sub(1) as u32);
                mask((xs >> sh) as u128, w)
            }
            Eq => (x == y) as u128,
            Ne => (x != y) as u128,
            Ult => (x < y) as u128,
            Ule => (x <= y) as u128,
            Slt => (xs < ys) as u128,
            Sle => (xs <= ys) as u128,
            Carry => {
                let aw = a.width();
                (mask(x.wrapping_add(y), aw) < mask(x, aw)) as u128
            }
            Scarry => {
                // Signed addition overflow.
                let aw = a.width();
                let r = sign_extend(mask(x.wrapping_add(y), aw), aw);
                ((xs >= 0) == (ys >= 0) && (r >= 0) != (xs >= 0)) as u128
            }
            Sborrow => {
                // Signed subtraction overflow.
                let aw = a.width();
                let r = sign_extend(mask(x.wrapping_sub(y), aw), aw);
                ((xs >= 0) != (ys >= 0) && (r >= 0) != (xs >= 0)) as u128
            }
        }
    }
}

fn temp_key(id: u32) -> String {
    format!("$t{id}")
}

fn lowmask(w: Width) -> u128 {
    if w == 0 || w >= 128 {
        u128::MAX
    } else {
        (1u128 << w) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Op;

    fn run(st: &mut State, ops: Vec<Op>) {
        for (i, op) in ops.into_iter().enumerate() {
            st.exec(&Insn::new(i as u64, op)).unwrap();
        }
    }

    #[test]
    fn add_and_flags() {
        let mut st = State::new();
        st.set_reg("rax", 0xffff_ffff_ffff_ffff, 64);
        st.set_reg("rbx", 1, 64);
        run(
            &mut st,
            vec![
                Op::Bin {
                    dst: Var::reg("CF", 1),
                    op: BinOp::Carry,
                    a: Var::reg("rax", 64),
                    b: Var::reg("rbx", 64),
                },
                Op::Bin {
                    dst: Var::reg("rax", 64),
                    op: BinOp::Add,
                    a: Var::reg("rax", 64),
                    b: Var::reg("rbx", 64),
                },
            ],
        );
        assert_eq!(st.reg("rax"), 0, "wrapped to zero");
        assert_eq!(st.reg("CF"), 1, "carry set");
    }

    #[test]
    fn signed_overflow() {
        let mut st = State::new();
        // 0x7fff_ffff + 1 overflows signed 32-bit → OF = 1.
        st.set_reg("eax", 0x7fff_ffff, 32);
        st.exec(&Insn::new(
            0,
            Op::Bin {
                dst: Var::reg("OF", 1),
                op: BinOp::Scarry,
                a: Var::reg("eax", 32),
                b: Var::con(1, 32),
            },
        ))
        .unwrap();
        assert_eq!(st.reg("OF"), 1);
    }

    #[test]
    fn load_store_roundtrip() {
        let mut st = State::new();
        st.set_reg("rdi", 0x4000, 64);
        // *rdi = 0xdeadbeef (32-bit), then read it back into eax.
        st.exec(&Insn::new(
            0,
            Op::Store {
                addr: Var::reg("rdi", 64),
                a: Var::con(0xdead_beef, 32),
            },
        ))
        .unwrap();
        st.exec(&Insn::new(
            1,
            Op::Load {
                dst: Var::reg("eax", 32),
                addr: Var::reg("rdi", 64),
            },
        ))
        .unwrap();
        assert_eq!(st.reg("eax"), 0xdead_beef);
        // Little-endian: low byte at 0x4000.
        assert_eq!(st.load_byte(0x4000), 0xef);
    }

    #[test]
    fn concat_extract() {
        let mut st = State::new();
        st.exec(&Insn::new(
            0,
            Op::Concat {
                dst: Var::reg("rax", 64),
                hi: Var::con(0x1122_3344, 32),
                lo: Var::con(0x5566_7788, 32),
            },
        ))
        .unwrap();
        assert_eq!(st.reg("rax"), 0x1122_3344_5566_7788);
        st.exec(&Insn::new(
            1,
            Op::Extract {
                dst: Var::reg("ax", 16),
                a: Var::reg("rax", 64),
                lo: 0,
                hi: 16,
            },
        ))
        .unwrap();
        assert_eq!(st.reg("ax"), 0x7788);
    }

    #[test]
    fn conditional_branch() {
        let mut st = State::new();
        st.set_reg("ZF", 1, 1);
        let s = st
            .exec(&Insn::new(
                0,
                Op::CBranch {
                    cond: Var::reg("ZF", 1),
                    target: 0x2000,
                },
            ))
            .unwrap();
        assert_eq!(s, Step::Branch(0x2000));
        st.set_reg("ZF", 0, 1);
        let s = st
            .exec(&Insn::new(
                0,
                Op::CBranch {
                    cond: Var::reg("ZF", 1),
                    target: 0x2000,
                },
            ))
            .unwrap();
        assert_eq!(s, Step::NotTaken);
    }
}
