//! Reference interpreter for the IR (spec §7.4). It is the oracle the lifter's
//! differential tests (B3) compare against: deterministic, no host state.

use crate::{BinOp, Insn, Op, Place, RegId, UnOp, Var, Width, mask, sign_extend};
use std::collections::HashMap;

/// Machine state: registers/flags by id, temporaries, byte-addressed
/// little-endian memory. Anything never written reads as zero.
#[derive(Debug, Default, Clone)]
pub struct State {
    regs: HashMap<RegId, u128>,
    temps: HashMap<u32, u128>,
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
    /// A destination register id that no register table knows.
    UnknownReg(RegId),
}

impl State {
    pub fn new() -> State {
        State::default()
    }

    /// Set a whole register (masked to its table width).
    pub fn set_reg(&mut self, id: RegId, value: u128) {
        self.regs.insert(id, mask(value, id.width()));
    }

    pub fn reg(&self, id: RegId) -> u128 {
        self.regs.get(&id).copied().unwrap_or(0)
    }

    pub fn temp(&self, id: u32) -> u128 {
        self.temps.get(&id).copied().unwrap_or(0)
    }

    pub fn load_byte(&self, addr: u64) -> u8 {
        self.mem.get(&addr).copied().unwrap_or(0)
    }

    pub fn store_byte(&mut self, addr: u64, b: u8) {
        self.mem.insert(addr, b);
    }

    /// Every memory byte that has been written (any order).
    pub fn written(&self) -> impl Iterator<Item = (u64, u8)> + '_ {
        self.mem.iter().map(|(&a, &b)| (a, b))
    }

    fn load_mem(&self, addr: u64, width: Width) -> u128 {
        let bytes = u32::from(width).div_ceil(8).min(16);
        let mut v: u128 = 0;
        for i in 0..bytes {
            v |= u128::from(self.load_byte(addr.wrapping_add(u64::from(i)))) << (8 * i);
        }
        mask(v, width)
    }

    fn store_mem(&mut self, addr: u64, value: u128, width: Width) {
        let bytes = u32::from(width).div_ceil(8).min(16);
        for i in 0..bytes {
            self.store_byte(addr.wrapping_add(u64::from(i)), (value >> (8 * i)) as u8);
        }
    }

    /// Evaluate a varnode to its (unsigned, masked) value.
    pub fn eval(&self, v: &Var) -> u128 {
        match v {
            Var::Const { value, width } => mask(u128::from(*value), *width),
            Var::Wide { value, width } => mask(**value, *width),
            Var::Reg { id, width } => mask(self.reg(*id), *width),
            Var::Temp { id, width } => mask(self.temp(*id), *width),
        }
    }

    /// Assign `value` to a destination. A register narrower than its table
    /// width is written zero-extended (see [`Place::Reg`]).
    fn assign(&mut self, dst: Place, value: u128) -> Result<(), StepError> {
        match dst {
            Place::Reg { id, width } => {
                let full = id.info().ok_or(StepError::UnknownReg(id))?.width;
                self.regs.insert(id, mask(mask(value, width), full));
            }
            Place::Temp { id, width } => {
                self.temps.insert(id, mask(value, width));
            }
        }
        Ok(())
    }

    /// Execute one instruction, updating state and returning the control step.
    pub fn exec(&mut self, insn: &Insn) -> Result<Step, StepError> {
        match &insn.op {
            Op::Copy { dst, a } => {
                let v = self.eval(a);
                self.assign(*dst, v)?;
                Ok(Step::Next)
            }
            Op::Load { dst, addr } => {
                let a = self.eval(addr) as u64;
                let v = self.load_mem(a, dst.width());
                self.assign(*dst, v)?;
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
                self.assign(*dst, v)?;
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
                self.assign(*dst, v)?;
                Ok(Step::Next)
            }
            Op::Zext { dst, a } => {
                let v = mask(self.eval(a), dst.width());
                self.assign(*dst, v)?;
                Ok(Step::Next)
            }
            Op::Sext { dst, a } => {
                let s = sign_extend(self.eval(a), a.width());
                self.assign(*dst, mask(s as u128, dst.width()))?;
                Ok(Step::Next)
            }
            Op::Trunc { dst, a } => {
                let v = mask(self.eval(a), dst.width());
                self.assign(*dst, v)?;
                Ok(Step::Next)
            }
            Op::Concat { dst, hi, lo } => {
                let v = self
                    .eval(hi)
                    .checked_shl(u32::from(lo.width()))
                    .unwrap_or(0)
                    | self.eval(lo);
                self.assign(*dst, mask(v, dst.width()))?;
                Ok(Step::Next)
            }
            Op::Extract { dst, a, lo, hi } => {
                let x = self.eval(a);
                let w = hi.saturating_sub(*lo);
                let v = mask(x.checked_shr(u32::from(*lo)).unwrap_or(0), w);
                self.assign(*dst, mask(v, dst.width()))?;
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
            // Unknown semantics: the output is left unchanged.
            Op::Intrinsic(_) => Ok(Step::Next),
            Op::Undef { dst } => {
                // Undefined value; model as zero to stay deterministic.
                self.assign(*dst, 0)?;
                Ok(Step::Next)
            }
        }
    }

    fn bin(&self, op: BinOp, a: &Var, b: &Var, w: Width) -> u128 {
        let x = self.eval(a);
        let y = self.eval(b);
        let xs = sign_extend(x, a.width());
        let ys = sign_extend(y, b.width());
        // Shift amounts beyond u32 must not wrap to a small shift.
        let sh = u32::try_from(y).unwrap_or(u32::MAX);
        use BinOp::*;
        match op {
            Add => mask(x.wrapping_add(y), w),
            Sub => mask(x.wrapping_sub(y), w),
            Mul => mask(x.wrapping_mul(y), w),
            Udiv => mask(x.checked_div(y).unwrap_or(0), w),
            Urem => mask(x.checked_rem(y).unwrap_or(0), w),
            Sdiv => mask(if ys == 0 { 0 } else { xs.wrapping_div(ys) } as u128, w),
            Srem => mask(if ys == 0 { 0 } else { xs.wrapping_rem(ys) } as u128, w),
            And => mask(x & y, w),
            Or => mask(x | y, w),
            Xor => mask(x ^ y, w),
            Shl => mask(x.checked_shl(sh).unwrap_or(0), w),
            Lshr => mask((x & lowmask(a.width())).checked_shr(sh).unwrap_or(0), w),
            Ashr => {
                let sh = sh.min(u32::from(a.width().saturating_sub(1)));
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
    use crate::{Arch, Op};

    fn x86(name: &str) -> RegId {
        Arch::X86_64.reg(name).expect("x86-64 register")
    }

    fn run(st: &mut State, ops: Vec<Op>) {
        for (i, op) in ops.into_iter().enumerate() {
            st.exec(&Insn::new(i as u64, op)).expect("exec");
        }
    }

    #[test]
    fn add_and_flags() {
        let (rax, rbx, cf) = (x86("rax"), x86("rbx"), x86("CF"));
        let mut st = State::new();
        st.set_reg(rax, 0xffff_ffff_ffff_ffff);
        st.set_reg(rbx, 1);
        run(
            &mut st,
            vec![
                Op::Bin {
                    dst: Place::reg(cf),
                    op: BinOp::Carry,
                    a: Var::reg(rax),
                    b: Var::reg(rbx),
                },
                Op::Bin {
                    dst: Place::reg(rax),
                    op: BinOp::Add,
                    a: Var::reg(rax),
                    b: Var::reg(rbx),
                },
            ],
        );
        assert_eq!(st.reg(rax), 0, "wrapped to zero");
        assert_eq!(st.reg(cf), 1, "carry set");
    }

    #[test]
    fn signed_overflow() {
        let (rax, of) = (x86("rax"), x86("OF"));
        let mut st = State::new();
        // eax = 0x7fff_ffff; eax + 1 overflows signed 32-bit → OF = 1.
        st.set_reg(rax, 0x7fff_ffff);
        st.exec(&Insn::new(
            0,
            Op::Bin {
                dst: Place::reg(of),
                op: BinOp::Scarry,
                a: Var::reg_w(rax, 32),
                b: Var::con(1, 32),
            },
        ))
        .expect("exec");
        assert_eq!(st.reg(of), 1);
    }

    #[test]
    fn load_store_roundtrip() {
        let (rdi, rax) = (x86("rdi"), x86("rax"));
        let mut st = State::new();
        st.set_reg(rdi, 0x4000);
        st.set_reg(rax, u128::MAX);
        // *rdi = 0xdeadbeef (32-bit), then read it back into eax.
        run(
            &mut st,
            vec![
                Op::Store {
                    addr: Var::reg(rdi),
                    a: Var::con(0xdead_beef, 32),
                },
                Op::Load {
                    dst: Place::reg_w(rax, 32),
                    addr: Var::reg(rdi),
                },
            ],
        );
        // A 32-bit write zero-extends into rax.
        assert_eq!(st.reg(rax), 0xdead_beef);
        // Little-endian: low byte at 0x4000.
        assert_eq!(st.load_byte(0x4000), 0xef);
    }

    #[test]
    fn concat_extract() {
        let rax = x86("rax");
        let mut st = State::new();
        run(
            &mut st,
            vec![
                Op::Concat {
                    dst: Place::reg(rax),
                    hi: Var::con(0x1122_3344, 32),
                    lo: Var::con(0x5566_7788, 32),
                },
                Op::Extract {
                    dst: Place::temp(0, 16),
                    a: Var::reg(rax),
                    lo: 0,
                    hi: 16,
                },
            ],
        );
        assert_eq!(st.reg(rax), 0x1122_3344_5566_7788);
        assert_eq!(st.temp(0), 0x7788);
    }

    #[test]
    fn conditional_branch() {
        let zf = x86("ZF");
        let br = Insn::new(
            0,
            Op::CBranch {
                cond: Var::reg(zf),
                target: 0x2000,
            },
        );
        let mut st = State::new();
        st.set_reg(zf, 1);
        assert_eq!(st.exec(&br), Ok(Step::Branch(0x2000)));
        st.set_reg(zf, 0);
        assert_eq!(st.exec(&br), Ok(Step::NotTaken));
    }

    #[test]
    fn wide_constants_and_vectors() {
        let v0 = Arch::Aarch64.reg("v0").expect("v0");
        let sp = Arch::Aarch64.reg("sp").expect("sp");
        let big = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128;
        let mut st = State::new();
        st.set_reg(sp, 0x8000);
        run(
            &mut st,
            vec![
                Op::Copy {
                    dst: Place::reg(v0),
                    a: Var::con(big, 128),
                },
                Op::Store {
                    addr: Var::reg(sp),
                    a: Var::reg(v0),
                },
                Op::Load {
                    dst: Place::temp(1, 128),
                    addr: Var::reg(sp),
                },
            ],
        );
        assert_eq!(st.reg(v0), big);
        assert_eq!(st.temp(1), big);
        assert_eq!(st.load_byte(0x800f), 0x01);
    }

    #[test]
    fn huge_shift_amounts_do_not_wrap() {
        let rax = x86("rax");
        let mut st = State::new();
        // A shift by 2^32 + 1 must not act like a shift by 1.
        for op in [BinOp::Shl, BinOp::Lshr] {
            st.exec(&Insn::new(
                0,
                Op::Bin {
                    dst: Place::reg(rax),
                    op,
                    a: Var::con(0x10, 64),
                    b: Var::con((1 << 32) + 1, 64),
                },
            ))
            .expect("exec");
            assert_eq!(st.reg(rax), 0, "{op:?}");
        }
        st.exec(&Insn::new(
            0,
            Op::Bin {
                dst: Place::reg(rax),
                op: BinOp::Ashr,
                a: Var::con(0x8000_0000_0000_0000, 64),
                b: Var::con((1 << 32) + 1, 64),
            },
        ))
        .expect("exec");
        assert_eq!(st.reg(rax), u128::from(u64::MAX), "sign fill");
        // Concat/Extract at the 128-bit edge must not overflow.
        st.exec(&Insn::new(
            0,
            Op::Extract {
                dst: Place::temp(2, 8),
                a: Var::con(u128::MAX, 128),
                lo: 200,
                hi: 208,
            },
        ))
        .expect("exec");
        assert_eq!(st.temp(2), 0);
    }

    #[test]
    fn unknown_register_is_an_error() {
        let mut st = State::new();
        let bad = RegId(0xff00);
        assert_eq!(
            st.exec(&Insn::new(
                0,
                Op::Copy {
                    dst: Place::Reg { id: bad, width: 64 },
                    a: Var::con(1, 64),
                },
            )),
            Err(StepError::UnknownReg(bad))
        );
    }
}
