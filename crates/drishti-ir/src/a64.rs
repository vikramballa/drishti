//! AArch64 → IR lifter (milestone B2, Days 6–8). Decodes one 32-bit
//! instruction word straight from the encoding (no disassembler) and emits
//! address-tagged IR. Covered: integer data processing (immediate,
//! register, shifted/extended, bitfield, conditional select/compare,
//! multiply/divide, bit/byte reversal, CLZ/CLS), every load/store addressing
//! form for general and SIMD&FP registers (pairs, literal, register offset,
//! pre/post-index, exclusive, acquire/release, LSE atomics, LD1/ST1 multiple),
//! branches, system hints/barriers/thread-pointer reads, and the SIMD&FP
//! *moves* (FMOV, MOVI/MVNI/ORR/BIC immediate, UMOV/SMOV/DUP/INS, vector
//! logic). Floating-point arithmetic, crypto, and other SIMD arithmetic lift
//! to `INTRINSIC a64.<class>(word)` — honest "unknown semantics", counted by
//! the coverage report.
//!
//! Semantics follow the Arm ARM pseudocode; W-register and scalar-FP writes
//! zero-extend (`Place::reg_w`). Single-threaded model: exclusive stores
//! always succeed, barriers and hints are no-ops, pointer-authentication
//! branches behave like their plain forms.

use crate::{BinOp, Insn, Op, Place, RegId, UnOp, Var, Width};

// Register ids in the AArch64 table (`regs.rs`; ids are append-only).
const fn a(i: u16) -> RegId {
    RegId(0x100 | i)
}
/// `x0`–`x30`, and 31 = `sp`.
fn xr(n: u32) -> RegId {
    a(n as u16)
}
fn vr(n: u32) -> RegId {
    a(37 + (n & 31) as u16)
}
pub const SP: RegId = a(31);
pub const NF: RegId = a(33);
pub const ZF: RegId = a(34);
pub const CF: RegId = a(35);
pub const VF: RegId = a(36);
const FPCR: RegId = a(69);
const FPSR: RegId = a(70);
const TPIDR: RegId = a(71);
const TPIDRRO: RegId = a(72);

/// Result of lifting one instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifted {
    /// Full semantics in IR.
    Ok,
    /// Lifted as `INTRINSIC a64.<class>`; the class names what is missing.
    Intrinsic(&'static str),
}

/// Lift the instruction `word` at `pc`, appending to `out`.
pub fn lift(word: u32, pc: u64, out: &mut Vec<Insn>) -> Lifted {
    let mut l = L { pc, out, t: 0 };
    let start = l.out.len();
    match l.top(word) {
        Some(()) => Lifted::Ok,
        None => {
            let class = class_of(word);
            l.out.truncate(start);
            l.op(Op::intrinsic(
                class,
                vec![Var::con(u128::from(word), 32)],
                None,
            ));
            Lifted::Intrinsic(class)
        }
    }
}

/// Lift a run of little-endian instruction bytes starting at `pc`.
pub fn lift_bytes(bytes: &[u8], pc: u64) -> (Vec<Insn>, usize, usize) {
    let mut out = Vec::with_capacity(bytes.len());
    let (mut ok, mut n) = (0, 0);
    for (i, w) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let word = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        n += 1;
        if lift(word, pc.wrapping_add(4 * i as u64), &mut out) == Lifted::Ok {
            ok += 1;
        }
    }
    (out, ok, n)
}

/// Coarse class of an instruction the lifter does not model.
fn class_of(w: u32) -> &'static str {
    let op0 = (w >> 25) & 0xf;
    match op0 {
        0b0000 => "a64.udf",
        0b1000 | 0b1001 => "a64.dp_imm",
        0b1010 | 0b1011 => {
            if w & 0xff00_0000 == 0xd400_0000 {
                "a64.exception"
            } else if w & 0xffc0_0000 == 0xd500_0000 {
                "a64.system"
            } else {
                "a64.branch"
            }
        }
        0b0100 | 0b0110 | 0b1100 | 0b1110 => {
            if w & (1 << 26) != 0 {
                "a64.simd_mem"
            } else {
                "a64.mem"
            }
        }
        0b0101 | 0b1101 => "a64.dp_reg",
        0b0111 | 0b1111 => {
            if w & 0x5f00_0000 == 0x1e00_0000 || w & 0x5f00_0000 == 0x1f00_0000 {
                "a64.fp"
            } else if w & 0xff3e_0c00 == 0x4e28_0800 {
                "a64.crypto"
            } else {
                "a64.simd"
            }
        }
        _ => "a64.unallocated",
    }
}

fn c(v: u64, w: Width) -> Var {
    Var::con(u128::from(v), w)
}
fn ones(n: u32) -> u64 {
    if n >= 64 { u64::MAX } else { (1u64 << n) - 1 }
}
fn sext_bits(v: u64, bits: u32) -> u64 {
    let s = 64 - bits;
    (((v << s) as i64) >> s) as u64
}
fn bit(w: u32, n: u32) -> u32 {
    (w >> n) & 1
}
fn field(w: u32, lo: u32, len: u32) -> u32 {
    (w >> lo) & ((1u32 << len) - 1)
}

/// Arm ARM `DecodeBitMasks` → (wmask, tmask) for `m`-bit registers.
fn bit_masks(n: u32, imms: u32, immr: u32, immediate: bool, m: u32) -> Option<(u64, u64)> {
    let combined = (n << 6) | (!imms & 0x3f);
    if combined == 0 {
        return None;
    }
    let len = 31 - combined.leading_zeros();
    if len < 1 || (1u32 << len) > m {
        return None;
    }
    let levels = (1u32 << len) - 1;
    if immediate && imms & levels == levels {
        return None;
    }
    let s = imms & levels;
    let r = immr & levels;
    let d = s.wrapping_sub(r) & levels;
    let esize = 1u32 << len;
    let emask = ones(esize);
    let welem = ones(s + 1);
    let telem = ones(d + 1);
    let ror = |x: u64| {
        if r == 0 {
            x
        } else {
            ((x >> r) | (x << (esize - r))) & emask
        }
    };
    let rep = |e: u64| {
        let mut v = 0u64;
        let mut i = 0;
        while i < m {
            v |= e << i;
            i += esize;
        }
        v & ones(m)
    };
    Some((rep(ror(welem)), rep(telem)))
}

/// Arm ARM `VFPExpandImm` for 16/32/64-bit floats.
fn vfp_imm(imm8: u32, n: u32) -> u64 {
    let e = match n {
        16 => 5,
        32 => 8,
        _ => 11,
    };
    let f = n - e - 1;
    let sign = u64::from(imm8 >> 7);
    let b6 = u64::from((imm8 >> 6) & 1);
    let exp = ((b6 ^ 1) << (e - 1))
        | (if b6 == 1 { ones(e - 3) << 2 } else { 0 })
        | u64::from((imm8 >> 4) & 3);
    let frac = u64::from(imm8 & 0xf) << (f - 4);
    (sign << (n - 1)) | (exp << f) | frac
}

/// Arm ARM `AdvSIMDExpandImm` → 64-bit pattern.
fn simd_imm(op: u32, cmode: u32, imm8: u32) -> Option<u64> {
    let i = u64::from(imm8);
    let r2 = |x: u64| x | (x << 32);
    let r4 = |x: u64| x | (x << 16) | (x << 32) | (x << 48);
    Some(match cmode >> 1 {
        0 => r2(i),
        1 => r2(i << 8),
        2 => r2(i << 16),
        3 => r2(i << 24),
        4 => r4(i),
        5 => r4(i << 8),
        6 => {
            if cmode & 1 == 0 {
                r2((i << 8) | 0xff)
            } else {
                r2((i << 16) | 0xffff)
            }
        }
        _ => match (cmode & 1, op) {
            (0, 0) => i * 0x0101_0101_0101_0101,
            (0, _) => (0..8).fold(0, |v, b| {
                if (i >> b) & 1 == 1 {
                    v | (0xff << (8 * b))
                } else {
                    v
                }
            }),
            (_, 0) => r2(vfp_imm(imm8, 32)),
            _ => vfp_imm(imm8, 64),
        },
    })
}

enum Rt {
    /// General register `n` read/written at `w` bits (31 = zero register).
    G(u32, Width),
    /// SIMD&FP register `n`, `w` low bits.
    V(u32, Width),
}

/// A single-register load/store: (register, access bytes, load?, sign-extend-to).
type LsKind = (Rt, u32, bool, Option<Width>);

struct L<'a> {
    pc: u64,
    out: &'a mut Vec<Insn>,
    t: u32,
}

impl L<'_> {
    fn op(&mut self, op: Op) {
        self.out.push(Insn::new(self.pc, op));
    }
    fn tmp(&mut self, w: Width) -> Place {
        let p = Place::temp(self.t, w);
        self.t += 1;
        p
    }
    fn bin(&mut self, op: BinOp, a: Var, b: Var, w: Width) -> Var {
        let dst = self.tmp(w);
        self.op(Op::Bin { dst, op, a, b });
        dst.into()
    }
    fn un(&mut self, op: UnOp, a: Var, w: Width) -> Var {
        let dst = self.tmp(w);
        self.op(Op::Un { dst, op, a });
        dst.into()
    }
    fn zext(&mut self, a: Var, w: Width) -> Var {
        if a.width() == w {
            return a;
        }
        let dst = self.tmp(w);
        self.op(if a.width() < w {
            Op::Zext { dst, a }
        } else {
            Op::Trunc { dst, a }
        });
        dst.into()
    }
    fn sext(&mut self, a: Var, w: Width) -> Var {
        if a.width() >= w {
            return self.zext(a, w);
        }
        let dst = self.tmp(w);
        self.op(Op::Sext { dst, a });
        dst.into()
    }
    fn extract(&mut self, a: Var, lo: Width, hi: Width) -> Var {
        let dst = self.tmp(hi - lo);
        self.op(Op::Extract { dst, a, lo, hi });
        dst.into()
    }
    fn copy(&mut self, dst: Place, a: Var) {
        self.op(Op::Copy { dst, a });
    }
    fn not1(&mut self, a: Var) -> Var {
        self.bin(BinOp::Xor, a, c(1, 1), 1)
    }
    /// `cond ? a : b` without control flow (both `w` bits wide).
    fn select(&mut self, cond: Var, a: Var, b: Var, w: Width) -> Var {
        let cz = self.zext(cond, w);
        let m = self.un(UnOp::Neg, cz, w);
        let x = self.bin(BinOp::And, a, m.clone(), w);
        let nm = self.un(UnOp::Not, m, w);
        let y = self.bin(BinOp::And, b, nm, w);
        self.bin(BinOp::Or, x, y, w)
    }

    // ---- registers

    fn gpr(&self, n: u32, w: Width, sp: bool) -> Var {
        if n == 31 && !sp {
            c(0, w)
        } else {
            Var::reg_w(xr(n), w)
        }
    }
    fn set_gpr(&mut self, n: u32, w: Width, sp: bool, v: Var) {
        if n == 31 && !sp {
            return;
        }
        let v = self.zext(v, w);
        self.copy(Place::reg_w(xr(n), w), v);
    }
    fn set_nzcv(&mut self, n: Var, z: Var, cf: Var, v: Var) {
        self.copy(Place::reg(NF), n);
        self.copy(Place::reg(ZF), z);
        self.copy(Place::reg(CF), cf);
        self.copy(Place::reg(VF), v);
    }
    fn nz(&mut self, r: &Var, w: Width) -> (Var, Var) {
        let n = self.extract(r.clone(), w - 1, w);
        let z = self.bin(BinOp::Eq, r.clone(), c(0, w), 1);
        (n, z)
    }

    /// Arm ARM `ConditionHolds` → 1-bit value.
    fn cond(&mut self, cond: u32) -> Var {
        let (n, z, cf, v) = (Var::reg(NF), Var::reg(ZF), Var::reg(CF), Var::reg(VF));
        let base = match cond >> 1 {
            0 => z,
            1 => cf,
            2 => n,
            3 => v,
            4 => {
                let nz = self.not1(z);
                self.bin(BinOp::And, cf, nz, 1)
            }
            5 => self.bin(BinOp::Eq, n, v, 1),
            6 => {
                let ge = self.bin(BinOp::Eq, n, v, 1);
                let nz = self.not1(z);
                self.bin(BinOp::And, ge, nz, 1)
            }
            _ => return c(1, 1),
        };
        if cond & 1 == 1 { self.not1(base) } else { base }
    }

    /// `a + b` or `a - b`, optionally setting NZCV.
    fn addsub(&mut self, sub: bool, a: Var, b: Var, w: Width, flags: bool) -> Var {
        let r = self.bin(
            if sub { BinOp::Sub } else { BinOp::Add },
            a.clone(),
            b.clone(),
            w,
        );
        if flags {
            let cf = if sub {
                self.bin(BinOp::Ule, b.clone(), a.clone(), 1)
            } else {
                self.bin(BinOp::Carry, a.clone(), b.clone(), 1)
            };
            let v = self.bin(if sub { BinOp::Sborrow } else { BinOp::Scarry }, a, b, 1);
            let (n, z) = self.nz(&r, w);
            self.set_nzcv(n, z, cf, v);
        }
        r
    }

    /// Arm ARM `AddWithCarry(a, b, C)`, optionally setting NZCV.
    fn adc(&mut self, a: Var, b: Var, w: Width, flags: bool) -> Var {
        let cin = Var::reg(CF);
        let cz = self.zext(cin.clone(), w);
        let s = self.bin(BinOp::Add, a.clone(), b.clone(), w);
        let r = self.bin(BinOp::Add, s, cz, w);
        if flags {
            let w2 = 2 * w;
            let (ua, ub, uc) = (
                self.zext(a.clone(), w2),
                self.zext(b.clone(), w2),
                self.zext(cin, w2),
            );
            let us = self.bin(BinOp::Add, ua, ub, w2);
            let us = self.bin(BinOp::Add, us, uc.clone(), w2);
            let cf = self.extract(us, w, w + 1);
            let (sa, sb) = (self.sext(a, w2), self.sext(b, w2));
            let ss = self.bin(BinOp::Add, sa, sb, w2);
            let ss = self.bin(BinOp::Add, ss, uc, w2);
            let rs = self.sext(r.clone(), w2);
            let v = self.bin(BinOp::Ne, rs, ss, 1);
            let (n, z) = self.nz(&r, w);
            self.set_nzcv(n, z, cf, v);
        }
        r
    }

    fn ror_imm(&mut self, x: Var, amt: u32, w: Width) -> Var {
        let amt = amt % u32::from(w);
        if amt == 0 {
            return x;
        }
        let lo = self.bin(BinOp::Lshr, x.clone(), c(u64::from(amt), w), w);
        let hi = self.bin(BinOp::Shl, x, c(u64::from(w) - u64::from(amt), w), w);
        self.bin(BinOp::Or, lo, hi, w)
    }
    fn shift(&mut self, x: Var, ty: u32, amt: u32, w: Width) -> Var {
        if amt == 0 {
            return x;
        }
        let k = c(u64::from(amt), w);
        match ty {
            0 => self.bin(BinOp::Shl, x, k, w),
            1 => self.bin(BinOp::Lshr, x, k, w),
            2 => self.bin(BinOp::Ashr, x, k, w),
            _ => self.ror_imm(x, amt, w),
        }
    }
    /// Arm ARM `ExtendReg(m, option, shift)` at `w` bits.
    fn extend_reg(&mut self, m: u32, option: u32, sh: u32, w: Width) -> Var {
        let len: Width = 8 << (option & 3);
        let src = self.gpr(m, len.min(64), false);
        let v = if option & 4 != 0 {
            self.sext(src, w)
        } else {
            self.zext(src, w)
        };
        if sh == 0 {
            v
        } else {
            self.bin(BinOp::Shl, v, c(u64::from(sh), w), w)
        }
    }

    // ---- decode tree

    fn top(&mut self, w: u32) -> Option<()> {
        match (w >> 25) & 0xf {
            0b1000 | 0b1001 => self.dp_imm(w),
            0b1010 | 0b1011 => self.branch_sys(w),
            0b0100 | 0b0110 | 0b1100 | 0b1110 => self.ldst(w),
            0b0101 | 0b1101 => self.dp_reg(w),
            0b0111 | 0b1111 => self.simd_fp(w),
            _ => None,
        }
    }

    // ---- data processing: immediate

    fn dp_imm(&mut self, i: u32) -> Option<()> {
        let sf = bit(i, 31) == 1;
        let w: Width = if sf { 64 } else { 32 };
        let rd = field(i, 0, 5);
        let rn = field(i, 5, 5);
        match field(i, 23, 3) {
            0b000 | 0b001 => {
                // ADR / ADRP
                let imm = (field(i, 5, 19) << 2) | field(i, 29, 2);
                let imm = sext_bits(u64::from(imm), 21);
                let v = if bit(i, 31) == 1 {
                    (self.pc & !0xfff).wrapping_add(imm << 12)
                } else {
                    self.pc.wrapping_add(imm)
                };
                self.set_gpr(rd, 64, false, c(v, 64));
                Some(())
            }
            0b010 => {
                // ADD/ADDS/SUB/SUBS (immediate)
                let sub = bit(i, 30) == 1;
                let s = bit(i, 29) == 1;
                let imm = u64::from(field(i, 10, 12)) << (12 * bit(i, 22));
                let a = self.gpr(rn, w, true);
                let r = self.addsub(sub, a, c(imm, w), w, s);
                self.set_gpr(rd, w, !s, r);
                Some(())
            }
            0b100 => {
                // Logical (immediate)
                let opc = field(i, 29, 2);
                let n = bit(i, 22);
                if !sf && n == 1 {
                    return None;
                }
                let (imm, _) = bit_masks(n, field(i, 10, 6), field(i, 16, 6), true, u32::from(w))?;
                let a = self.gpr(rn, w, false);
                let op = match opc {
                    0 | 3 => BinOp::And,
                    1 => BinOp::Or,
                    _ => BinOp::Xor,
                };
                let r = self.bin(op, a, c(imm, w), w);
                if opc == 3 {
                    let (n, z) = self.nz(&r, w);
                    self.set_nzcv(n, z, c(0, 1), c(0, 1));
                }
                self.set_gpr(rd, w, opc != 3, r);
                Some(())
            }
            0b101 => {
                // MOVN / MOVZ / MOVK
                let hw = field(i, 21, 2);
                if !sf && hw > 1 {
                    return None;
                }
                let sh = 16 * hw;
                let imm = u64::from(field(i, 5, 16)) << sh;
                match field(i, 29, 2) {
                    0 => self.set_gpr(rd, w, false, c(!imm & ones(u32::from(w)), w)),
                    2 => self.set_gpr(rd, w, false, c(imm, w)),
                    3 => {
                        let old = self.gpr(rd, w, false);
                        let kept = self.bin(
                            BinOp::And,
                            old,
                            c(!(0xffff << sh) & ones(u32::from(w)), w),
                            w,
                        );
                        let r = self.bin(BinOp::Or, kept, c(imm, w), w);
                        self.set_gpr(rd, w, false, r);
                    }
                    _ => return None,
                }
                Some(())
            }
            0b110 => {
                // SBFM / BFM / UBFM
                let opc = field(i, 29, 2);
                let n = bit(i, 22);
                if opc == 3 || n != u32::from(sf) {
                    return None;
                }
                let (immr, imms) = (field(i, 16, 6), field(i, 10, 6));
                if !sf && (immr > 31 || imms > 31) {
                    return None;
                }
                let (wm, tm) = bit_masks(n, imms, immr, false, u32::from(w))?;
                let full = ones(u32::from(w));
                let src = self.gpr(rn, w, false);
                let rot = self.ror_imm(src.clone(), immr, w);
                let r = match opc {
                    2 => self.bin(BinOp::And, rot, c(wm & tm, w), w),
                    0 => {
                        let bot = self.bin(BinOp::And, rot, c(wm, w), w);
                        let sb = self.extract(src, imms as Width, imms as Width + 1);
                        let sz = self.zext(sb, w);
                        let top = self.un(UnOp::Neg, sz, w);
                        let t = self.bin(BinOp::And, top, c(!tm & full, w), w);
                        let b = self.bin(BinOp::And, bot, c(tm, w), w);
                        self.bin(BinOp::Or, t, b, w)
                    }
                    _ => {
                        let dst = self.gpr(rd, w, false);
                        let keep = self.bin(BinOp::And, dst.clone(), c(!wm & full, w), w);
                        let ins = self.bin(BinOp::And, rot, c(wm, w), w);
                        let bot = self.bin(BinOp::Or, keep, ins, w);
                        let t = self.bin(BinOp::And, dst, c(!tm & full, w), w);
                        let b = self.bin(BinOp::And, bot, c(tm, w), w);
                        self.bin(BinOp::Or, t, b, w)
                    }
                };
                self.set_gpr(rd, w, false, r);
                Some(())
            }
            0b111 => {
                // EXTR
                if field(i, 29, 2) != 0 || bit(i, 21) == 1 || bit(i, 22) != u32::from(sf) {
                    return None;
                }
                let lsb = field(i, 10, 6);
                if !sf && lsb > 31 {
                    return None;
                }
                let rm = field(i, 16, 5);
                let hi = self.gpr(rn, w, false);
                let lo = self.gpr(rm, w, false);
                let r = if lsb == 0 {
                    lo
                } else {
                    let cat = self.tmp(2 * w);
                    self.op(Op::Concat { dst: cat, hi, lo });
                    self.extract(cat.into(), lsb as Width, lsb as Width + w)
                };
                self.set_gpr(rd, w, false, r);
                Some(())
            }
            _ => None,
        }
    }

    // ---- branches, exceptions, system

    fn branch_sys(&mut self, i: u32) -> Option<()> {
        let pc = self.pc;
        if i & 0x7c00_0000 == 0x1400_0000 {
            let t = pc.wrapping_add(sext_bits(u64::from(i & 0x03ff_ffff), 26) << 2);
            if bit(i, 31) == 1 {
                self.copy(Place::reg(xr(30)), c(pc.wrapping_add(4), 64));
                self.op(Op::Call { target: t });
            } else {
                self.op(Op::Branch { target: t });
            }
            return Some(());
        }
        if i & 0xff00_0010 == 0x5400_0000 {
            let t = pc.wrapping_add(sext_bits(u64::from(field(i, 5, 19)), 19) << 2);
            let cond = field(i, 0, 4);
            if cond >= 14 {
                self.op(Op::Branch { target: t });
            } else {
                let cv = self.cond(cond);
                self.op(Op::CBranch {
                    cond: cv,
                    target: t,
                });
            }
            return Some(());
        }
        if i & 0x7e00_0000 == 0x3400_0000 {
            // CBZ / CBNZ
            let w: Width = if bit(i, 31) == 1 { 64 } else { 32 };
            let t = pc.wrapping_add(sext_bits(u64::from(field(i, 5, 19)), 19) << 2);
            let r = self.gpr(field(i, 0, 5), w, false);
            let op = if bit(i, 24) == 1 {
                BinOp::Ne
            } else {
                BinOp::Eq
            };
            let cv = self.bin(op, r, c(0, w), 1);
            self.op(Op::CBranch {
                cond: cv,
                target: t,
            });
            return Some(());
        }
        if i & 0x7e00_0000 == 0x3600_0000 {
            // TBZ / TBNZ
            let b = (bit(i, 31) << 5) | field(i, 19, 5);
            let t = pc.wrapping_add(sext_bits(u64::from(field(i, 5, 14)), 14) << 2);
            let r = self.gpr(field(i, 0, 5), 64, false);
            let bv = self.extract(r, b as Width, b as Width + 1);
            let cv = if bit(i, 24) == 1 { bv } else { self.not1(bv) };
            self.op(Op::CBranch {
                cond: cv,
                target: t,
            });
            return Some(());
        }
        if i & 0xfe00_0000 == 0xd600_0000 {
            // Unconditional branch (register), incl. pointer-auth forms.
            let opc = field(i, 21, 4);
            if field(i, 16, 5) != 0x1f {
                return None;
            }
            let op3 = field(i, 10, 6);
            if !matches!(op3, 0 | 2 | 3) {
                return None;
            }
            let rn = field(i, 5, 5);
            match opc {
                0 | 8 => {
                    let t = self.gpr(rn, 64, false);
                    self.op(Op::BranchInd { target: t });
                }
                1 | 9 => {
                    let tv = self.gpr(rn, 64, false);
                    let t = self.tmp(64);
                    self.copy(t, tv);
                    self.copy(Place::reg(xr(30)), c(pc.wrapping_add(4), 64));
                    self.op(Op::CallInd { target: t.into() });
                }
                // RET (x30) and RETAA/RETAB (always x30) are returns;
                // RET Xn with another register branches to Xn.
                2 if rn == 30 || op3 != 0 => self.op(Op::Return),
                2 => {
                    let t = self.gpr(rn, 64, false);
                    self.op(Op::BranchInd { target: t });
                }
                _ => return None,
            }
            return Some(());
        }
        if i & 0xffc0_0000 == 0xd500_0000 {
            return self.system(i);
        }
        None
    }

    fn system(&mut self, i: u32) -> Option<()> {
        // HINT space (NOP, YIELD, PAC*SP/AUT*SP, BTI, ...): no effect here.
        if i & 0xffff_f01f == 0xd503_201f {
            return Some(());
        }
        // Barriers: CLREX, DSB, DMB, ISB, SB, DSB nXS.
        if i & 0xffff_f01f == 0xd503_301f {
            let (crm, op2) = (field(i, 8, 4), field(i, 5, 3));
            let ok = matches!(op2, 2 | 4 | 5 | 6)
                || (op2 == 7 && crm == 0)
                || (op2 == 1 && crm & 3 == 2);
            return ok.then_some(());
        }
        let rt = field(i, 0, 5);
        let sysreg = field(i, 5, 15);
        // o0:op1:CRn:CRm:op2 (op0 = 2 + o0), grouped by field.
        #[allow(clippy::unusual_byte_groupings)]
        const NZCV: u32 = 0b1_011_0100_0010_000;
        #[allow(clippy::unusual_byte_groupings)]
        const R_FPCR: u32 = 0b1_011_0100_0100_000;
        #[allow(clippy::unusual_byte_groupings)]
        const R_FPSR: u32 = 0b1_011_0100_0100_001;
        #[allow(clippy::unusual_byte_groupings)]
        const R_TPIDR: u32 = 0b1_011_1101_0000_010;
        #[allow(clippy::unusual_byte_groupings)]
        const R_TPIDRRO: u32 = 0b1_011_1101_0000_011;
        match field(i, 20, 12) {
            0xd53 => {
                // MRS
                let v = match sysreg {
                    NZCV => {
                        let mut acc = c(0, 64);
                        for (f, b) in [(NF, 31), (ZF, 30), (CF, 29), (VF, 28)] {
                            let z = self.zext(Var::reg(f), 64);
                            let s = self.bin(BinOp::Shl, z, c(b, 64), 64);
                            acc = self.bin(BinOp::Or, acc, s, 64);
                        }
                        acc
                    }
                    R_FPCR => Var::reg(FPCR),
                    R_FPSR => Var::reg(FPSR),
                    R_TPIDR => Var::reg(TPIDR),
                    R_TPIDRRO => Var::reg(TPIDRRO),
                    _ => return None,
                };
                self.set_gpr(rt, 64, false, v);
                Some(())
            }
            0xd51 => {
                // MSR (register)
                let v = self.gpr(rt, 64, false);
                match sysreg {
                    NZCV => {
                        let mut fl = Vec::new();
                        for b in [31, 30, 29, 28] {
                            fl.push(self.extract(v.clone(), b, b + 1));
                        }
                        let [n, z, cf, vf]: [Var; 4] = fl.try_into().ok()?;
                        self.set_nzcv(n, z, cf, vf);
                    }
                    R_FPCR => self.copy(Place::reg(FPCR), v),
                    R_FPSR => self.copy(Place::reg(FPSR), v),
                    R_TPIDR => self.copy(Place::reg(TPIDR), v),
                    _ => return None,
                }
                Some(())
            }
            _ => None,
        }
    }

    // ---- data processing: register

    fn dp_reg(&mut self, i: u32) -> Option<()> {
        let sf = bit(i, 31) == 1;
        let w: Width = if sf { 64 } else { 32 };
        let rd = field(i, 0, 5);
        let rn = field(i, 5, 5);
        let rm = field(i, 16, 5);
        let wu = u32::from(w);
        if i & 0x1f00_0000 == 0x0a00_0000 {
            // Logical (shifted register)
            let amt = field(i, 10, 6);
            if !sf && amt > 31 {
                return None;
            }
            let opc = field(i, 29, 2);
            let a = self.gpr(rn, w, false);
            let m = self.gpr(rm, w, false);
            let mut b = self.shift(m, field(i, 22, 2), amt, w);
            if bit(i, 21) == 1 {
                b = self.un(UnOp::Not, b, w);
            }
            let op = match opc {
                0 | 3 => BinOp::And,
                1 => BinOp::Or,
                _ => BinOp::Xor,
            };
            let r = self.bin(op, a, b, w);
            if opc == 3 {
                let (n, z) = self.nz(&r, w);
                self.set_nzcv(n, z, c(0, 1), c(0, 1));
            }
            self.set_gpr(rd, w, false, r);
            return Some(());
        }
        if i & 0x1f20_0000 == 0x0b00_0000 {
            // Add/sub (shifted register)
            let ty = field(i, 22, 2);
            let amt = field(i, 10, 6);
            if ty == 3 || (!sf && amt > 31) {
                return None;
            }
            let s = bit(i, 29) == 1;
            let a = self.gpr(rn, w, false);
            let m = self.gpr(rm, w, false);
            let b = self.shift(m, ty, amt, w);
            let r = self.addsub(bit(i, 30) == 1, a, b, w, s);
            self.set_gpr(rd, w, false, r);
            return Some(());
        }
        if i & 0x1f20_0000 == 0x0b20_0000 {
            // Add/sub (extended register)
            let sh = field(i, 10, 3);
            if sh > 4 || field(i, 22, 2) != 0 {
                return None;
            }
            let s = bit(i, 29) == 1;
            let a = self.gpr(rn, w, true);
            let b = self.extend_reg(rm, field(i, 13, 3), sh, w);
            let r = self.addsub(bit(i, 30) == 1, a, b, w, s);
            self.set_gpr(rd, w, !s, r);
            return Some(());
        }
        if i & 0x1fe0_fc00 == 0x1a00_0000 {
            // ADC / ADCS / SBC / SBCS
            let s = bit(i, 29) == 1;
            let a = self.gpr(rn, w, false);
            let mut b = self.gpr(rm, w, false);
            if bit(i, 30) == 1 {
                b = self.un(UnOp::Not, b, w);
            }
            let r = self.adc(a, b, w, s);
            self.set_gpr(rd, w, false, r);
            return Some(());
        }
        if i & 0x1fe0_0010 == 0x1a40_0000 && bit(i, 29) == 1 {
            // CCMN / CCMP (register or immediate)
            if bit(i, 10) == 1 {
                return None;
            }
            let cond = self.cond(field(i, 12, 4));
            let a = self.gpr(rn, w, false);
            let b = if bit(i, 11) == 1 {
                c(u64::from(rm), w)
            } else {
                self.gpr(rm, w, false)
            };
            let sub = bit(i, 30) == 1;
            let r = self.bin(
                if sub { BinOp::Sub } else { BinOp::Add },
                a.clone(),
                b.clone(),
                w,
            );
            let cf = if sub {
                self.bin(BinOp::Ule, b.clone(), a.clone(), 1)
            } else {
                self.bin(BinOp::Carry, a.clone(), b.clone(), 1)
            };
            let v = self.bin(if sub { BinOp::Sborrow } else { BinOp::Scarry }, a, b, 1);
            let (n, z) = self.nz(&r, w);
            let nzcv = field(i, 0, 4);
            let mut out = Vec::new();
            for (f, b) in [(n, 3), (z, 2), (cf, 1), (v, 0)] {
                out.push(self.select(cond.clone(), f, c(u64::from((nzcv >> b) & 1), 1), 1));
            }
            let [n, z, cf, v]: [Var; 4] = out.try_into().ok()?;
            self.set_nzcv(n, z, cf, v);
            return Some(());
        }
        if i & 0x1fe0_0000 == 0x1a80_0000 && bit(i, 29) == 0 {
            // CSEL / CSINC / CSINV / CSNEG
            let op2 = field(i, 10, 2);
            if op2 > 1 {
                return None;
            }
            let cond = self.cond(field(i, 12, 4));
            let a = self.gpr(rn, w, false);
            let m = self.gpr(rm, w, false);
            let b = match (bit(i, 30), op2) {
                (0, 0) => m,
                (0, _) => self.bin(BinOp::Add, m, c(1, w), w),
                (_, 0) => self.un(UnOp::Not, m, w),
                _ => self.un(UnOp::Neg, m, w),
            };
            let r = self.select(cond, a, b, w);
            self.set_gpr(rd, w, false, r);
            return Some(());
        }
        if i & 0x5fe0_0000 == 0x1ac0_0000 && bit(i, 29) == 0 {
            // Data processing (2 source)
            let a = self.gpr(rn, w, false);
            let b = self.gpr(rm, w, false);
            let r = match field(i, 10, 6) {
                0b000010 => self.bin(BinOp::Udiv, a, b, w),
                0b000011 => self.bin(BinOp::Sdiv, a, b, w),
                op @ 0b001000..=0b001011 => {
                    let amt = self.bin(BinOp::And, b, c(u64::from(wu - 1), w), w);
                    match op & 3 {
                        0 => self.bin(BinOp::Shl, a, amt, w),
                        1 => self.bin(BinOp::Lshr, a, amt, w),
                        2 => self.bin(BinOp::Ashr, a, amt, w),
                        _ => {
                            let lo = self.bin(BinOp::Lshr, a.clone(), amt.clone(), w);
                            let inv = self.bin(BinOp::Sub, c(u64::from(wu), w), amt, w);
                            let hi = self.bin(BinOp::Shl, a, inv, w);
                            self.bin(BinOp::Or, lo, hi, w)
                        }
                    }
                }
                _ => return None,
            };
            self.set_gpr(rd, w, false, r);
            return Some(());
        }
        if i & 0x5fe0_0000 == 0x5ac0_0000 && bit(i, 29) == 0 {
            // Data processing (1 source)
            if field(i, 16, 5) != 0 {
                return None;
            }
            let x = self.gpr(rn, w, false);
            let r = match field(i, 10, 6) {
                0 => self.rbit(x, w),
                1 => self.rev_chunks(x, w, 16),
                // REV32 (64-bit) and REV (32-bit): bytes within 32-bit chunks.
                2 => self.rev_chunks(x, w, 32),
                3 if sf => self.rev_chunks(x, w, 64),
                4 => self.clz(x, w),
                5 => {
                    let hi = self.bin(BinOp::Lshr, x.clone(), c(1, w), w);
                    let lo = self.bin(BinOp::And, x, c(ones(wu - 1), w), w);
                    let y = self.bin(BinOp::Xor, hi, lo, w);
                    let z = self.clz(y, w);
                    self.bin(BinOp::Sub, z, c(1, w), w)
                }
                _ => return None,
            };
            self.set_gpr(rd, w, false, r);
            return Some(());
        }
        if i & 0x1f00_0000 == 0x1b00_0000 {
            return self.dp3(i);
        }
        None
    }

    /// Reverse the bytes within each `chunk`-bit unit (REV16/REV32/REV).
    fn rev_chunks(&mut self, x: Var, w: Width, chunk: Width) -> Var {
        let mut acc: Option<Var> = None;
        let mut base = 0;
        while base < w {
            for b in 0..chunk / 8 {
                // Byte `b` of this chunk moves to byte `chunk/8 - 1 - b`.
                let lo = base + 8 * b;
                let byte = self.extract(x.clone(), lo, lo + 8);
                let z = self.zext(byte, w);
                let to = base + chunk - 8 - 8 * b;
                let placed = if to == 0 {
                    z
                } else {
                    self.bin(BinOp::Shl, z, c(u64::from(to), w), w)
                };
                acc = Some(match acc {
                    None => placed,
                    Some(a) => self.bin(BinOp::Or, a, placed, w),
                });
            }
            base += chunk;
        }
        acc.unwrap_or_else(|| c(0, w))
    }

    fn rbit(&mut self, x: Var, w: Width) -> Var {
        let mut v = x;
        let masks: [(u64, u32); 6] = [
            (0x5555_5555_5555_5555, 1),
            (0x3333_3333_3333_3333, 2),
            (0x0f0f_0f0f_0f0f_0f0f, 4),
            (0x00ff_00ff_00ff_00ff, 8),
            (0x0000_ffff_0000_ffff, 16),
            (0x0000_0000_ffff_ffff, 32),
        ];
        for (m, s) in masks {
            if s >= u32::from(w) {
                break;
            }
            let m = m & ones(u32::from(w));
            let a = self.bin(BinOp::Lshr, v.clone(), c(u64::from(s), w), w);
            let a = self.bin(BinOp::And, a, c(m, w), w);
            let b = self.bin(BinOp::And, v, c(m, w), w);
            let b = self.bin(BinOp::Shl, b, c(u64::from(s), w), w);
            v = self.bin(BinOp::Or, a, b, w);
        }
        v
    }

    fn clz(&mut self, x: Var, w: Width) -> Var {
        // Smear the top set bit down, then count the zeros above it.
        let mut v = x;
        let mut s = 1;
        while s < u32::from(w) {
            let sh = self.bin(BinOp::Lshr, v.clone(), c(u64::from(s), w), w);
            v = self.bin(BinOp::Or, v, sh, w);
            s *= 2;
        }
        let pc = self.un(UnOp::Popcount, v, w);
        self.bin(BinOp::Sub, c(u64::from(w), w), pc, w)
    }

    fn dp3(&mut self, i: u32) -> Option<()> {
        let sf = bit(i, 31) == 1;
        let w: Width = if sf { 64 } else { 32 };
        let (rd, rn, ra, rm) = (
            field(i, 0, 5),
            field(i, 5, 5),
            field(i, 10, 5),
            field(i, 16, 5),
        );
        if field(i, 29, 2) != 0 {
            return None;
        }
        let o0 = bit(i, 15) == 1;
        let r = match field(i, 21, 3) {
            0 => {
                let a = self.gpr(rn, w, false);
                let b = self.gpr(rm, w, false);
                let p = self.bin(BinOp::Mul, a, b, w);
                let acc = self.gpr(ra, w, false);
                self.bin(if o0 { BinOp::Sub } else { BinOp::Add }, acc, p, w)
            }
            op @ (1 | 5) if sf => {
                let a = self.gpr(rn, 32, false);
                let b = self.gpr(rm, 32, false);
                let (a, b) = if op == 1 {
                    (self.sext(a, 64), self.sext(b, 64))
                } else {
                    (self.zext(a, 64), self.zext(b, 64))
                };
                let p = self.bin(BinOp::Mul, a, b, 64);
                let acc = self.gpr(ra, 64, false);
                self.bin(if o0 { BinOp::Sub } else { BinOp::Add }, acc, p, 64)
            }
            op @ (2 | 6) if sf && !o0 => {
                let a = self.gpr(rn, 64, false);
                let b = self.gpr(rm, 64, false);
                let (a, b) = if op == 2 {
                    (self.sext(a, 128), self.sext(b, 128))
                } else {
                    (self.zext(a, 128), self.zext(b, 128))
                };
                let p = self.bin(BinOp::Mul, a, b, 128);
                self.extract(p, 64, 128)
            }
            _ => return None,
        };
        self.set_gpr(rd, w, false, r);
        Some(())
    }

    // ---- loads and stores

    fn load(&mut self, rt: &Rt, addr: Var, bytes: u32, sign_to: Option<Width>) -> Var {
        let bits = (8 * bytes) as Width;
        let t = self.tmp(bits);
        self.op(Op::Load { dst: t, addr });
        let v: Var = t.into();
        match (rt, sign_to) {
            (Rt::G(..), Some(w)) => self.sext(v, w),
            _ => v,
        }
    }
    fn write_rt(&mut self, rt: &Rt, v: Var) {
        match *rt {
            Rt::G(n, w) => self.set_gpr(n, w, false, v),
            Rt::V(n, w) => {
                let v = self.zext(v, w);
                self.copy(Place::reg_w(vr(n), w), v);
            }
        }
    }
    fn read_rt(&self, rt: &Rt, bytes: u32) -> Var {
        let bits = (8 * bytes) as Width;
        match *rt {
            Rt::G(n, _) => self.gpr(n, bits, false),
            Rt::V(n, _) => Var::reg_w(vr(n), bits),
        }
    }
    fn store(&mut self, rt: &Rt, addr: Var, bytes: u32) {
        let a = self.read_rt(rt, bytes);
        self.op(Op::Store { addr, a });
    }

    /// Decode `size`/`V`/`opc` of a single-register load/store →
    /// (register, access bytes, load?, sign-extend-to). `None` for PRFM
    /// (returned as `Some(None)`) or unallocated.
    fn ls_kind(i: u32) -> Option<Option<LsKind>> {
        let size = field(i, 30, 2);
        let v = bit(i, 26) == 1;
        let opc = field(i, 22, 2);
        let rt = field(i, 0, 5);
        if v {
            let (bytes, load) = match (size, opc) {
                (0, 2) => (16, false),
                (0, 3) => (16, true),
                (s, 0) => (1 << s, false),
                (s, 1) => (1 << s, true),
                _ => return None,
            };
            return Some(Some((Rt::V(rt, (8 * bytes) as Width), bytes, load, None)));
        }
        let bytes = 1u32 << size;
        Some(Some(match opc {
            0 => (
                Rt::G(rt, if size == 3 { 64 } else { 32 }),
                bytes,
                false,
                None,
            ),
            1 => (
                Rt::G(rt, if size == 3 { 64 } else { 32 }),
                bytes,
                true,
                None,
            ),
            2 => {
                if size == 3 {
                    return Some(None); // PRFM
                }
                (Rt::G(rt, 64), bytes, true, Some(64))
            }
            _ => {
                if size >= 2 {
                    return None;
                }
                (Rt::G(rt, 32), bytes, true, Some(32))
            }
        }))
    }

    fn ldst(&mut self, i: u32) -> Option<()> {
        let rn = field(i, 5, 5);
        let rt = field(i, 0, 5);
        // Load register (literal)
        if i & 0x3b00_0000 == 0x1800_0000 {
            let opc = field(i, 30, 2);
            let addr = c(
                self.pc
                    .wrapping_add(sext_bits(u64::from(field(i, 5, 19)), 19) << 2),
                64,
            );
            let (r, bytes, sign) = if bit(i, 26) == 1 {
                match opc {
                    0 => (Rt::V(rt, 32), 4, None),
                    1 => (Rt::V(rt, 64), 8, None),
                    2 => (Rt::V(rt, 128), 16, None),
                    _ => return None,
                }
            } else {
                match opc {
                    0 => (Rt::G(rt, 32), 4, None),
                    1 => (Rt::G(rt, 64), 8, None),
                    2 => (Rt::G(rt, 64), 4, Some(64)),
                    _ => return Some(()), // PRFM (literal)
                }
            };
            let v = self.load(&r, addr, bytes, sign);
            self.write_rt(&r, v);
            return Some(());
        }
        // Load/store pair
        if i & 0x3a00_0000 == 0x2800_0000 {
            return self.ldst_pair(i);
        }
        // Exclusive / ordered / compare-and-swap
        if i & 0x3f00_0000 == 0x0800_0000 {
            return self.ldst_excl(i);
        }
        // LD1/ST1 (multiple structures)
        if i & 0xbfbf_0000 == 0x0c00_0000 || i & 0xbfa0_0000 == 0x0c80_0000 {
            return self.ld1_multi(i);
        }
        if i & 0x3b00_0000 == 0x3900_0000 {
            // Unsigned immediate offset.
            let Some(kind) = Self::ls_kind(i)? else {
                return Some(());
            };
            let (r, bytes, load, sign) = kind;
            let off = u64::from(field(i, 10, 12)) * u64::from(bytes);
            let base = self.gpr(rn, 64, true);
            let addr = self.bin(BinOp::Add, base, c(off, 64), 64);
            self.access(&r, addr, bytes, load, sign);
            return Some(());
        }
        if i & 0x3b20_0000 == 0x3800_0000 {
            // Unscaled / post-index / unprivileged / pre-index (imm9).
            let mode = field(i, 10, 2);
            if mode == 2 && bit(i, 26) == 1 {
                return None; // no unprivileged SIMD&FP forms
            }
            let Some(kind) = Self::ls_kind(i)? else {
                // PRFM: only the unscaled form (PRFUM) exists.
                return (mode == 0).then_some(());
            };
            let (r, bytes, load, sign) = kind;
            let imm = sext_bits(u64::from(field(i, 12, 9)), 9);
            let base = self.gpr(rn, 64, true);
            match field(i, 10, 2) {
                0 | 2 => {
                    let addr = self.bin(BinOp::Add, base, c(imm, 64), 64);
                    self.access(&r, addr, bytes, load, sign);
                }
                mode => {
                    let a0 = self.tmp(64);
                    self.copy(a0, base.clone());
                    let wb = self.bin(BinOp::Add, base, c(imm, 64), 64);
                    let addr = if mode == 3 { wb.clone() } else { a0.into() };
                    self.access(&r, addr, bytes, load, sign);
                    self.set_gpr(rn, 64, true, wb);
                }
            }
            return Some(());
        }
        if i & 0x3b20_0c00 == 0x3820_0800 {
            // Register offset.
            let option = field(i, 13, 3);
            if option & 2 == 0 {
                return None;
            }
            let Some(kind) = Self::ls_kind(i)? else {
                return Some(());
            };
            let (r, bytes, load, sign) = kind;
            let sh = if bit(i, 12) == 1 {
                bytes.trailing_zeros()
            } else {
                0
            };
            let off = self.extend_reg(field(i, 16, 5), option, sh, 64);
            let base = self.gpr(rn, 64, true);
            let addr = self.bin(BinOp::Add, base, off, 64);
            self.access(&r, addr, bytes, load, sign);
            return Some(());
        }
        if i & 0x3f20_0c00 == 0x3820_0000 {
            return self.atomic(i);
        }
        None
    }

    fn access(&mut self, r: &Rt, addr: Var, bytes: u32, load: bool, sign: Option<Width>) {
        if load {
            let v = self.load(r, addr, bytes, sign);
            self.write_rt(r, v);
        } else {
            self.store(r, addr, bytes);
        }
    }

    fn ldst_pair(&mut self, i: u32) -> Option<()> {
        let opc = field(i, 30, 2);
        let v = bit(i, 26) == 1;
        let load = bit(i, 22) == 1;
        let mode = field(i, 23, 2);
        let (rt, rt2, rn) = (field(i, 0, 5), field(i, 10, 5), field(i, 5, 5));
        let (mk, bytes, sign): (fn(u32) -> Rt, u32, Option<Width>) = if v {
            match opc {
                0 => (|n| Rt::V(n, 32), 4, None),
                1 => (|n| Rt::V(n, 64), 8, None),
                2 => (|n| Rt::V(n, 128), 16, None),
                _ => return None,
            }
        } else {
            match (opc, load) {
                (0, _) => (|n| Rt::G(n, 32), 4, None),
                (2, _) => (|n| Rt::G(n, 64), 8, None),
                (1, true) if mode != 0 => (|n| Rt::G(n, 64), 4, Some(64)),
                _ => return None, // STGP (MTE) and unallocated
            }
        };
        let scale = u64::from(bytes);
        let imm = sext_bits(u64::from(field(i, 15, 7)), 7).wrapping_mul(scale);
        let base = self.gpr(rn, 64, true);
        let (addr, wb) = match mode {
            0 | 2 => (self.bin(BinOp::Add, base, c(imm, 64), 64), None),
            1 => {
                let a0 = self.tmp(64);
                self.copy(a0, base.clone());
                let wb = self.bin(BinOp::Add, base, c(imm, 64), 64);
                (a0.into(), Some(wb))
            }
            _ => {
                let wb = self.bin(BinOp::Add, base, c(imm, 64), 64);
                (wb.clone(), Some(wb))
            }
        };
        let addr2 = self.bin(BinOp::Add, addr.clone(), c(scale, 64), 64);
        let (r1, r2) = (mk(rt), mk(rt2));
        if load {
            let a = self.load(&r1, addr, bytes, sign);
            let b = self.load(&r2, addr2, bytes, sign);
            self.write_rt(&r1, a);
            self.write_rt(&r2, b);
        } else {
            self.store(&r1, addr, bytes);
            self.store(&r2, addr2, bytes);
        }
        if let Some(wb) = wb {
            self.set_gpr(rn, 64, true, wb);
        }
        Some(())
    }

    fn ldst_excl(&mut self, i: u32) -> Option<()> {
        let size = field(i, 30, 2);
        let bytes = 1u32 << size;
        let rw: Width = if size == 3 { 64 } else { 32 };
        let (o2, l, o1) = (bit(i, 23), bit(i, 22) == 1, bit(i, 21));
        let (rs, rt2, rn, rt) = (
            field(i, 16, 5),
            field(i, 10, 5),
            field(i, 5, 5),
            field(i, 0, 5),
        );
        let base = self.gpr(rn, 64, true);
        let addr = self.tmp(64);
        self.copy(addr, base);
        let addr: Var = addr.into();
        let r = Rt::G(rt, rw);
        // Should-be-one register fields: anything else is CONSTRAINED
        // UNPREDICTABLE, so it is left to the intrinsic.
        let rs_sbo = (o2 == 1 && o1 == 0) || (o2 == 0 && l);
        if (rs_sbo && rs != 31) || (o1 == 0 && rt2 != 31) {
            return None;
        }
        match (o2, o1) {
            (1, 0) => {
                // LDAR/STLR/LDLAR/STLLR: plain ordered access.
                self.access(&r, addr, bytes, l, None);
            }
            (1, _) => {
                // CAS/CASA/CASL/CASAL
                if rt2 != 31 {
                    return None;
                }
                let bits = (8 * bytes) as Width;
                let old = self.load(&r, addr.clone(), bytes, None);
                let cmp = self.gpr(rs, bits, false);
                let new = self.gpr(rt, bits, false);
                let eq = self.bin(BinOp::Eq, old.clone(), cmp, 1);
                let val = self.select(eq, new, old.clone(), bits);
                self.op(Op::Store { addr, a: val });
                self.set_gpr(rs, rw, false, old);
            }
            (0, 0) => {
                if l {
                    self.access(&r, addr, bytes, true, None);
                } else {
                    // STXR/STLXR: always succeeds in this model.
                    self.store(&r, addr, bytes);
                    self.set_gpr(rs, 32, false, c(0, 32));
                }
            }
            _ => {
                // LDXP/STXP (size 1x); CASP (size 0x) is not modelled.
                if size < 2 {
                    return None;
                }
                let r2 = Rt::G(rt2, rw);
                let a2 = self.bin(BinOp::Add, addr.clone(), c(u64::from(bytes), 64), 64);
                if l {
                    let x = self.load(&r, addr, bytes, None);
                    let y = self.load(&r2, a2, bytes, None);
                    self.write_rt(&r, x);
                    self.write_rt(&r2, y);
                } else {
                    self.store(&r, addr, bytes);
                    self.store(&r2, a2, bytes);
                    self.set_gpr(rs, 32, false, c(0, 32));
                }
            }
        }
        Some(())
    }

    fn atomic(&mut self, i: u32) -> Option<()> {
        if bit(i, 26) == 1 {
            return None;
        }
        let size = field(i, 30, 2);
        let bytes = 1u32 << size;
        let bits = (8 * bytes) as Width;
        let rw: Width = if size == 3 { 64 } else { 32 };
        let (rs, rn, rt) = (field(i, 16, 5), field(i, 5, 5), field(i, 0, 5));
        let o3 = bit(i, 15);
        let opc = field(i, 12, 3);
        let base = self.gpr(rn, 64, true);
        let addr = self.tmp(64);
        self.copy(addr, base);
        let addr: Var = addr.into();
        let r = Rt::G(rt, rw);
        if o3 == 1 && opc == 4 {
            // LDAPR (A=1, R=0, Rs=11111)
            if rs != 31 || field(i, 22, 2) != 0b10 {
                return None;
            }
            self.access(&r, addr, bytes, true, None);
            return Some(());
        }
        if o3 == 1 && opc != 0 {
            return None;
        }
        let old = self.load(&r, addr.clone(), bytes, None);
        let s = self.gpr(rs, bits, false);
        let new = if o3 == 1 {
            s // SWP
        } else {
            match opc {
                0 => self.bin(BinOp::Add, old.clone(), s, bits),
                1 => {
                    let ns = self.un(UnOp::Not, s, bits);
                    self.bin(BinOp::And, old.clone(), ns, bits)
                }
                2 => self.bin(BinOp::Xor, old.clone(), s, bits),
                3 => self.bin(BinOp::Or, old.clone(), s, bits),
                k => {
                    let op = if k < 6 { BinOp::Slt } else { BinOp::Ult };
                    let max = k % 2 == 0;
                    // max: old < s ? s : old; min: s < old ? s : old.
                    let lt = if max {
                        self.bin(op, old.clone(), s.clone(), 1)
                    } else {
                        self.bin(op, s.clone(), old.clone(), 1)
                    };
                    self.select(lt, s, old.clone(), bits)
                }
            }
        };
        self.op(Op::Store { addr, a: new });
        self.write_rt(&r, old);
        Some(())
    }

    fn ld1_multi(&mut self, i: u32) -> Option<()> {
        let nregs = match field(i, 12, 4) {
            0b0111 => 1,
            0b1010 => 2,
            0b0110 => 3,
            0b0010 => 4,
            _ => return None,
        };
        let q = bit(i, 30) == 1;
        let load = bit(i, 22) == 1;
        let bytes: u32 = if q { 16 } else { 8 };
        let (rt, rn, rm) = (field(i, 0, 5), field(i, 5, 5), field(i, 16, 5));
        let post = bit(i, 23) == 1;
        let base = self.gpr(rn, 64, true);
        let a0 = self.tmp(64);
        self.copy(a0, base);
        let a0: Var = a0.into();
        let mut loaded = Vec::new();
        for k in 0..nregs {
            let r = Rt::V((rt + k) % 32, (8 * bytes) as Width);
            let addr = if k == 0 {
                a0.clone()
            } else {
                self.bin(BinOp::Add, a0.clone(), c(u64::from(k * bytes), 64), 64)
            };
            if load {
                let v = self.load(&r, addr, bytes, None);
                loaded.push((r, v));
            } else {
                self.store(&r, addr, bytes);
            }
        }
        for (r, v) in loaded {
            self.write_rt(&r, v);
        }
        if post {
            let inc = if rm == 31 {
                c(u64::from(nregs * bytes), 64)
            } else {
                self.gpr(rm, 64, false)
            };
            let wb = self.bin(BinOp::Add, a0, inc, 64);
            self.set_gpr(rn, 64, true, wb);
        }
        Some(())
    }

    // ---- SIMD & FP: moves only

    fn simd_fp(&mut self, i: u32) -> Option<()> {
        let rd = field(i, 0, 5);
        let rn = field(i, 5, 5);
        // FMOV (general)
        if i & 0x7f36_fc00 == 0x1e26_0000 {
            let sf = bit(i, 31) == 1;
            let ty = field(i, 22, 2);
            let rmode = field(i, 19, 2);
            let to_fp = bit(i, 16) == 1;
            let (bits, top) = match (sf, ty, rmode) {
                (false, 0, 0) => (32, false),
                (true, 1, 0) => (64, false),
                (true, 2, 1) => (64, true),
                (false, 3, 0) | (true, 3, 0) => (16, false),
                _ => return None,
            };
            let gw: Width = if sf { 64 } else { 32 };
            if to_fp {
                let x = self.gpr(rn, bits, false);
                if top {
                    let v = Var::reg(vr(rd));
                    let lo = self.extract(v, 0, 64);
                    let cat = self.tmp(128);
                    self.op(Op::Concat {
                        dst: cat,
                        hi: x,
                        lo,
                    });
                    self.copy(Place::reg(vr(rd)), cat.into());
                } else {
                    self.copy(Place::reg_w(vr(rd), bits), x);
                }
            } else {
                let v = if top {
                    self.extract(Var::reg(vr(rn)), 64, 128)
                } else {
                    Var::reg_w(vr(rn), bits)
                };
                self.set_gpr(rd, gw, false, v);
            }
            return Some(());
        }
        // FMOV (register)
        if i & 0xff3f_fc00 == 0x1e20_4000 {
            let bits: Width = match field(i, 22, 2) {
                0 => 32,
                1 => 64,
                3 => 16,
                _ => return None,
            };
            self.copy(Place::reg_w(vr(rd), bits), Var::reg_w(vr(rn), bits));
            return Some(());
        }
        // FMOV (scalar immediate)
        if i & 0xff20_1fe0 == 0x1e20_1000 {
            let bits: u32 = match field(i, 22, 2) {
                0 => 32,
                1 => 64,
                3 => 16,
                _ => return None,
            };
            let v = vfp_imm(field(i, 13, 8), bits);
            self.copy(Place::reg_w(vr(rd), bits as Width), c(v, bits as Width));
            return Some(());
        }
        // Advanced SIMD modified immediate (MOVI/MVNI/ORR/BIC/FMOV)
        if i & 0x9ff8_0400 == 0x0f00_0400 {
            let q = bit(i, 30) == 1;
            let op = bit(i, 29);
            let cmode = field(i, 12, 4);
            if bit(i, 11) == 1 {
                return None;
            }
            let imm8 = (field(i, 16, 3) << 5) | field(i, 5, 5);
            if cmode == 15 && op == 1 && !q {
                return None;
            }
            let imm = simd_imm(op, cmode, imm8)?;
            let w: Width = if q { 128 } else { 64 };
            let full = |x: u64| -> Var {
                if q {
                    Var::con((u128::from(x) << 64) | u128::from(x), 128)
                } else {
                    c(x, 64)
                }
            };
            let logic = matches!(cmode, 1 | 3 | 5 | 7 | 9 | 11);
            let r = if logic {
                let cur = Var::reg_w(vr(rd), w);
                if op == 0 {
                    self.bin(BinOp::Or, cur, full(imm), w)
                } else {
                    self.bin(BinOp::And, cur, full(!imm), w)
                }
            } else if op == 1 && cmode < 14 {
                full(!imm)
            } else {
                full(imm)
            };
            self.copy(Place::reg_w(vr(rd), w), r);
            return Some(());
        }
        // Advanced SIMD copy (DUP/INS/UMOV/SMOV)
        if i & 0x9fe0_8400 == 0x0e00_0400 {
            return self.simd_copy(i);
        }
        // Advanced SIMD three same, logical (AND/BIC/ORR/ORN/EOR/BSL/BIT/BIF)
        if i & 0x9f20_fc00 == 0x0e20_1c00 {
            let q = bit(i, 30) == 1;
            let w: Width = if q { 128 } else { 64 };
            let rm = field(i, 16, 5);
            let (a, b) = (Var::reg_w(vr(rn), w), Var::reg_w(vr(rm), w));
            let size = field(i, 22, 2);
            let r = if bit(i, 29) == 0 {
                match size {
                    0 => self.bin(BinOp::And, a, b, w),
                    1 => {
                        let nb = self.un(UnOp::Not, b, w);
                        self.bin(BinOp::And, a, nb, w)
                    }
                    2 => self.bin(BinOp::Or, a, b, w),
                    _ => {
                        let nb = self.un(UnOp::Not, b, w);
                        self.bin(BinOp::Or, a, nb, w)
                    }
                }
            } else {
                let d = Var::reg_w(vr(rd), w);
                match size {
                    0 => self.bin(BinOp::Xor, a, b, w),
                    // BSL: d = (d & n) | (!d & m)
                    1 => self.bitsel(d.clone(), a, b, w),
                    // BIT: d = (m & n) | (!m & d)
                    2 => self.bitsel(b, a, d, w),
                    // BIF: d = (!m & n) | (m & d)
                    _ => self.bitsel(b, d, a, w),
                }
            };
            self.copy(Place::reg_w(vr(rd), w), r);
            return Some(());
        }
        None
    }

    /// `(sel & x) | (!sel & y)`.
    fn bitsel(&mut self, sel: Var, x: Var, y: Var, w: Width) -> Var {
        let a = self.bin(BinOp::And, sel.clone(), x, w);
        let ns = self.un(UnOp::Not, sel, w);
        let b = self.bin(BinOp::And, ns, y, w);
        self.bin(BinOp::Or, a, b, w)
    }

    fn simd_copy(&mut self, i: u32) -> Option<()> {
        let q = bit(i, 30) == 1;
        let op = bit(i, 29);
        let imm5 = field(i, 16, 5);
        let imm4 = field(i, 11, 4);
        let (rd, rn) = (field(i, 0, 5), field(i, 5, 5));
        if imm5 & 0xf == 0 {
            return None;
        }
        let size = imm5.trailing_zeros();
        let esize = 8u32 << size;
        let idx = imm5 >> (size + 1);
        let lo = (idx * esize) as Width;
        let ew = esize as Width;
        let vw: Width = if q { 128 } else { 64 };
        let rep = |l: &mut Self, e: Var, w: Width| -> Var {
            let mut pat: u128 = 0;
            let mut k = 0;
            while k < u32::from(w) {
                pat |= 1u128 << k;
                k += esize;
            }
            let z = l.zext(e, w);
            l.bin(BinOp::Mul, z, Var::con(pat, w), w)
        };
        let insert = |l: &mut Self, x: Var, lo: Width| {
            let v = Var::reg(vr(rd));
            let m: u128 = ((1u128 << ew) - 1) << lo;
            let kept = l.bin(BinOp::And, v, Var::con(!m, 128), 128);
            let z = l.zext(x, 128);
            let sh = if lo == 0 {
                z
            } else {
                l.bin(BinOp::Shl, z, Var::con(u128::from(lo), 128), 128)
            };
            let r = l.bin(BinOp::Or, kept, sh, 128);
            l.copy(Place::reg(vr(rd)), r);
        };
        if op == 1 {
            // INS (element)
            if !q {
                return None;
            }
            let src = (imm4 >> size) * esize;
            let e = self.extract(Var::reg(vr(rn)), src as Width, (src + esize) as Width);
            insert(self, e, lo);
            return Some(());
        }
        match imm4 {
            0b0000 => {
                // DUP (element)
                if size == 3 && !q {
                    return None;
                }
                let e = self.extract(Var::reg(vr(rn)), lo, lo + ew);
                let r = rep(self, e, vw);
                self.copy(Place::reg_w(vr(rd), vw), r);
            }
            0b0001 => {
                // DUP (general)
                if size == 3 && !q {
                    return None;
                }
                let x = self.gpr(rn, ew, false);
                let r = rep(self, x, vw);
                self.copy(Place::reg_w(vr(rd), vw), r);
            }
            0b0011 => {
                // INS (general)
                if !q {
                    return None;
                }
                let x = self.gpr(rn, ew, false);
                insert(self, x, lo);
            }
            0b0101 | 0b0111 => {
                // SMOV / UMOV
                let signed = imm4 == 0b0101;
                let gw: Width = if q { 64 } else { 32 };
                if (!signed && ((q && size != 3) || (!q && size == 3)))
                    || (signed && (size >= 2 + u32::from(q)))
                {
                    return None;
                }
                let e = self.extract(Var::reg(vr(rn)), lo, lo + ew);
                let v = if signed {
                    self.sext(e, gw)
                } else {
                    self.zext(e, gw)
                };
                self.set_gpr(rd, gw, false, v);
            }
            _ => return None,
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Arch, State, Step};

    fn x(n: u32) -> RegId {
        xr(n)
    }

    /// Run one instruction word from `st`; returns the control step of the
    /// last IR op and whether it lifted fully.
    fn run(word: u32, pc: u64, st: &mut State) -> (Step, Lifted) {
        let mut v = Vec::new();
        let l = lift(word, pc, &mut v);
        let mut step = Step::Next;
        for i in &v {
            step = st.exec(i).expect("exec");
            if step != Step::Next && step != Step::NotTaken {
                break;
            }
        }
        (step, l)
    }

    fn st(regs: &[(u32, u64)]) -> State {
        let mut s = State::new();
        for &(n, v) in regs {
            s.set_reg(x(n), u128::from(v));
        }
        s
    }

    fn flags(s: &State) -> (u128, u128, u128, u128) {
        (s.reg(NF), s.reg(ZF), s.reg(CF), s.reg(VF))
    }

    #[test]
    fn register_ids_match_the_table() {
        let a = Arch::Aarch64;
        assert_eq!(a.reg("x30"), Some(xr(30)));
        assert_eq!(a.reg("sp"), Some(SP));
        assert_eq!(a.reg("N"), Some(NF));
        assert_eq!(a.reg("V"), Some(VF));
        assert_eq!(a.reg("v0"), Some(vr(0)));
        assert_eq!(a.reg("v31"), Some(vr(31)));
        assert_eq!(a.reg("fpcr"), Some(FPCR));
        assert_eq!(a.reg("tpidr_el0"), Some(TPIDR));
        assert_eq!(a.reg("tpidrro_el0"), Some(TPIDRRO));
    }

    #[test]
    fn bitmask_immediates() {
        // orr x0, xzr, #0xff (N=1 immr=0 imms=7)
        assert_eq!(bit_masks(1, 7, 0, true, 64).map(|m| m.0), Some(0xff));
        // and w0, w0, #0x55555555 (N=0 immr=0 imms=0b111100)
        assert_eq!(
            bit_masks(0, 0x3c, 0, true, 32).map(|m| m.0),
            Some(0x5555_5555)
        );
        // 0xffff0000ffff0000 (N=0, immr=16, imms=0b001111? esize 32)
        assert_eq!(
            bit_masks(0, 0x0f, 16, true, 64).map(|m| m.0),
            Some(0xffff_0000_ffff_0000)
        );
        assert_eq!(
            bit_masks(1, 0x3f, 0, true, 64),
            None,
            "all-ones is reserved"
        );
    }

    // ---- Day 6: arithmetic and logic

    #[test]
    fn add_sub_immediate_and_flags() {
        // add x0, x1, #0x10
        let mut s = st(&[(1, 5)]);
        run(0x9100_4020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x15);
        // add x0, x1, #1, lsl #12
        run(0x9140_0420, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x1005);
        // subs w0, w1, #5 → 0, Z=1 C=1
        run(0x7100_1420, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0);
        assert_eq!(flags(&s), (0, 1, 1, 0));
        // cmp w1, #6 → negative, borrow (C=0)
        run(0x7100_183f, 0, &mut s);
        assert_eq!(flags(&s), (1, 0, 0, 0));
        // adds x0, x1, #1 with x1 = i64::MAX → V=1, N=1
        let mut s = st(&[(1, i64::MAX as u64)]);
        run(0xb100_0420, 0, &mut s);
        assert_eq!(s.reg(x(0)), 1 << 63);
        assert_eq!(flags(&s), (1, 0, 0, 1));
        // add sp, sp, #0x20 (rd/rn = 31 are SP here)
        let mut s = State::new();
        s.set_reg(SP, 0x1000);
        run(0x9100_83ff, 0, &mut s);
        assert_eq!(s.reg(SP), 0x1020);
        // add w0, w1, #1 zero-extends into x0
        let mut s = st(&[(0, u64::MAX), (1, 0xffff_ffff)]);
        run(0x1100_0420, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0);
    }

    #[test]
    fn shifted_and_extended_register_forms() {
        // add x0, x1, x2, lsl #3
        let mut s = st(&[(1, 1), (2, 2)]);
        run(0x8b02_0c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 17);
        // sub x0, x1, x2, asr #1  with x2 = -8
        let mut s = st(&[(1, 0), (2, (-8i64) as u64)]);
        run(0xcb82_0420, 0, &mut s);
        assert_eq!(s.reg(x(0)), 4);
        // add x0, x1, w2, sxtw #2  with w2 = -1
        let mut s = st(&[(1, 100), (2, 0xffff_ffff)]);
        run(0x8b22_c820, 0, &mut s);
        assert_eq!(s.reg(x(0)), 96);
        // cmp x1, x2 (subs xzr, x1, x2) equal → Z=1 C=1
        let mut s = st(&[(1, 7), (2, 7)]);
        run(0xeb02_003f, 0, &mut s);
        assert_eq!(flags(&s), (0, 1, 1, 0));
        // neg x0, x1 (sub x0, xzr, x1)
        let mut s = st(&[(1, 3)]);
        run(0xcb01_03e0, 0, &mut s);
        assert_eq!(s.reg(x(0)), (-3i64) as u64 as u128);
    }

    #[test]
    fn logic_and_moves() {
        // mov x0, x1 (orr x0, xzr, x1)
        let mut s = st(&[(1, 0xabcd)]);
        run(0xaa01_03e0, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0xabcd);
        // and x0, x1, #0xff
        let mut s = st(&[(1, 0x1234)]);
        run(0x9240_1c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x34);
        // eon / bic: bic x0, x1, x2 → x1 & !x2
        let mut s = st(&[(1, 0xff), (2, 0x0f)]);
        run(0x8a22_0020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0xf0);
        // tst w1, #1 (ands wzr, w1, #1) → Z
        let mut s = st(&[(1, 2)]);
        run(0x7200_003f, 0, &mut s);
        assert_eq!(flags(&s), (0, 1, 0, 0));
        // movz x0, #0x1234, lsl #16 ; movk x0, #0x5678 ; movn w1, #0
        let mut s = State::new();
        run(0xd2a2_4680, 0, &mut s);
        run(0xf28a_cf00, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x1234_5678);
        run(0x1280_0001, 0, &mut s);
        assert_eq!(s.reg(x(1)), 0xffff_ffff);
        // mvn x0, x1
        let mut s = st(&[(1, 0)]);
        run(0xaa21_03e0, 0, &mut s);
        assert_eq!(s.reg(x(0)), u128::from(u64::MAX));
    }

    #[test]
    fn bitfields_and_shifts() {
        // lsl x0, x1, #4 (ubfm x0, x1, #60, #59)
        let mut s = st(&[(1, 0x1)]);
        run(0xd37c_ec20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x10);
        // lsr w0, w1, #4 (ubfm w0, w1, #4, #31)
        let mut s = st(&[(1, 0xf0)]);
        run(0x5304_7c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0xf);
        // asr x0, x1, #63 (sbfm x0, x1, #63, #63)
        let mut s = st(&[(1, 1 << 63)]);
        run(0x937f_fc20, 0, &mut s);
        assert_eq!(s.reg(x(0)), u128::from(u64::MAX));
        // sxtw x0, w1
        let mut s = st(&[(1, 0x8000_0000)]);
        run(0x9340_7c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0xffff_ffff_8000_0000);
        // uxtb w0, w1
        let mut s = st(&[(1, 0x1ff)]);
        run(0x5300_1c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0xff);
        // ubfx x0, x1, #8, #4
        let mut s = st(&[(1, 0xabcd)]);
        run(0xd348_2c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0xb);
        // bfi x0, x1, #8, #8 (bfm x0, x1, #56, #7)
        let mut s = st(&[(0, 0xffff_ffff), (1, 0x12)]);
        run(0xb378_1c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0xffff_12ff);
        // extr x0, x1, x2, #8 ; ror w0, w1, #4 (extr w0, w1, w1, #4)
        let mut s = st(&[(1, 0x11), (2, 0x2200)]);
        run(0x93c2_2020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x1100_0000_0000_0022);
        let mut s = st(&[(1, 0x1)]);
        run(0x1381_1020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x1000_0000);
        // lslv / asrv / rorv
        let mut s = st(&[(1, 1), (2, 65)]);
        run(0x9ac2_2020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 2, "shift amount is mod 64");
        let mut s = st(&[(1, 0x8000_0000), (2, 4)]);
        run(0x1ac2_2820, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0xf800_0000);
        let mut s = st(&[(1, 1), (2, 1)]);
        run(0x9ac2_2c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 1 << 63);
    }

    #[test]
    fn multiply_divide_and_bit_ops() {
        // mul x0, x1, x2 ; madd x0, x1, x2, x3 ; msub
        let mut s = st(&[(1, 6), (2, 7), (3, 100)]);
        run(0x9b02_7c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 42);
        run(0x9b02_0c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 142);
        run(0x9b02_8c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 58);
        // smull x0, w1, w2 with w1 = -2
        let mut s = st(&[(1, 0xffff_fffe), (2, 3)]);
        run(0x9b22_7c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), (-6i64) as u64 as u128);
        // umulh / smulh
        let mut s = st(&[(1, u64::MAX), (2, 2)]);
        run(0x9bc2_7c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 1);
        run(0x9b42_7c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), u128::from(u64::MAX), "-1 * 2 high half");
        // udiv by zero → 0 ; sdiv -7 / 2 = -3
        let mut s = st(&[(1, 9), (2, 0)]);
        run(0x9ac2_0820, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0);
        let mut s = st(&[(1, (-7i64) as u64), (2, 2)]);
        run(0x9ac2_0c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), (-3i64) as u64 as u128);
        // clz x0, x1 ; cls x0, x1 ; rev w0, w1 ; rev16 ; rbit
        let mut s = st(&[(1, 1 << 40)]);
        run(0xdac0_1020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 23);
        let mut s = st(&[(1, 0)]);
        run(0xdac0_1020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 64);
        let mut s = st(&[(1, u64::MAX)]);
        run(0xdac0_1420, 0, &mut s);
        assert_eq!(s.reg(x(0)), 63);
        let mut s = st(&[(1, 0x1122_3344)]);
        run(0x5ac0_0820, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x4433_2211);
        run(0x5ac0_0420, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x2211_4433);
        let mut s = st(&[(1, 0x0102_0304_0506_0708)]);
        run(0xdac0_0c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x0807_0605_0403_0201);
        let mut s = st(&[(1, 1)]);
        run(0xdac0_0020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 1 << 63);
    }

    #[test]
    fn carries_selects_and_conditional_compares() {
        // adds x0, x1, x2 (carry out) then adc x3, xzr, xzr → 1
        let mut s = st(&[(1, u64::MAX), (2, 1)]);
        run(0xab02_0020, 0, &mut s);
        assert_eq!(flags(&s), (0, 1, 1, 0));
        run(0x9a1f_03e3, 0, &mut s);
        assert_eq!(s.reg(x(3)), 1);
        // sbcs x0, x1, x2 with C=1: 5 - 3 = 2, C=1
        let mut s = st(&[(1, 5), (2, 3)]);
        s.set_reg(CF, 1);
        run(0xfa02_0020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 2);
        assert_eq!(flags(&s), (0, 0, 1, 0));
        // csel x0, x1, x2, eq ; cset w0, ne (csinc w0, wzr, wzr, eq)
        let mut s = st(&[(1, 10), (2, 20)]);
        s.set_reg(ZF, 1);
        run(0x9a82_0020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 10);
        run(0x1a9f_07e0, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0);
        s.set_reg(ZF, 0);
        run(0x1a9f_07e0, 0, &mut s);
        assert_eq!(s.reg(x(0)), 1);
        // cneg x0, x1, lt (csneg x0, x1, x1, ge) with N != V
        let mut s = st(&[(1, 5)]);
        s.set_reg(NF, 1);
        run(0xda81_a420, 0, &mut s);
        assert_eq!(s.reg(x(0)), (-5i64) as u64 as u128);
        // ccmp x1, #3, #0b0100, ne: Z=1 → flags = nzcv immediate (Z set)
        let mut s = st(&[(1, 3)]);
        s.set_reg(ZF, 1);
        run(0xfa43_1824, 0, &mut s);
        assert_eq!(flags(&s), (0, 1, 0, 0));
        // Z=0 → compare x1 with 3 → equal → Z=1, C=1
        s.set_reg(ZF, 0);
        run(0xfa43_1824, 0, &mut s);
        assert_eq!(flags(&s), (0, 1, 1, 0));
    }

    // ---- Day 7: memory

    #[test]
    fn loads_and_stores() {
        let mut s = st(&[(1, 0x1000), (2, 0x1122_3344_5566_7788)]);
        // str x2, [x1, #8] ; ldr x0, [x1, #8]
        run(0xf900_0422, 0, &mut s);
        run(0xf940_0420, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x1122_3344_5566_7788);
        assert_eq!(s.load_byte(0x1008), 0x88);
        // ldrb w0, [x1, #8] ; ldrsb x0, [x1, #8] ; ldrsh w0, [x1, #8]
        run(0x3940_2020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x88);
        run(0x3980_2020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0xffff_ffff_ffff_ff88);
        run(0x79c0_1020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x7788, "0x7788 is positive");
        // ldrsh w0, [x1, #10] → 0x5566 ; ldursh x0, [x1, #7] → 0x8800 negative
        run(0x79c0_1420, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x5566);
        run(0x7880_7020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0xffff_ffff_ffff_8800);
        // ldrsw x0, [x1, #12] → 0x11223344
        run(0xb980_0c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x1122_3344);
        // ldur w0, [x1, #9] (unscaled)
        run(0xb840_9020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x4455_6677);
        // str x2, [x1, #-16]! (pre-index) → x1 = 0xff0
        run(0xf81f_0c22, 0, &mut s);
        assert_eq!(s.reg(x(1)), 0xff0);
        assert_eq!(s.load_byte(0xff0), 0x88);
        // ldr x0, [x1], #16 (post-index) → reads 0xff0, x1 = 0x1000
        run(0xf841_0420, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x1122_3344_5566_7788);
        assert_eq!(s.reg(x(1)), 0x1000);
        // ldr x0, [x1, x3, lsl #3] with x3 = 1
        s.set_reg(x(3), 1);
        run(0xf863_7820, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x1122_3344_5566_7788);
        // ldr w0, [x1, w4, sxtw] with w4 = -8 → 0xff8 (zeros)
        s.set_reg(x(4), 0xffff_fff8);
        run(0xb864_c820, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0);
        // prfm pldl1keep, [x1] is a no-op
        assert_eq!(run(0xf980_0020, 0, &mut s).1, Lifted::Ok);
    }

    #[test]
    fn pairs_literals_and_sp() {
        let mut s = st(&[(29, 0xaaaa), (30, 0xbbbb)]);
        s.set_reg(SP, 0x2000);
        // stp x29, x30, [sp, #-16]!
        run(0xa9bf_7bfd, 0, &mut s);
        assert_eq!(s.reg(SP), 0x1ff0);
        // ldp x0, x1, [sp], #16
        run(0xa8c1_07e0, 0, &mut s);
        assert_eq!((s.reg(x(0)), s.reg(x(1))), (0xaaaa, 0xbbbb));
        assert_eq!(s.reg(SP), 0x2000);
        // ldp x1, x0, [x0] style overlap: ldp x0, x1, [x0]
        let mut s = st(&[(0, 0x3000)]);
        s.store_byte(0x3000, 7);
        s.store_byte(0x3008, 9);
        run(0xa940_0400, 0, &mut s);
        assert_eq!((s.reg(x(0)), s.reg(x(1))), (7, 9));
        // ldpsw x0, x1, [x2]
        let mut s = st(&[(2, 0x4000)]);
        for (k, b) in [0xffu8, 0xff, 0xff, 0xff, 1, 0, 0, 0].iter().enumerate() {
            s.store_byte(0x4000 + k as u64, *b);
        }
        run(0x6940_0440, 0, &mut s);
        assert_eq!((s.reg(x(0)), s.reg(x(1))), (u128::from(u64::MAX), 1));
        // ldr x0, #8 (literal) at pc 0x5000
        let mut s = State::new();
        s.store_byte(0x5008, 0x42);
        run(0x5800_0040, 0x5000, &mut s);
        assert_eq!(s.reg(x(0)), 0x42);
        // stp q0, q1, [x2] / ldr d3, [x2, #16]
        let mut s = st(&[(2, 0x6000)]);
        s.set_reg(vr(0), 0x0102);
        s.set_reg(vr(1), 0x0304);
        run(0xad00_0440, 0, &mut s);
        run(0xfd40_0843, 0, &mut s);
        assert_eq!(s.reg(vr(3)), 0x0304);
        // ld1 {v0.16b, v1.16b}, [x2], #32
        s.set_reg(vr(0), 0);
        run(0x4cdf_a040, 0, &mut s);
        assert_eq!((s.reg(vr(0)), s.reg(vr(1))), (0x0102, 0x0304));
        assert_eq!(s.reg(x(2)), 0x6020);
    }

    #[test]
    fn exclusives_and_atomics() {
        let mut s = st(&[(1, 0x7000), (2, 5)]);
        // stxr w3, x2, [x1] → stored, w3 = 0 ; ldaxr x0, [x1]
        s.set_reg(x(3), 9);
        run(0xc803_7c22, 0, &mut s);
        assert_eq!(s.reg(x(3)), 0);
        run(0xc85f_fc20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 5);
        // ldadd x2, x0, [x1] → x0 = old (5), mem = 10
        run(0xf822_0020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 5);
        run(0xf940_0020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 10);
        // swp x2, x0, [x1] → x0 = 10, mem = 5
        run(0xf822_8020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 10);
        // cas x4, x6, [x1]: x4 = 5 == mem → mem = x6
        s.set_reg(x(4), 5);
        s.set_reg(x(6), 77);
        run(0xc8a4_7c26, 0, &mut s);
        assert_eq!(s.reg(x(4)), 5);
        run(0xf940_0020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 77);
        // cas again with x4 = 5 (mem is 77) → no store, x4 = 77
        run(0xc8a4_7c26, 0, &mut s);
        assert_eq!(s.reg(x(4)), 77);
        // ldumax w2, w0, [x1]: mem=77 (low 32), w2=5 → max 77
        run(0xb822_6020, 0, &mut s);
        assert_eq!(s.reg(x(0)), 77);
        // ldar / stlr
        assert_eq!(run(0xc8df_fc20, 0, &mut s).1, Lifted::Ok);
        assert_eq!(run(0xc89f_fc22, 0, &mut s).1, Lifted::Ok);
    }

    /// Values from running `ldsmaxb` on an Apple M-series CPU (Unicorn
    /// 2.1.5 gets sub-64-bit signed atomics wrong; see drishti-difftest).
    #[test]
    fn signed_atomics() {
        // ldsmaxb w25, w0, [x24] with w25 low byte 0xe0 (-32)
        for (old, want) in [
            (0x00u8, 0x00u8),
            (0x7f, 0x7f),
            (0x80, 0xe0),
            (0xf0, 0xf0),
            (0x10, 0x10),
        ] {
            let mut s = st(&[(24, 0x9000), (25, 0x4007_d0e0)]);
            s.store_byte(0x9000, old);
            run(0x3839_4300, 0, &mut s);
            assert_eq!(s.load_byte(0x9000), want, "old {old:#x}");
            assert_eq!(s.reg(x(0)), u128::from(old));
        }
        // ldsmin w25, w0, [x24] with w25 = -128 → stored -128
        let mut s = st(&[(24, 0x9000), (25, 0xffff_ff80)]);
        s.store_byte(0x9000, 1);
        run(0xb839_5300, 0, &mut s);
        assert_eq!(s.load_byte(0x9000), 0x80);
    }

    // ---- Day 8: control flow

    #[test]
    fn branches() {
        let mut s = State::new();
        // b +0x40 ; bl -4 (x30 = pc + 4)
        assert_eq!(run(0x1400_0010, 0x1000, &mut s).0, Step::Branch(0x1040));
        assert_eq!(run(0x97ff_ffff, 0x1000, &mut s).0, Step::Call(0xffc));
        assert_eq!(s.reg(x(30)), 0x1004);
        // b.eq +8 with Z=1 / Z=0
        s.set_reg(ZF, 1);
        assert_eq!(run(0x5400_0040, 0x1000, &mut s).0, Step::Branch(0x1008));
        s.set_reg(ZF, 0);
        assert_eq!(run(0x5400_0040, 0x1000, &mut s).0, Step::NotTaken);
        // b.gt: Z=0, N=V → taken
        assert_eq!(run(0x5400_004c, 0x1000, &mut s).0, Step::Branch(0x1008));
        // cbz x0 / cbnz w0
        let mut s = st(&[(0, 0)]);
        assert_eq!(run(0xb400_0040, 0x1000, &mut s).0, Step::Branch(0x1008));
        assert_eq!(run(0x3500_0040, 0x1000, &mut s).0, Step::NotTaken);
        // tbnz x0, #33, +8 / tbz
        let mut s = st(&[(0, 1 << 33)]);
        assert_eq!(run(0xb708_0040, 0x1000, &mut s).0, Step::Branch(0x1008));
        assert_eq!(run(0xb608_0040, 0x1000, &mut s).0, Step::NotTaken);
        // br x16 ; blr x30 (reads x30 before writing it) ; ret ; retaa
        let mut s = st(&[(16, 0x4000), (30, 0x5000)]);
        assert_eq!(run(0xd61f_0200, 0x1000, &mut s).0, Step::Indirect(0x4000));
        assert_eq!(run(0xd63f_03c0, 0x1000, &mut s).0, Step::Indirect(0x5000));
        assert_eq!(s.reg(x(30)), 0x1004);
        assert_eq!(run(0xd65f_03c0, 0x1000, &mut s).0, Step::Return);
        assert_eq!(run(0xd65f_0bff, 0x1000, &mut s), (Step::Return, Lifted::Ok));
    }

    #[test]
    fn system_and_unknowns() {
        let mut s = State::new();
        // nop, paciasp, bti c, dmb ish, isb
        for w in [
            0xd503_201f,
            0xd503_233f,
            0xd503_245f,
            0xd503_3bbf,
            0xd503_3fdf,
        ] {
            assert_eq!(run(w, 0, &mut s).1, Lifted::Ok, "{w:#x}");
        }
        // mrs x0, tpidrro_el0
        s.set_reg(TPIDRRO, 0x55);
        run(0xd53b_d060, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0x55);
        // mrs x1, nzcv with Z and C
        s.set_reg(ZF, 1);
        s.set_reg(CF, 1);
        run(0xd53b_4201, 0, &mut s);
        assert_eq!(s.reg(x(1)), 0x6000_0000);
        // Unknown semantics become intrinsics: svc, fadd d0, d1, d2, udf.
        let mut v = Vec::new();
        assert_eq!(
            lift(0xd400_1001, 0, &mut v),
            Lifted::Intrinsic("a64.exception")
        );
        assert_eq!(lift(0x1e62_2820, 0, &mut v), Lifted::Intrinsic("a64.fp"));
        assert_eq!(lift(0x0000_0000, 0, &mut v), Lifted::Intrinsic("a64.udf"));
        assert!(crate::render(&v).contains("INTRINSIC a64.fp(0x1e622820:32)"));
    }

    /// Bugs the Unicorn differential run found (Day 12), kept as
    /// regression tests: encodings that must NOT lift, and RET Xn.
    #[test]
    fn diff_test_regressions() {
        let mut v = Vec::new();
        for (w, what) in [
            (0x0e02_1c71u32, "INS (general) needs Q=1"),
            (0x1335_7004, "32-bit SBFM with imms<5> set"),
            (0xd503_317f, "barrier space, op2=011"),
            (0x8867_00d8, "LDXP with Rs != 11111"),
            (0x8859_d1cd, "LDAXR with Rs != 11111"),
            (0x3c52_e8ad, "unprivileged SIMD&FP load"),
            (0xf899_4f0b, "PRFM pre-index"),
            (0xf8a6_9971, "register offset with option 100"),
            (0xb8ff_c0d1, "LDAPR with R=1"),
        ] {
            assert!(
                matches!(lift(w, 0, &mut v), Lifted::Intrinsic(_)),
                "{w:#010x}: {what}"
            );
        }
        // ret x5 jumps to x5, not x30.
        let mut s = st(&[(5, 0x7000), (30, 0x9000)]);
        assert_eq!(run(0xd65f_00a0, 0, &mut s).0, Step::Indirect(0x7000));
    }

    #[test]
    fn simd_moves() {
        let mut s = st(&[(1, 0x1122_3344_5566_7788)]);
        // fmov d0, x1 ; fmov x2, d0 ; fmov s3, w1
        run(0x9e67_0020, 0, &mut s);
        assert_eq!(s.reg(vr(0)), 0x1122_3344_5566_7788);
        run(0x9e66_0002, 0, &mut s);
        assert_eq!(s.reg(x(2)), 0x1122_3344_5566_7788);
        run(0x1e27_0023, 0, &mut s);
        assert_eq!(s.reg(vr(3)), 0x5566_7788);
        // fmov v0.d[1], x1 (top half)
        run(0x9eaf_0020, 0, &mut s);
        assert_eq!(s.reg(vr(0)) >> 64, 0x1122_3344_5566_7788);
        // fmov d1, #1.0 ; fmov s1, #-2.0
        run(0x1e6e_1001, 0, &mut s);
        assert_eq!(s.reg(vr(1)), u128::from(1.0f64.to_bits()));
        run(0x1e30_1001, 0, &mut s);
        assert_eq!(s.reg(vr(1)), u128::from((-2.0f32).to_bits()));
        // movi v0.2d, #0 ; movi v1.16b, #0xff ; mvni v2.4s, #0
        run(0x6f00_e400, 0, &mut s);
        assert_eq!(s.reg(vr(0)), 0);
        run(0x4f07_e7e1, 0, &mut s);
        assert_eq!(s.reg(vr(1)), u128::MAX);
        run(0x6f00_0402, 0, &mut s);
        assert_eq!(s.reg(vr(2)), u128::MAX);
        // umov w0, v1.b[3] ; dup v4.4s, w1 ; ins v4.s[1], wzr
        s.set_reg(vr(1), 0xaa00_0000);
        run(0x0e07_3c20, 0, &mut s);
        assert_eq!(s.reg(x(0)), 0xaa);
        run(0x4e04_0c24, 0, &mut s);
        assert_eq!(s.reg(vr(4)), 0x5566_7788_5566_7788_5566_7788_5566_7788);
        run(0x4e0c_1fe4, 0, &mut s);
        assert_eq!(s.reg(vr(4)), 0x5566_7788_5566_7788_0000_0000_5566_7788);
        // mov v5.16b, v4.16b (orr) ; eor v5.16b, v5.16b, v5.16b
        run(0x4ea4_1c85, 0, &mut s);
        assert_eq!(s.reg(vr(5)), s.reg(vr(4)));
        run(0x6e25_1ca5, 0, &mut s);
        assert_eq!(s.reg(vr(5)), 0);
    }
}
