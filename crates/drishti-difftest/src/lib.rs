//! Differential testing of the AArch64 lifter (Days 11–12, ROADMAP B3):
//! run one instruction word in Unicorn and, lifted, in the IR interpreter
//! from the same machine state, and compare registers, flags, SIMD
//! registers, memory and the next PC.
//!
//! Test-only crate: Unicorn is GPL-2.0, so nothing in the shipped binary
//! depends on this crate (it is outside the workspace's default members).

use drishti_ir::a64::{self, CF, Lifted, NF, SP, VF, ZF};
use drishti_ir::{Arch, RegId, State, Step};
use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::{Arch as UArch, Mode, Prot};

/// The instruction sits in the middle of a 256 MiB code region, so every
/// B/BL target (±128 MiB) and PC-relative load is mapped: Unicorn fetches
/// at the branch target even when asked to run one instruction.
pub const CODE: u64 = 0x1000_0000;
pub const CODE_LEN: u64 = 0x1000_0000;
pub const PC: u64 = CODE + CODE_LEN / 2;
/// Data region (also executable, for register branches into it); pointer
/// registers point into its middle.
pub const DATA: u64 = 0x4000_0000;
pub const DATA_LEN: u64 = 0x10_0000;

/// Unicorn register numbers (generated `RegisterARM64`, unicorn 2.1.5).
mod ureg {
    pub const X29: i32 = 1;
    pub const X30: i32 = 2;
    pub const NZCV: i32 = 3;
    pub const SP: i32 = 4;
    pub const Q0: i32 = 104;
    pub const X0: i32 = 199;
    pub const PC: i32 = 260;
    pub const TPIDR_EL0: i32 = 262;
    pub const TPIDRRO_EL0: i32 = 263;
    pub fn x(n: usize) -> i32 {
        match n {
            29 => X29,
            30 => X30,
            n => X0 + n as i32,
        }
    }
}

/// Architectural state that both sides start from and are compared on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    pub x: [u64; 31],
    pub sp: u64,
    /// N Z C V in bits 3..0.
    pub nzcv: u8,
    pub v: [u128; 32],
    pub tpidr: u64,
    pub tpidrro: u64,
}

/// Memory initialised before the run: `(address, bytes)` windows in DATA.
pub type Windows = Vec<(u64, Vec<u8>)>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub m: Machine,
    pub next_pc: u64,
    /// The whole DATA region after the run.
    pub data: Vec<u8>,
    /// Bytes outside DATA (in the code region) the IR wrote, and their
    /// values; Unicorn's outcome holds its own memory at those addresses.
    pub other: Vec<(u64, u8)>,
}

fn id(name: &str) -> RegId {
    Arch::Aarch64.reg(name).unwrap_or(RegId(0))
}

fn initial_data(w: &Windows) -> Vec<u8> {
    let mut d = vec![0u8; DATA_LEN as usize];
    for (a, bytes) in w {
        let off = (a - DATA) as usize;
        d[off..off + bytes.len()].copy_from_slice(bytes);
    }
    d
}

/// Run in Unicorn. `Err` means Unicorn refused (fault, invalid encoding):
/// the caller decides whether that is a skip or a lifter bug.
pub fn run_unicorn(word: u32, m: &Machine, w: &Windows) -> Result<Outcome, String> {
    run_unicorn_probe(word, m, w, &[])
}

/// [`run_unicorn`], also reading memory at `probe` (addresses outside DATA).
pub fn run_unicorn_probe(
    word: u32,
    m: &Machine,
    w: &Windows,
    probe: &[u64],
) -> Result<Outcome, String> {
    let e = |x: unicorn_engine::unicorn_const::uc_error| format!("{x:?}");
    let mut uc = Unicorn::new(UArch::ARM64, Mode::ARM).map_err(e)?;
    uc.ctl_set_cpu_model(unicorn_engine::Arm64CpuModel::MAX as i32)
        .map_err(e)?;
    uc.mem_map(CODE, CODE_LEN, Prot::ALL).map_err(e)?;
    uc.mem_map(DATA, DATA_LEN, Prot::ALL).map_err(e)?;
    uc.mem_write(PC, &word.to_le_bytes()).map_err(e)?;
    for (a, bytes) in w {
        uc.mem_write(*a, bytes).map_err(e)?;
    }
    for (n, &v) in m.x.iter().enumerate() {
        uc.reg_write(ureg::x(n), v).map_err(e)?;
    }
    uc.reg_write(ureg::SP, m.sp).map_err(e)?;
    uc.reg_write(ureg::NZCV, u64::from(m.nzcv) << 28)
        .map_err(e)?;
    uc.reg_write(ureg::TPIDR_EL0, m.tpidr).map_err(e)?;
    uc.reg_write(ureg::TPIDRRO_EL0, m.tpidrro).map_err(e)?;
    for (n, &v) in m.v.iter().enumerate() {
        uc.reg_write_long(ureg::Q0 + n as i32, &v.to_le_bytes())
            .map_err(e)?;
    }
    uc.emu_start(PC, u64::MAX, 0, 1).map_err(e)?;
    let mut out = m.clone();
    for (n, x) in out.x.iter_mut().enumerate() {
        *x = uc.reg_read(ureg::x(n)).map_err(e)?;
    }
    out.sp = uc.reg_read(ureg::SP).map_err(e)?;
    out.nzcv = (uc.reg_read(ureg::NZCV).map_err(e)? >> 28) as u8 & 0xf;
    out.tpidr = uc.reg_read(ureg::TPIDR_EL0).map_err(e)?;
    out.tpidrro = uc.reg_read(ureg::TPIDRRO_EL0).map_err(e)?;
    for (n, v) in out.v.iter_mut().enumerate() {
        let b = uc.reg_read_long(ureg::Q0 + n as i32).map_err(e)?;
        let mut q = [0u8; 16];
        q.copy_from_slice(b.get(..16).ok_or("short Q register")?);
        *v = u128::from_le_bytes(q);
    }
    let next_pc = uc.reg_read(ureg::PC).map_err(e)?;
    let data = uc.mem_read_as_vec(DATA, DATA_LEN as usize).map_err(e)?;
    let mut other = Vec::new();
    for &a in probe {
        let mut b = [0u8; 1];
        uc.mem_read(a, &mut b).map_err(e)?;
        other.push((a, b[0]));
    }
    Ok(Outcome {
        m: out,
        next_pc,
        data,
        other,
    })
}

/// Lift and run in the IR interpreter. `Err` if the word is not fully
/// lifted or the IR touches memory outside DATA.
pub fn run_ir(word: u32, m: &Machine, w: &Windows) -> Result<Outcome, String> {
    let mut insns = Vec::new();
    if let Lifted::Intrinsic(c) = a64::lift(word, PC, &mut insns) {
        return Err(format!("not lifted ({c})"));
    }
    let mut st = State::new();
    for (n, &v) in m.x.iter().enumerate() {
        st.set_reg(id(&format!("x{n}")), u128::from(v));
    }
    st.set_reg(SP, u128::from(m.sp));
    for (k, f) in [NF, ZF, CF, VF].into_iter().enumerate() {
        st.set_reg(f, u128::from((m.nzcv >> (3 - k)) & 1));
    }
    for (n, &v) in m.v.iter().enumerate() {
        st.set_reg(id(&format!("v{n}")), v);
    }
    st.set_reg(id("tpidr_el0"), u128::from(m.tpidr));
    st.set_reg(id("tpidrro_el0"), u128::from(m.tpidrro));
    st.store_byte(PC, word as u8);
    for k in 1..4 {
        st.store_byte(PC + k, (word >> (8 * k)) as u8);
    }
    for (a, bytes) in w {
        for (k, b) in bytes.iter().enumerate() {
            st.store_byte(a + k as u64, *b);
        }
    }
    let mut next_pc = PC + 4;
    for i in &insns {
        match st.exec(i).map_err(|e| format!("{e:?}"))? {
            Step::Next | Step::NotTaken => {}
            Step::Branch(t) | Step::Call(t) | Step::Indirect(t) => {
                next_pc = t;
                break;
            }
            Step::Return => {
                next_pc = st.reg(id("x30")) as u64;
                break;
            }
        }
    }
    let mut out = m.clone();
    for (n, x) in out.x.iter_mut().enumerate() {
        *x = st.reg(id(&format!("x{n}"))) as u64;
    }
    out.sp = st.reg(SP) as u64;
    out.nzcv = [NF, ZF, CF, VF]
        .into_iter()
        .fold(0u8, |acc, f| (acc << 1) | (st.reg(f) & 1) as u8);
    for (n, v) in out.v.iter_mut().enumerate() {
        *v = st.reg(id(&format!("v{n}")));
    }
    out.tpidr = st.reg(id("tpidr_el0")) as u64;
    out.tpidrro = st.reg(id("tpidrro_el0")) as u64;
    let mut data = initial_data(w);
    let mut other = Vec::new();
    for (a, b) in st.written() {
        if (DATA..DATA + DATA_LEN).contains(&a) {
            data[(a - DATA) as usize] = b;
        } else if (CODE..CODE + CODE_LEN).contains(&a) {
            other.push((a, b));
        } else {
            return Err(format!("IR wrote outside mapped memory at {a:#x}"));
        }
    }
    // The instruction word itself (written by the setup, never by the IR
    // unless it stores over it) only counts if it changed.
    let word_bytes = word.to_le_bytes();
    other.retain(|&(a, b)| !(PC..PC + 4).contains(&a) || b != word_bytes[(a - PC) as usize]);
    other.sort_unstable();
    Ok(Outcome {
        m: out,
        next_pc,
        data,
        other,
    })
}

/// A readable difference between two outcomes (`None` if equal).
pub fn diff(ir: &Outcome, uc: &Outcome) -> Option<String> {
    let mut d = Vec::new();
    for n in 0..31 {
        if ir.m.x[n] != uc.m.x[n] {
            d.push(format!(
                "x{n}: ir {:#x} unicorn {:#x}",
                ir.m.x[n], uc.m.x[n]
            ));
        }
    }
    if ir.m.sp != uc.m.sp {
        d.push(format!("sp: ir {:#x} unicorn {:#x}", ir.m.sp, uc.m.sp));
    }
    if ir.m.nzcv != uc.m.nzcv {
        d.push(format!(
            "nzcv: ir {:04b} unicorn {:04b}",
            ir.m.nzcv, uc.m.nzcv
        ));
    }
    for n in 0..32 {
        if ir.m.v[n] != uc.m.v[n] {
            d.push(format!(
                "v{n}: ir {:#x} unicorn {:#x}",
                ir.m.v[n], uc.m.v[n]
            ));
        }
    }
    if ir.m.tpidr != uc.m.tpidr {
        d.push(format!(
            "tpidr_el0: ir {:#x} unicorn {:#x}",
            ir.m.tpidr, uc.m.tpidr
        ));
    }
    if ir.next_pc != uc.next_pc {
        d.push(format!(
            "pc: ir {:#x} unicorn {:#x}",
            ir.next_pc, uc.next_pc
        ));
    }
    if let Some(i) = (0..ir.data.len()).find(|&i| ir.data[i] != uc.data[i]) {
        let n = (0..ir.data.len())
            .filter(|&i| ir.data[i] != uc.data[i])
            .count();
        d.push(format!(
            "memory: {n} bytes differ, first at {:#x}: ir {:#04x} unicorn {:#04x}",
            DATA + i as u64,
            ir.data[i],
            uc.data[i]
        ));
    }
    let mut theirs = uc.other.clone();
    theirs.sort_unstable();
    if ir.other != theirs {
        d.push(format!(
            "code-region memory: ir {:x?} unicorn {:x?}",
            ir.other, theirs
        ));
    }
    if d.is_empty() {
        None
    } else {
        Some(d.join("; "))
    }
}

/// Encodings whose behaviour this lifter deliberately models differently
/// from a real CPU (documented in `a64.rs`), or that are UNPREDICTABLE.
pub fn excluded(w: u32) -> bool {
    let hint = w & 0xffff_f01f == 0xd503_201f;
    let crm = (w >> 8) & 0xf;
    let op2 = (w >> 5) & 7;
    // Pointer-authentication hints (PACIASP, AUTIASP, XPACLRI, ...): with
    // PAuth on, Unicorn signs/strips x30; the lifter treats them as NOPs.
    if hint && (crm == 1 || crm == 3 || (crm == 0 && op2 == 7)) {
        return true;
    }
    // Pointer-authenticated branches (BRAA, BLRAA, RETAA, ...).
    if w & 0xfe00_0000 == 0xd600_0000 && ((w >> 21) & 0xf >= 8 || (w >> 10) & 0x3f != 0) {
        return true;
    }
    // Exclusive stores: the single-threaded model always succeeds; a real
    // monitor without a prior load-exclusive fails.
    if w & 0x3f00_0000 == 0x0800_0000 && (w >> 23) & 1 == 0 && (w >> 22) & 1 == 0 {
        return true;
    }
    // Newer than Unicorn's CPU model: DSB nXS (Armv8.7) and SB (Armv8.5).
    if w & 0xffff_f01f == 0xd503_301f && ((w >> 5) & 7 == 1 || (w >> 5) & 7 == 7) {
        return true;
    }
    // Unicorn 2.1.5 (QEMU 5) bug: LDSMAX/LDSMIN on bytes, halfwords and
    // words compare unsigned. Verified against an Apple M-series CPU, which
    // agrees with the lifter (regression test `a64::tests::signed_atomics`).
    if w & 0x3f20_8c00 == 0x3820_0000 && matches!((w >> 12) & 7, 4 | 5) && w >> 30 < 3 {
        return true;
    }
    unpredictable(w)
}

/// Writeback with the base register also transferred, and load pairs into
/// one register: UNPREDICTABLE in the Arm ARM.
fn unpredictable(w: u32) -> bool {
    let rt = w & 0x1f;
    let rn = (w >> 5) & 0x1f;
    let rt2 = (w >> 10) & 0x1f;
    // Single register, pre/post-index (imm9 forms with writeback).
    if w & 0x3b20_0000 == 0x3800_0000 && (w >> 10) & 1 == 1 && rn == rt && rn != 31 {
        return true;
    }
    // Pairs.
    if w & 0x3a00_0000 == 0x2800_0000 {
        let wb = (w >> 23) & 3 == 1 || (w >> 23) & 3 == 3;
        let load = (w >> 22) & 1 == 1;
        let gpr = (w >> 26) & 1 == 0;
        if gpr && wb && rn != 31 && (rn == rt || rn == rt2) {
            return true;
        }
        if load && rt == rt2 {
            return true;
        }
    }
    // LD1/ST1 multiple, post-index: base among the transferred registers is
    // fine (SIMD), nothing to exclude.
    false
}

/// Run the IR first (to learn which code-region bytes it writes), then
/// Unicorn probing those bytes. `Ok(None)`: Unicorn refused (skip).
pub fn run_both(word: u32, m: &Machine, w: &Windows) -> Result<Option<(Outcome, Outcome)>, String> {
    let ir = run_ir(word, m, w);
    let probe: Vec<u64> = ir
        .as_ref()
        .map(|o| o.other.iter().map(|x| x.0).collect())
        .unwrap_or_default();
    let uc = match run_unicorn_probe(word, m, w, &probe) {
        Ok(u) => u,
        Err(_) => return Ok(None),
    };
    Ok(Some((ir?, uc)))
}
