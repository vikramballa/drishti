//! Per-architecture register tables. A [`RegId`] is a `u16`: the high byte
//! picks the architecture, the low byte indexes its table, so ids from
//! different architectures never collide and print without extra context.
//!
//! Only full architectural registers are listed. Sub-registers (`w0`, `eax`,
//! `al`) are a narrower width of the full register (see [`crate::Var::reg_w`]);
//! there is no zero register (`xzr` reads lift to the constant 0).

use crate::Width;
use serde::{Deserialize, Serialize};

/// Architectures with a register table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    Aarch64,
    X86_64,
}

/// A register id (`arch << 8 | index`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RegId(pub u16);

/// One register table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegInfo {
    pub name: &'static str,
    pub width: Width,
}

const fn r(name: &'static str, width: Width) -> RegInfo {
    RegInfo { name, width }
}

/// AArch64: x0–x30, sp, pc, the NZCV flags, v0–v31, fpcr, fpsr, the two
/// thread-pointer registers. Ids are fixed (the lifter indexes them
/// directly), so new registers are only ever appended.
const AARCH64: &[RegInfo] = &[
    r("x0", 64),
    r("x1", 64),
    r("x2", 64),
    r("x3", 64),
    r("x4", 64),
    r("x5", 64),
    r("x6", 64),
    r("x7", 64),
    r("x8", 64),
    r("x9", 64),
    r("x10", 64),
    r("x11", 64),
    r("x12", 64),
    r("x13", 64),
    r("x14", 64),
    r("x15", 64),
    r("x16", 64),
    r("x17", 64),
    r("x18", 64),
    r("x19", 64),
    r("x20", 64),
    r("x21", 64),
    r("x22", 64),
    r("x23", 64),
    r("x24", 64),
    r("x25", 64),
    r("x26", 64),
    r("x27", 64),
    r("x28", 64),
    r("x29", 64),
    r("x30", 64),
    r("sp", 64),
    r("pc", 64),
    r("N", 1),
    r("Z", 1),
    r("C", 1),
    r("V", 1),
    r("v0", 128),
    r("v1", 128),
    r("v2", 128),
    r("v3", 128),
    r("v4", 128),
    r("v5", 128),
    r("v6", 128),
    r("v7", 128),
    r("v8", 128),
    r("v9", 128),
    r("v10", 128),
    r("v11", 128),
    r("v12", 128),
    r("v13", 128),
    r("v14", 128),
    r("v15", 128),
    r("v16", 128),
    r("v17", 128),
    r("v18", 128),
    r("v19", 128),
    r("v20", 128),
    r("v21", 128),
    r("v22", 128),
    r("v23", 128),
    r("v24", 128),
    r("v25", 128),
    r("v26", 128),
    r("v27", 128),
    r("v28", 128),
    r("v29", 128),
    r("v30", 128),
    r("v31", 128),
    r("fpcr", 64),
    r("fpsr", 64),
    r("tpidr_el0", 64),
    r("tpidrro_el0", 64),
];

/// x86-64: the 16 general registers, rip, the arithmetic flags + DF,
/// xmm0–xmm15, fs/gs base.
const X86_64: &[RegInfo] = &[
    r("rax", 64),
    r("rcx", 64),
    r("rdx", 64),
    r("rbx", 64),
    r("rsp", 64),
    r("rbp", 64),
    r("rsi", 64),
    r("rdi", 64),
    r("r8", 64),
    r("r9", 64),
    r("r10", 64),
    r("r11", 64),
    r("r12", 64),
    r("r13", 64),
    r("r14", 64),
    r("r15", 64),
    r("rip", 64),
    r("CF", 1),
    r("PF", 1),
    r("AF", 1),
    r("ZF", 1),
    r("SF", 1),
    r("DF", 1),
    r("OF", 1),
    r("xmm0", 128),
    r("xmm1", 128),
    r("xmm2", 128),
    r("xmm3", 128),
    r("xmm4", 128),
    r("xmm5", 128),
    r("xmm6", 128),
    r("xmm7", 128),
    r("xmm8", 128),
    r("xmm9", 128),
    r("xmm10", 128),
    r("xmm11", 128),
    r("xmm12", 128),
    r("xmm13", 128),
    r("xmm14", 128),
    r("xmm15", 128),
    r("fs_base", 64),
    r("gs_base", 64),
];

impl Arch {
    const ALL: [Arch; 2] = [Arch::Aarch64, Arch::X86_64];

    fn tag(self) -> u16 {
        match self {
            Arch::Aarch64 => 1,
            Arch::X86_64 => 2,
        }
    }

    /// This architecture's register table, in id order.
    pub fn regs(self) -> &'static [RegInfo] {
        match self {
            Arch::Aarch64 => AARCH64,
            Arch::X86_64 => X86_64,
        }
    }

    /// Id of the register named `name` (ASCII case-insensitive).
    pub fn reg(self, name: &str) -> Option<RegId> {
        let i = self
            .regs()
            .iter()
            .position(|r| r.name.eq_ignore_ascii_case(name))?;
        Some(RegId(self.tag() << 8 | i as u16))
    }

    /// Ids of every register in the table.
    pub fn reg_ids(self) -> impl Iterator<Item = RegId> {
        let tag = self.tag() << 8;
        (0..self.regs().len() as u16).map(move |i| RegId(tag | i))
    }
}

impl RegId {
    pub fn arch(self) -> Option<Arch> {
        Arch::ALL.into_iter().find(|a| a.tag() == self.0 >> 8)
    }
    /// Table entry, or `None` for an id no table knows (e.g. deserialised).
    pub fn info(self) -> Option<&'static RegInfo> {
        self.arch()?.regs().get(usize::from(self.0 & 0xff))
    }
    /// Register name (`"?"` for an unknown id).
    pub fn name(self) -> &'static str {
        self.info().map_or("?", |r| r.name)
    }
    /// Full register width (64 for an unknown id).
    pub fn width(self) -> Width {
        self.info().map_or(64, |r| r.width)
    }
}

impl std::fmt::Display for RegId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.info() {
            Some(r) => f.write_str(r.name),
            None => write!(f, "reg{:#06x}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables() {
        for a in Arch::ALL {
            assert!(a.regs().len() <= 256);
            for id in a.reg_ids() {
                assert_eq!(id.arch(), Some(a));
                assert_eq!(a.reg(id.name()), Some(id), "{}", id.name());
            }
        }
        let x0 = Arch::Aarch64.reg("X0").expect("x0");
        assert_eq!((x0.name(), x0.width()), ("x0", 64));
        assert_eq!(Arch::Aarch64.reg("v31").map(RegId::width), Some(128));
        assert_eq!(Arch::X86_64.reg("zf").map(RegId::width), Some(1));
        // Same index, different architecture: different ids.
        assert_ne!(Arch::X86_64.reg("rax"), Some(x0));
        assert_eq!(Arch::Aarch64.reg("eax"), None);
        assert_eq!(RegId(0xff00).to_string(), "reg0xff00");
    }
}
