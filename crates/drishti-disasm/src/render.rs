//! Text disassembly for visible windows (iced-x86 Intel syntax for x86,
//! capstone for AArch64 and other architectures).

use crate::analyze::{Analysis, Func, a64_track_pub};
use crate::arch::{Flow, decode_a64, decode_x86};
use capstone::prelude::BuildsCapstone;
use drishti_loader::Image;
use drishti_loader::util::hex;
use drishti_model::{
    Addr, Arch, BasicBlock, Edge, Function, FunctionMetrics, InsnKind, Instruction,
};
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};

fn kind_of(f: Flow) -> (InsnKind, Vec<Addr>) {
    match f {
        Flow::Call(t) => (InsnKind::Call, vec![Addr(t)]),
        Flow::IndirectCall => (InsnKind::Call, vec![]),
        Flow::Jump(t) => (InsnKind::Jump, vec![Addr(t)]),
        Flow::IndirectJump => (InsnKind::Jump, vec![]),
        Flow::CondJump(t) => (InsnKind::Cjump, vec![Addr(t)]),
        Flow::Ret => (InsnKind::Ret, vec![]),
        Flow::Next | Flow::Stop => (InsnKind::Other, vec![]),
    }
}

thread_local! {
    /// Building a Capstone handle costs far more than decoding one
    /// instruction; whole-program instruction search renders millions.
    static A64: Option<capstone::Capstone> = capstone::Capstone::new()
        .arm64()
        .mode(capstone::arch::arm64::ArchMode::Arm)
        .build()
        .ok();
}

/// Disassemble `count` instructions starting at `addr`. `namer` resolves an
/// address to a display label (function, import, string preview).
pub fn disasm(
    img: &Image,
    addr: u64,
    count: usize,
    namer: &dyn Fn(u64) -> Option<String>,
) -> Vec<Instruction> {
    disasm_bounded(img, addr, count, u64::MAX, namer)
}

/// Like [`disasm`], but stops before `end` (e.g. the end of a function's
/// range) instead of decoding `count` instructions regardless.
pub fn disasm_bounded(
    img: &Image,
    addr: u64,
    count: usize,
    end: u64,
    namer: &dyn Fn(u64) -> Option<String>,
) -> Vec<Instruction> {
    let count = count.min(4096);
    let want = count
        .saturating_mul(16)
        .max(16)
        .min(usize::try_from(end.saturating_sub(addr)).unwrap_or(usize::MAX));
    let Some(bytes) = img.read(addr, want) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(count);
    match img.arch {
        Arch::X86 | Arch::X86_64 => {
            let bits = if img.arch == Arch::X86 { 32 } else { 64 };
            let mut dec = Decoder::with_ip(bits, bytes, addr, DecoderOptions::NONE);
            let mut fmt = IntelFormatter::new();
            fmt.options_mut().set_space_after_operand_separator(true);
            fmt.options_mut().set_hex_prefix("0x");
            fmt.options_mut().set_hex_suffix("");
            fmt.options_mut().set_uppercase_hex(false);
            fmt.options_mut().set_rip_relative_addresses(false);
            fmt.options_mut().set_branch_leading_zeros(false);
            fmt.options_mut().set_leading_zeros(false);
            fmt.options_mut().set_show_branch_size(false);
            let mut ins = iced_x86::Instruction::default();
            let mut scratch = iced_x86::Instruction::default();
            while dec.can_decode() && out.len() < count {
                let pos = dec.position();
                dec.decode_out(&mut ins);
                let ip = ins.ip();
                if ip >= end {
                    break;
                }
                let len = ins.len();
                let raw = &bytes[pos..pos + len];
                let mut mnemonic = String::new();
                let mut operands = String::new();
                fmt.format_mnemonic(&ins, &mut mnemonic);
                fmt.format_all_operands(&ins, &mut operands);
                let d = decode_x86(raw, ip, bits, &mut scratch);
                let (kind, targets) = d
                    .map(|d| kind_of(d.flow))
                    .unwrap_or((InsnKind::Other, vec![]));
                let comment = targets.first().and_then(|t| namer(t.0)).or_else(|| {
                    d.and_then(|d| d.mem_ref).and_then(|r| {
                        img.import_at(r)
                            .map(|s| s.display_name().to_string())
                            .or_else(|| namer(r))
                    })
                });
                if ins.is_invalid() {
                    mnemonic = "(bad)".into();
                }
                out.push(Instruction {
                    addr: Addr(ip),
                    size: len as u32,
                    bytes: hex(raw),
                    mnemonic,
                    operands,
                    kind,
                    targets,
                    comment,
                });
            }
        }
        Arch::Aarch64 if img.bits == 64 => A64.with(|cs| {
            let mut regs = [None; 32];
            let mut loaded = [None; 32];
            let mut off = 0usize;
            while out.len() < count && off + 4 <= bytes.len() {
                let a = addr + off as u64;
                if a >= end {
                    break;
                }
                let raw = &bytes[off..off + 4];
                let (mnemonic, operands) =
                    match cs.as_ref().and_then(|cs| cs.disasm_count(raw, a, 1).ok()) {
                        Some(insns) if !insns.is_empty() => {
                            let i = insns.iter().next().map(|i| {
                                (
                                    i.mnemonic().unwrap_or("").to_string(),
                                    i.op_str().unwrap_or("").to_string(),
                                )
                            });
                            i.unwrap_or_else(|| (".word".into(), format!("0x{}", hex(raw))))
                        }
                        _ => (
                            ".word".into(),
                            format!(
                                "0x{:08x}",
                                u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])
                            ),
                        ),
                    };
                let d = decode_a64(raw, a);
                let (kind, targets) = d
                    .map(|d| kind_of(d.flow))
                    .unwrap_or((InsnKind::Other, vec![]));
                let tracked = d.and_then(|d| {
                    let r = a64_track_pub(&d, &mut regs, &mut loaded);
                    if let crate::arch::A64Op::BrReg { rn } = d.a64 {
                        loaded[rn as usize].or(r)
                    } else {
                        r
                    }
                });
                let comment = targets.first().and_then(|t| namer(t.0)).or_else(|| {
                    tracked.and_then(|r| {
                        img.import_at(r)
                            .map(|s| s.display_name().to_string())
                            .or_else(|| namer(r))
                    })
                });
                if matches!(kind, InsnKind::Call) {
                    regs = [None; 32];
                    loaded = [None; 32];
                }
                out.push(Instruction {
                    addr: Addr(a),
                    size: 4,
                    bytes: hex(raw),
                    mnemonic,
                    operands,
                    kind,
                    targets,
                    comment,
                });
                off += 4;
            }
        }),
        other => {
            // Display-only for architectures the analyser does not cover yet.
            let cs = match other {
                Arch::Arm => capstone::Capstone::new()
                    .arm()
                    .mode(capstone::arch::arm::ArchMode::Arm)
                    .build(),
                Arch::Mips => capstone::Capstone::new()
                    .mips()
                    .mode(capstone::arch::mips::ArchMode::Mips32)
                    .build(),
                Arch::Mips64 => capstone::Capstone::new()
                    .mips()
                    .mode(capstone::arch::mips::ArchMode::Mips64)
                    .build(),
                Arch::Riscv64 => capstone::Capstone::new()
                    .riscv()
                    .mode(capstone::arch::riscv::ArchMode::RiscV64)
                    .build(),
                Arch::Ppc => capstone::Capstone::new()
                    .ppc()
                    .mode(capstone::arch::ppc::ArchMode::Mode64)
                    .build(),
                _ => return out,
            };
            let Ok(cs) = cs else { return out };
            if let Ok(insns) = cs.disasm_count(bytes, addr, count) {
                for i in insns.iter() {
                    out.push(Instruction {
                        addr: Addr(i.address()),
                        size: i.len() as u32,
                        bytes: hex(i.bytes()),
                        mnemonic: i.mnemonic().unwrap_or("").to_string(),
                        operands: i.op_str().unwrap_or("").to_string(),
                        kind: InsnKind::Other,
                        targets: vec![],
                        comment: None,
                    });
                }
            }
        }
    }
    out
}

/// Instruction addresses in `[start, end)` (decoding linearly).
pub fn insn_addrs(img: &Image, start: u64, end: u64) -> Vec<Addr> {
    let mut v = Vec::new();
    let mut a = start;
    let mut scratch = iced_x86::Instruction::default();
    while a < end && v.len() < 100_000 {
        let len = match img.arch {
            Arch::X86 | Arch::X86_64 => {
                let bits = if img.arch == Arch::X86 { 32 } else { 64 };
                match img
                    .read(a, 16)
                    .and_then(|b| decode_x86(b, a, bits, &mut scratch))
                {
                    Some(d) => u64::from(d.len),
                    None => break,
                }
            }
            _ => 4,
        };
        v.push(Addr(a));
        a += len;
    }
    v
}

/// Convert a compact `Func` to the normalized schema `Function`.
pub fn to_model(
    img: &Image,
    analysis: &Analysis,
    f: &Func,
    engine_version: &str,
    with_insns: bool,
) -> Function {
    let blocks = analysis
        .cfg(img, f.entry)
        .unwrap_or_default()
        .iter()
        .map(|b| BasicBlock {
            start: Addr(b.start),
            end: Addr(b.end),
            instructions: if with_insns {
                insn_addrs(img, b.start, b.end)
            } else {
                Vec::new()
            },
            successors: b
                .succs
                .iter()
                .map(|&(t, k)| Edge {
                    target: Addr(t),
                    kind: k,
                })
                .collect(),
        })
        .collect();
    Function {
        engine: drishti_model::EngineId::Core,
        engine_version: engine_version.to_string(),
        entry: Addr(f.entry),
        name: f.name.to_string(),
        name_source: f.name_source,
        size: Some(f.size),
        blocks,
        calls: f.calls.iter().map(|&c| Addr(c)).collect(),
        called_by: f.called_by.iter().map(|&c| Addr(c)).collect(),
        is_thunk: f.is_thunk,
        noreturn: f.noreturn,
        is_library: false,
        signature: None,
        decompiled: None,
        metrics: Some(FunctionMetrics {
            block_count: f.nblocks,
            edge_count: f.edge_count() as u32,
            cyclomatic: f.cyclomatic(),
            goto_count: None,
            loc: None,
        }),
    }
}
