//! Minimal per-instruction semantics needed for control-flow recovery.
//!
//! Analysis only needs length, flow kind, direct target and referenced
//! address. Producing these without building strings keeps discovery fast
//! and allocation-free; text is rendered separately for visible windows.

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction as XInsn, Mnemonic, OpKind, Register,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Next,
    Jump(u64),
    CondJump(u64),
    IndirectJump,
    Call(u64),
    IndirectCall,
    Ret,
    /// Trap / invalid / halt: execution does not continue.
    Stop,
}

impl Flow {
    pub fn ends_block(self) -> bool {
        matches!(
            self,
            Flow::Jump(_) | Flow::CondJump(_) | Flow::IndirectJump | Flow::Ret | Flow::Stop
        )
    }
}

/// AArch64 address-forming instruction details for register tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A64Op {
    None,
    /// ADRP/ADR: rd = value
    SetAddr {
        rd: u8,
        value: u64,
    },
    /// ADD rd, rn, #imm (64-bit)
    AddImm {
        rd: u8,
        rn: u8,
        imm: u64,
    },
    /// LDR/STR/LDRB.. [rn, #imm]: memory at rn+imm; `rt` is the loaded reg
    /// (only meaningful for 64-bit loads, else 0xff).
    Mem {
        rn: u8,
        imm: u64,
        rt: u8,
        load64: bool,
    },
    /// Branch via register (BR/BLR/BRAA..): rn
    BrReg {
        rn: u8,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct Decoded {
    pub addr: u64,
    pub len: u8,
    pub flow: Flow,
    /// Absolute address referenced by a memory operand or immediate
    /// (x86 RIP-relative / absolute displacements, ARM64 ADR).
    pub mem_ref: Option<u64>,
    /// x86: true if the memory operand is a scaled-index table (`[base+idx*8+disp]`).
    pub table: Option<X86Table>,
    pub a64: A64Op,
    /// Compare-with-immediate value (`cmp reg, imm`) for jump-table bounds.
    pub cmp_imm: Option<u64>,
    pub is_nop_or_pad: bool,
    /// Raw AArch64 instruction word (0 for x86).
    pub raw: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86Table {
    pub disp: u64,
    pub scale: u8,
    pub has_base: bool,
}

/// x86 / x86-64 decoder (iced-x86).
pub fn decode_x86(bytes: &[u8], addr: u64, bitness: u32, out: &mut XInsn) -> Option<Decoded> {
    if bytes.is_empty() {
        return None;
    }
    let mut d = Decoder::with_ip(bitness, bytes, addr, DecoderOptions::NONE);
    d.decode_out(out);
    let i = &*out;
    if i.is_invalid() || i.code() == Code::INVALID {
        return None;
    }
    let flow = match i.flow_control() {
        FlowControl::Next | FlowControl::XbeginXabortXend => {
            if i.mnemonic() == Mnemonic::Hlt {
                Flow::Stop
            } else {
                Flow::Next
            }
        }
        FlowControl::UnconditionalBranch => match i.op0_kind() {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Flow::Jump(i.near_branch_target())
            }
            _ => Flow::IndirectJump,
        },
        FlowControl::ConditionalBranch => match i.op0_kind() {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Flow::CondJump(i.near_branch_target())
            }
            _ => Flow::Next,
        },
        FlowControl::IndirectBranch => Flow::IndirectJump,
        FlowControl::Return => Flow::Ret,
        FlowControl::Call => match i.op0_kind() {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Flow::Call(i.near_branch_target())
            }
            _ => Flow::IndirectCall,
        },
        FlowControl::IndirectCall => Flow::IndirectCall,
        FlowControl::Interrupt => {
            // int3 / ud2 / int 0x29 (fastfail) end execution; syscalls continue.
            match i.mnemonic() {
                Mnemonic::Int3 | Mnemonic::Ud2 | Mnemonic::Ud0 | Mnemonic::Ud1 => Flow::Stop,
                Mnemonic::Int if i.immediate8() == 0x29 => Flow::Stop,
                _ => Flow::Next,
            }
        }
        FlowControl::Exception => Flow::Stop,
    };
    let mut mem_ref = None;
    let mut table = None;
    for op in 0..i.op_count() {
        match i.op_kind(op) {
            OpKind::Memory => {
                if i.is_ip_rel_memory_operand() {
                    mem_ref = Some(i.ip_rel_memory_address());
                } else if i.memory_index() != Register::None && i.memory_index_scale() >= 4 {
                    table = Some(X86Table {
                        disp: i.memory_displacement64(),
                        scale: i.memory_index_scale() as u8,
                        has_base: i.memory_base() != Register::None,
                    });
                } else if i.memory_base() == Register::None && i.memory_index() == Register::None {
                    mem_ref = Some(i.memory_displacement64());
                }
            }
            OpKind::Immediate32 | OpKind::Immediate32to64
                if bitness == 32 && i.mnemonic() != Mnemonic::Cmp =>
            {
                let v = i.immediate(op);
                if v > 0x10000 {
                    mem_ref = Some(v);
                }
            }
            _ => {}
        }
    }
    let cmp_imm =
        if i.mnemonic() == Mnemonic::Cmp && i.op_count() == 2 && i.op0_kind() == OpKind::Register {
            match i.op1_kind() {
                OpKind::Immediate8
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32
                | OpKind::Immediate32to64
                | OpKind::Immediate16 => Some(i.immediate(1)),
                _ => None,
            }
        } else {
            None
        };
    let is_nop_or_pad = matches!(i.mnemonic(), Mnemonic::Nop | Mnemonic::Int3);
    Some(Decoded {
        addr,
        len: i.len() as u8,
        flow,
        mem_ref,
        table,
        a64: A64Op::None,
        cmp_imm,
        is_nop_or_pad,
        raw: 0,
    })
}

#[inline]
fn sext(v: u64, bits: u32) -> i64 {
    let s = 64 - bits;
    ((v << s) as i64) >> s
}

/// AArch64 decoder for control flow and address formation, by direct
/// encoding match (ARM ARM C4.1). Every 32-bit word decodes; unknown
/// encodings are treated as ordinary instructions.
pub fn decode_a64(bytes: &[u8], addr: u64) -> Option<Decoded> {
    let w: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    let i = u32::from_le_bytes(w);
    let mut flow = Flow::Next;
    let mut a64 = A64Op::None;
    let mut mem_ref = None;
    let mut cmp_imm = None;
    let rd = (i & 0x1f) as u8;
    let rn = ((i >> 5) & 0x1f) as u8;
    if i & 0x7c00_0000 == 0x1400_0000 {
        // B / BL imm26
        let t = addr.wrapping_add((sext(u64::from(i & 0x03ff_ffff), 26) << 2) as u64);
        flow = if i & 0x8000_0000 != 0 {
            Flow::Call(t)
        } else {
            Flow::Jump(t)
        };
    } else if i & 0xff00_0000 == 0x5400_0000 {
        // B.cond / BC.cond imm19
        let t = addr.wrapping_add((sext(u64::from((i >> 5) & 0x7ffff), 19) << 2) as u64);
        let cond = i & 0xf;
        flow = if cond >= 0xe {
            Flow::Jump(t)
        } else {
            Flow::CondJump(t)
        };
    } else if i & 0x7e00_0000 == 0x3400_0000 {
        // CBZ / CBNZ
        let t = addr.wrapping_add((sext(u64::from((i >> 5) & 0x7ffff), 19) << 2) as u64);
        flow = Flow::CondJump(t);
    } else if i & 0x7e00_0000 == 0x3600_0000 {
        // TBZ / TBNZ imm14
        let t = addr.wrapping_add((sext(u64::from((i >> 5) & 0x3fff), 14) << 2) as u64);
        flow = Flow::CondJump(t);
    } else if i >> 25 == 0b110_1011 {
        // Unconditional branch (register): BR, BLR, RET, ERET and PAC forms.
        let opc = (i >> 21) & 0xf;
        flow = match opc {
            0b0000 | 0b1000 => {
                a64 = A64Op::BrReg { rn };
                Flow::IndirectJump
            }
            0b0001 | 0b1001 => {
                a64 = A64Op::BrReg { rn };
                Flow::IndirectCall
            }
            0b0010 | 0b0100 => Flow::Ret,
            _ => Flow::Next,
        };
    } else if i & 0xffe0_001f == 0xd420_0000 || i & 0xffe0_001f == 0xd440_0000 || i >> 16 == 0 {
        // BRK / HLT / UDF
        flow = Flow::Stop;
    } else if i & 0x1f00_0000 == 0x1000_0000 {
        // ADR / ADRP
        let immlo = u64::from((i >> 29) & 3);
        let immhi = u64::from((i >> 5) & 0x7ffff);
        let imm = sext((immhi << 2) | immlo, 21);
        let value = if i & 0x8000_0000 != 0 {
            (addr & !0xfff).wrapping_add((imm << 12) as u64)
        } else {
            mem_ref = Some(addr.wrapping_add(imm as u64));
            addr.wrapping_add(imm as u64)
        };
        a64 = A64Op::SetAddr { rd, value };
    } else if i & 0xff80_0000 == 0x9100_0000 {
        // ADD Xd, Xn, #imm{, lsl #12}
        let mut imm = u64::from((i >> 10) & 0xfff);
        if i & 0x0040_0000 != 0 {
            imm <<= 12;
        }
        a64 = A64Op::AddImm { rd, rn, imm };
    } else if i & 0x3b00_0000 == 0x3900_0000 {
        // LDR/STR (unsigned immediate), all sizes incl. SIMD/FP.
        let size = (i >> 30) & 3;
        let v = (i >> 26) & 1;
        let opc = (i >> 22) & 3;
        let scale = if v == 1 && opc >= 2 { 4 } else { size };
        let imm = u64::from((i >> 10) & 0xfff) << scale;
        let load64 = v == 0 && size == 3 && opc == 1;
        a64 = A64Op::Mem {
            rn,
            imm,
            rt: if load64 { rd } else { 0xff },
            load64,
        };
    } else if i & 0x3b00_0000 == 0x1800_0000 {
        // LDR (literal)
        let t = addr.wrapping_add((sext(u64::from((i >> 5) & 0x7ffff), 19) << 2) as u64);
        mem_ref = Some(t);
    } else if i & 0x7f80_0000 == 0x7100_0000 && rd == 0x1f {
        // CMP Wn/Xn, #imm (SUBS xzr, xn, #imm)
        let mut imm = u64::from((i >> 10) & 0xfff);
        if i & 0x0040_0000 != 0 {
            imm <<= 12;
        }
        cmp_imm = Some(imm);
    }
    // NOP, BTI, PACIBSP/PACIASP hints (hint space) count as padding-neutral.
    let is_nop_or_pad = i == 0xd503_201f;
    Some(Decoded {
        addr,
        len: 4,
        flow,
        mem_ref,
        table: None,
        a64,
        cmp_imm,
        is_nop_or_pad,
        raw: i,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a64(word: u32, addr: u64) -> Decoded {
        decode_a64(&word.to_le_bytes(), addr).unwrap()
    }

    #[test]
    fn a64_branches() {
        assert_eq!(a64(0x9400_0010, 0x1000).flow, Flow::Call(0x1040)); // bl +0x40
        assert_eq!(a64(0x17ff_ffff, 0x1000).flow, Flow::Jump(0xffc)); // b -4
        assert_eq!(a64(0x5400_0040, 0x1000).flow, Flow::CondJump(0x1008)); // b.eq +8
        assert_eq!(a64(0xb400_0060, 0x1000).flow, Flow::CondJump(0x100c)); // cbz x0, +12
        assert_eq!(a64(0x3600_0040, 0x1000).flow, Flow::CondJump(0x1008)); // tbz w0, #0, +8
        assert_eq!(a64(0xd65f_03c0, 0).flow, Flow::Ret); // ret
        assert_eq!(a64(0xd65f_0fff, 0).flow, Flow::Ret); // retab
        assert_eq!(a64(0xd61f_0200, 0).flow, Flow::IndirectJump); // br x16
        assert_eq!(a64(0xd71f_0a11, 0).flow, Flow::IndirectJump); // braa x16, x17
        assert_eq!(a64(0xd63f_0100, 0).flow, Flow::IndirectCall); // blr x8
        assert_eq!(a64(0xd420_0020, 0).flow, Flow::Stop); // brk #1
        assert_eq!(a64(0xd503_201f, 0).flow, Flow::Next); // nop
    }

    #[test]
    fn a64_addr_forming() {
        // adrp x16, 0x1000 pages ahead? use immhi=1 -> +0x4000 (imm=4 -> <<12)
        let d = a64(0x9000_0030, 0x10_0123); // adrp x16, +0x4000? immlo=0 immhi=1
        assert_eq!(
            d.a64,
            A64Op::SetAddr {
                rd: 16,
                value: 0x10_4000
            }
        );
        let d = a64(0x9100_4210, 0); // add x16, x16, #0x10
        assert_eq!(
            d.a64,
            A64Op::AddImm {
                rd: 16,
                rn: 16,
                imm: 0x10
            }
        );
        let d = a64(0xf940_0610, 0); // ldr x16, [x16, #8]
        assert_eq!(
            d.a64,
            A64Op::Mem {
                rn: 16,
                imm: 8,
                rt: 16,
                load64: true
            }
        );
        assert_eq!(a64(0x7100_281f, 0).cmp_imm, Some(10)); // cmp w0, #10
    }

    #[test]
    fn x86_flow() {
        let mut ins = XInsn::default();
        // call rel32 +0
        let d = decode_x86(&[0xe8, 0, 0, 0, 0], 0x1000, 64, &mut ins).unwrap();
        assert_eq!(d.flow, Flow::Call(0x1005));
        // jmp [rip+0x10]
        let d = decode_x86(&[0xff, 0x25, 0x10, 0, 0, 0], 0x1000, 64, &mut ins).unwrap();
        assert_eq!(d.flow, Flow::IndirectJump);
        assert_eq!(d.mem_ref, Some(0x1016));
        let d = decode_x86(&[0xc3], 0, 64, &mut ins).unwrap();
        assert_eq!(d.flow, Flow::Ret);
        let d = decode_x86(&[0xcc], 0, 64, &mut ins).unwrap();
        assert_eq!(d.flow, Flow::Stop);
        // jmp qword [rax*8+0x401000]
        let d = decode_x86(&[0xff, 0x24, 0xc5, 0x00, 0x10, 0x40, 0x00], 0, 64, &mut ins).unwrap();
        assert_eq!(
            d.table,
            Some(X86Table {
                disp: 0x401000,
                scale: 8,
                has_base: false
            })
        );
        // cmp eax, 5
        let d = decode_x86(&[0x83, 0xf8, 0x05], 0, 64, &mut ins).unwrap();
        assert_eq!(d.cmp_imm, Some(5));
    }
}
