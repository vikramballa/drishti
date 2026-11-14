//! Mach-O loader (macOS / iOS). Handles modern arm64e binaries that use
//! chained fixups: imports are resolved through the indirect symbol table,
//! which every linker still emits, instead of legacy bind opcodes.

use crate::LoadError;
use crate::image::*;
use crate::util::{demangle, entropy};
use drishti_model::{
    Addr, Arch, Endian, Format, Platform, Section, Symbol, SymbolKind, SymbolSource,
};
use goblin::mach::MachO;
use goblin::mach::load_command::CommandVariant;
use std::collections::HashMap;

const S_ZEROFILL: u32 = 0x1;
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
const S_SYMBOL_STUBS: u32 = 0x8;
const S_GB_ZEROFILL: u32 = 0xc;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x400;
const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;
const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_EXT: u8 = 0x01;
const N_UNDF: u8 = 0x0;
const N_SECT: u8 = 0xe;

pub fn cpu_arch(cputype: u32) -> (Arch, u8) {
    match cputype {
        7 => (Arch::X86, 32),
        0x0100_0007 => (Arch::X86_64, 64),
        12 => (Arch::Arm, 32),
        0x0100_000c => (Arch::Aarch64, 64),
        0x0200_000c => (Arch::Aarch64, 32), // arm64_32 (watchOS)
        18 => (Arch::Ppc, 32),
        0x0100_0012 => (Arch::Ppc, 64),
        _ => (Arch::Unknown, 64),
    }
}

struct RawSection {
    seg: String,
    name: String,
    addr: u64,
    size: u64,
    offset: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
}

fn cstr16(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn rd32(b: &[u8], o: usize, le: bool) -> Option<u32> {
    let a: [u8; 4] = b.get(o..o.checked_add(4)?)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    })
}
fn rd64(b: &[u8], o: usize, le: bool) -> Option<u64> {
    let a: [u8; 8] = b.get(o..o.checked_add(8)?)?.try_into().ok()?;
    Some(if le {
        u64::from_le_bytes(a)
    } else {
        u64::from_be_bytes(a)
    })
}

/// goblin's `Section` omits reserved1/2, which index the indirect symbol
/// table; read section headers directly from the load command bytes.
fn raw_sections(
    bytes: &[u8],
    cmd_off: usize,
    is64: bool,
    nsects: u32,
    le: bool,
) -> Vec<RawSection> {
    let (hdr, sz) = if is64 { (72usize, 80usize) } else { (56, 68) };
    let mut out = Vec::new();
    for i in 0..nsects.min(255) as usize {
        let o = cmd_off + hdr + i * sz;
        let Some(b) = bytes.get(o..o + sz) else { break };
        let (addr, size, rest) = if is64 {
            (rd64(b, 32, le), rd64(b, 40, le), 48)
        } else {
            (
                rd32(b, 32, le).map(u64::from),
                rd32(b, 36, le).map(u64::from),
                40,
            )
        };
        let (Some(addr), Some(size)) = (addr, size) else {
            break;
        };
        out.push(RawSection {
            name: cstr16(&b[0..16]),
            seg: cstr16(&b[16..32]),
            addr,
            size,
            offset: rd32(b, rest, le).unwrap_or(0),
            flags: rd32(b, rest + 16, le).unwrap_or(0),
            reserved1: rd32(b, rest + 20, le).unwrap_or(0),
            reserved2: rd32(b, rest + 24, le).unwrap_or(0),
        });
    }
    out
}

fn uleb(d: &[u8], p: &mut usize) -> Option<u64> {
    let mut r = 0u64;
    let mut s = 0u32;
    loop {
        let b = *d.get(*p)?;
        *p += 1;
        if s < 64 {
            r |= u64::from(b & 0x7f) << s;
        }
        if b & 0x80 == 0 {
            return Some(r);
        }
        s += 7;
        if s > 70 {
            return None;
        }
    }
}

pub(crate) fn load(img: &mut Image) -> Result<(), LoadError> {
    let blob = img.blob.clone();
    let bytes: &[u8] = blob
        .as_ref()
        .as_ref()
        .get(img.slice_offset..img.slice_offset + img.slice_len)
        .unwrap_or(&[]);
    let m = MachO::parse(bytes, 0).map_err(|e| LoadError::Malformed(e.to_string()))?;
    let le = m.little_endian;
    let (arch, bits) = cpu_arch(m.header.cputype);
    img.arch = arch;
    img.bits = bits;
    img.endian = if le { Endian::Little } else { Endian::Big };
    img.format = Format::Macho;
    img.platform = Platform::Macos;

    let mut sects: Vec<RawSection> = Vec::new();
    let mut text_base = None;
    let mut func_starts = None;
    let mut dysym = None;
    let mut encrypted = false;
    let mut export_trie: Option<(usize, usize)> = None;
    for lc in &m.load_commands {
        match &lc.command {
            CommandVariant::DyldInfo(d) | CommandVariant::DyldInfoOnly(d) => {
                if d.export_size > 0 {
                    export_trie = Some((d.export_off as usize, d.export_size as usize));
                }
            }
            CommandVariant::DyldExportsTrie(c) => {
                export_trie = Some((c.dataoff as usize, c.datasize as usize))
            }
            CommandVariant::Segment64(s) => {
                seg(
                    img,
                    &s.segname,
                    s.vmaddr,
                    s.vmsize,
                    s.fileoff,
                    s.filesize,
                    s.initprot,
                    &mut text_base,
                );
                sects.extend(raw_sections(bytes, lc.offset, true, s.nsects, le));
            }
            CommandVariant::Segment32(s) => {
                seg(
                    img,
                    &s.segname,
                    u64::from(s.vmaddr),
                    u64::from(s.vmsize),
                    u64::from(s.fileoff),
                    u64::from(s.filesize),
                    s.initprot,
                    &mut text_base,
                );
                sects.extend(raw_sections(bytes, lc.offset, false, s.nsects, le));
            }
            CommandVariant::FunctionStarts(c) => {
                func_starts = Some((c.dataoff as usize, c.datasize as usize))
            }
            CommandVariant::Dysymtab(d) => {
                dysym = Some((d.indirectsymoff as usize, d.nindirectsyms as usize))
            }
            CommandVariant::BuildVersion(b) => {
                img.platform = match b.platform {
                    2 | 3 | 4 | 6 | 7 | 8 | 9 | 10 | 11 | 12 => Platform::Ios,
                    _ => Platform::Macos,
                }
            }
            CommandVariant::VersionMinIphoneos(_) => img.platform = Platform::Ios,
            CommandVariant::EncryptionInfo64(e) => encrypted |= e.cryptid != 0,
            CommandVariant::EncryptionInfo32(e) => encrypted |= e.cryptid != 0,
            _ => {}
        }
    }
    if encrypted {
        img.warnings.push(
            "Mach-O is App Store–encrypted (cryptid != 0); code bytes are not analysable".into(),
        );
    }
    let text_base = text_base.unwrap_or(0);
    img.image_base = text_base;

    for s in &sects {
        let ty = s.flags & 0xff;
        let zerofill = matches!(ty, S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL);
        let file_size = if zerofill { 0 } else { s.size };
        let perms = img.perms(s.addr);
        let ent = if zerofill {
            0.0
        } else {
            bytes
                .get(s.offset as usize..(s.offset as u64).saturating_add(s.size) as usize)
                .map(entropy)
                .unwrap_or(0.0)
        };
        let name = format!("{},{}", s.seg, s.name);
        if s.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0 && s.size > 0 {
            img.code.push(CodeRange {
                start: s.addr,
                end: s.addr.saturating_add(s.size),
                name: name.clone(),
                is_stub: ty == S_SYMBOL_STUBS,
            });
        }
        if s.name.starts_with("__swift5") {
            img.compiler_hints.push("swift".into());
        }
        if s.name.starts_with("__objc_") {
            img.compiler_hints.push("objc".into());
        }
        if s.name.starts_with("__gopclntab") || s.name.starts_with("__go_buildinfo") {
            img.compiler_hints.push("go".into());
        }
        img.sections.push(Section {
            name,
            vaddr: Addr(s.addr),
            vsize: s.size,
            file_offset: u64::from(s.offset),
            file_size,
            perms: perm_string(perms),
            entropy: ent,
        });
    }

    // Symbols.
    let libs: Vec<&str> = m.libs.clone();
    let mut undef_to_import: HashMap<usize, u32> = HashMap::new();
    let mut had_local = false;
    // `nsyms` comes from the file: never iterate more entries than could fit
    // in it (an nlist is at least 12 bytes). A hostile count of ~4 billion
    // otherwise spins for seconds producing out-of-bounds errors.
    let max_syms = bytes.len() / 12 + 1;
    for (idx, item) in m.symbols().enumerate().take(max_syms) {
        let Ok((name, nl)) = item else { continue };
        if nl.n_type & N_STAB != 0 || name.is_empty() {
            continue;
        }
        let t = nl.n_type & N_TYPE;
        if t == N_UNDF && nl.n_type & N_EXT != 0 {
            let ord = ((nl.n_desc >> 8) & 0xff) as usize;
            let lib = if ord > 0 && ord < 0xfe {
                libs.get(ord).map(|s| s.to_string())
            } else {
                None
            };
            undef_to_import.insert(idx, img.imports.len() as u32);
            img.imports.push(Symbol {
                demangled: demangle(name),
                name: name.to_string(),
                addr: Addr(0),
                size: None,
                kind: SymbolKind::Import,
                library: lib,
                source: SymbolSource::ImportTable,
            });
        } else if t == N_SECT {
            let sect_is_code = sects.get(nl.n_sect.wrapping_sub(1)).is_some_and(|s| {
                s.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0
            });
            if nl.n_type & N_EXT == 0 {
                had_local = true;
            }
            if sect_is_code {
                img.function_hints.push(nl.n_value);
            }
            img.symbols.push(Symbol {
                demangled: demangle(name),
                name: name.to_string(),
                addr: Addr(nl.n_value),
                size: None,
                kind: if sect_is_code {
                    SymbolKind::Function
                } else {
                    SymbolKind::Object
                },
                library: None,
                source: SymbolSource::Symtab,
            });
        }
    }
    img.is_stripped = !had_local;
    for s in &img.symbols {
        let n = s.name.as_str();
        if n.contains("rust_begin_unwind") || n.contains("rust_panic") {
            img.compiler_hints.push("rust".into());
            break;
        }
    }

    // Indirect symbol table: stubs and pointer sections → import names.
    if let Some((off, n)) = dysym {
        let read_ind = |i: usize| rd32(bytes, off + i * 4, le);
        for s in &sects {
            let ty = s.flags & 0xff;
            let (step, is_stub) = match ty {
                S_SYMBOL_STUBS if s.reserved2 > 0 => (u64::from(s.reserved2), true),
                S_NON_LAZY_SYMBOL_POINTERS | S_LAZY_SYMBOL_POINTERS => (u64::from(bits / 8), false),
                _ => continue,
            };
            let count = (s.size / step).min(1 << 20) as usize;
            for k in 0..count {
                let ii = s.reserved1 as usize + k;
                if ii >= n {
                    break;
                }
                let Some(sym) = read_ind(ii) else { break };
                if sym & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) != 0 {
                    continue;
                }
                let Some(&imp) = undef_to_import.get(&(sym as usize)) else {
                    continue;
                };
                let va = s.addr + k as u64 * step;
                if is_stub {
                    img.stubs.insert(va, imp);
                    if let Some(i) = img.imports.get_mut(imp as usize) {
                        i.addr = Addr(va);
                    }
                } else {
                    img.import_slots.insert(va, imp);
                    if let Some(i) = img.imports.get_mut(imp as usize)
                        && i.addr.0 == 0
                    {
                        i.addr = Addr(va);
                    }
                }
            }
        }
    }

    // Exports from the export trie (relative to the Mach-O header).
    // Walked by our own bounded, iterative parser: goblin's recursive walker
    // panics on bad re-export ordinals and can overflow the stack on cyclic
    // tries (both found by fuzzing).
    if let Some((off, size)) = export_trie {
        match bytes.get(off..off.saturating_add(size)) {
            Some(trie) => {
                let (exps, truncated) = walk_export_trie(trie);
                if truncated {
                    img.warnings
                        .push("export trie: malformed or truncated, some exports skipped".into());
                }
                for e in exps {
                    let a = if e.absolute {
                        e.address
                    } else {
                        text_base.wrapping_add(e.address)
                    };
                    let is_code = !e.absolute && img.code.iter().any(|c| a >= c.start && a < c.end);
                    if is_code {
                        img.function_hints.push(a);
                    }
                    img.exports.push(Symbol {
                        demangled: demangle(&e.name),
                        name: e.name,
                        addr: Addr(a),
                        size: None,
                        kind: if is_code {
                            SymbolKind::Export
                        } else {
                            SymbolKind::Object
                        },
                        library: None,
                        source: SymbolSource::ExportTable,
                    });
                }
            }
            None => img
                .warnings
                .push("export trie: points outside the file".into()),
        }
    }

    // LC_FUNCTION_STARTS: ULEB128 deltas from the __TEXT segment start.
    if let Some((off, size)) = func_starts
        && let Some(d) = bytes.get(off..off.saturating_add(size))
    {
        let mut p = 0;
        let mut a = text_base;
        let mut starts = Vec::new();
        while p < d.len() {
            match uleb(d, &mut p) {
                Some(0) | None => break,
                Some(delta) => {
                    a = a.wrapping_add(delta);
                    starts.push(a);
                }
            }
        }
        // The linker lists every function, so consecutive starts
        // partition the code: [s_i, s_{i+1}) or to the section end.
        for (i, &s) in starts.iter().enumerate() {
            let sect_end = img
                .code
                .iter()
                .find(|c| s >= c.start && s < c.end)
                .map(|c| c.end)
                .unwrap_or(s);
            let end = starts
                .get(i + 1)
                .copied()
                .filter(|&n| n <= sect_end)
                .unwrap_or(sect_end);
            img.function_ranges.push((s, end));
        }
        img.function_hints.extend(starts);
    }

    // __TEXT,__unwind_info (compact unwind) lists every function that has
    // unwind info — Chromium/Electron strip LC_FUNCTION_STARTS but keep this.
    if func_starts.is_none()
        && let Some(u) = sects
            .iter()
            .find(|s| s.seg == "__TEXT" && s.name == "__unwind_info")
        && let Some(d) =
            bytes.get(u.offset as usize..(u.offset as u64).saturating_add(u.size) as usize)
    {
        // Seeds only: ld folds adjacent functions with identical
        // encodings into one entry, so these are not a partition.
        for off in compact_unwind_starts(d, le) {
            let a = text_base.wrapping_add(off);
            if img.code.iter().any(|c| a >= c.start && a < c.end) {
                img.function_hints.push(a);
            }
        }
    }

    for l in &libs {
        if l.contains("libswiftCore") {
            img.compiler_hints.push("swift".into());
        }
        if l.contains("Electron Framework") {
            img.compiler_hints.push("electron".into());
        }
        if l.contains("FlutterMacOS") || l.contains("Flutter.framework") {
            img.compiler_hints.push("flutter".into());
        }
        if l.contains("hermes") {
            img.compiler_hints.push("react-native".into());
        }
    }
    img.libraries = libs.iter().skip(1).map(|s| s.to_string()).collect();
    if m.entry != 0 {
        img.entry = Some(m.entry);
        img.function_hints.push(m.entry);
    }
    Ok(())
}

/// Function offsets (from the image base) in a compact unwind section.
/// One address-bearing export from the dyld export trie.
pub(crate) struct TrieExport {
    pub name: String,
    pub address: u64,
    pub absolute: bool,
}

const EXPORT_KIND_MASK: u64 = 0x03;
const EXPORT_KIND_ABSOLUTE: u64 = 0x02;
const EXPORT_REEXPORT: u64 = 0x08;
const EXPORT_STUB_AND_RESOLVER: u64 = 0x10;
const TRIE_MAX_EXPORTS: usize = 4_000_000;
const TRIE_MAX_NAME: usize = 4096;

/// Iterative walk of a dyld export trie. Only exports that carry an address
/// are returned (re-exports have none). Every node is visited at most once,
/// so cycles and shared subtrees cannot loop or blow up; names are capped.
/// Returns the exports and whether anything malformed was skipped.
pub(crate) fn walk_export_trie(trie: &[u8]) -> (Vec<TrieExport>, bool) {
    let mut out = Vec::new();
    let mut bad = false;
    let mut visited = vec![false; trie.len()];
    let mut stack: Vec<(usize, Vec<u8>)> = vec![(0, Vec::new())];
    while let Some((node, prefix)) = stack.pop() {
        if out.len() >= TRIE_MAX_EXPORTS {
            bad = true;
            break;
        }
        match visited.get_mut(node) {
            Some(v) if !*v => *v = true,
            _ => {
                bad = true;
                continue;
            }
        }
        let mut p = node;
        let Some(term_size) = uleb(trie, &mut p) else {
            bad = true;
            continue;
        };
        let Some(children_at) = usize::try_from(term_size)
            .ok()
            .and_then(|t| p.checked_add(t))
        else {
            bad = true;
            continue;
        };
        if term_size > 0 {
            let mut q = p;
            match uleb(trie, &mut q) {
                Some(flags) if flags & (EXPORT_REEXPORT | EXPORT_STUB_AND_RESOLVER) == 0 => {
                    if let Some(address) = uleb(trie, &mut q) {
                        out.push(TrieExport {
                            name: String::from_utf8_lossy(&prefix).into_owned(),
                            address,
                            absolute: flags & EXPORT_KIND_MASK == EXPORT_KIND_ABSOLUTE,
                        });
                    } else {
                        bad = true;
                    }
                }
                Some(_) => {}
                None => bad = true,
            }
        }
        let mut c = children_at;
        let Some(&nchildren) = trie.get(c) else {
            if term_size == 0 || children_at != trie.len() {
                bad = true;
            }
            continue;
        };
        c += 1;
        for _ in 0..nchildren {
            let Some(rel) = trie.get(c..) else {
                bad = true;
                break;
            };
            let Some(len) = rel.iter().position(|&b| b == 0) else {
                bad = true;
                break;
            };
            let edge = &rel[..len];
            c += len + 1;
            let Some(child) = uleb(trie, &mut c).and_then(|v| usize::try_from(v).ok()) else {
                bad = true;
                break;
            };
            if prefix.len() + edge.len() > TRIE_MAX_NAME || child >= trie.len() {
                bad = true;
                continue;
            }
            let mut name = prefix.clone();
            name.extend_from_slice(edge);
            stack.push((child, name));
        }
    }
    (out, bad)
}

fn compact_unwind_starts(d: &[u8], le: bool) -> Vec<u64> {
    let mut out = Vec::new();
    if rd32(d, 0, le) != Some(1) {
        return out;
    }
    let (Some(idx_off), Some(idx_n)) = (rd32(d, 20, le), rd32(d, 24, le)) else {
        return out;
    };
    for i in 0..idx_n.min(1 << 20) as usize {
        let e = idx_off as usize + i * 12;
        let (Some(func), Some(page)) = (rd32(d, e, le), rd32(d, e + 4, le)) else {
            break;
        };
        if page == 0 {
            continue; // sentinel entry
        }
        let p = page as usize;
        let rd16 = |o: usize| {
            d.get(o..o + 2).map(|b| {
                if le {
                    u16::from_le_bytes([b[0], b[1]])
                } else {
                    u16::from_be_bytes([b[0], b[1]])
                }
            })
        };
        match rd32(d, p, le) {
            Some(2) => {
                // REGULAR: {functionOffset u32, encoding u32}[]
                let (Some(eo), Some(n)) = (rd16(p + 4), rd16(p + 6)) else {
                    continue;
                };
                for k in 0..n as usize {
                    if let Some(f) = rd32(d, p + eo as usize + k * 8, le) {
                        out.push(u64::from(f));
                    }
                }
            }
            Some(3) => {
                // COMPRESSED: u32 entries, low 24 bits = offset from index func.
                let (Some(eo), Some(n)) = (rd16(p + 4), rd16(p + 6)) else {
                    continue;
                };
                for k in 0..n as usize {
                    if let Some(w) = rd32(d, p + eo as usize + k * 4, le) {
                        out.push(u64::from(func) + u64::from(w & 0x00ff_ffff));
                    }
                }
            }
            _ => {}
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[allow(clippy::too_many_arguments)]
fn seg(
    img: &mut Image,
    name: &[u8; 16],
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    prot: u32,
    text_base: &mut Option<u64>,
) {
    let n = cstr16(name);
    if n == "__TEXT" && text_base.is_none() {
        *text_base = Some(vmaddr);
    }
    if vmsize == 0 && filesize == 0 {
        return;
    }
    let mut p = 0;
    if prot & 1 != 0 {
        p |= PERM_R;
    }
    if prot & 2 != 0 {
        p |= PERM_W;
    }
    if prot & 4 != 0 {
        p |= PERM_X;
    }
    img.segments.push(Segment {
        vaddr: vmaddr,
        vsize: vmsize,
        file_offset: fileoff,
        file_size: filesize,
        perms: p,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uleb_enc(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    #[test]
    fn trie_regular_reexport_and_stub() {
        // root: no terminal, 3 children "_a" -> A, "_r" -> R, "_s" -> S.
        let mut t = vec![0u8, 3];
        let mut fix = Vec::new();
        for e in ["_a", "_r", "_s"] {
            t.extend_from_slice(e.as_bytes());
            t.push(0);
            fix.push(t.len());
            t.push(0); // child offset placeholder (< 128)
        }
        let a = t.len();
        t.extend_from_slice(&[3, 0x00, 0x90, 0x01, 0]); // regular, addr 0x90
        let r = t.len();
        t.extend_from_slice(&[4, 0x08, 0x7f, b'x', 0, 0]); // reexport, bad ordinal 127
        let s = t.len();
        t.extend_from_slice(&[3, 0x10, 0x01, 0x02, 0]); // stub+resolver
        for (i, off) in [a, r, s].into_iter().enumerate() {
            t[fix[i]] = off as u8;
        }
        let (exps, bad) = walk_export_trie(&t);
        assert!(!bad);
        assert_eq!(exps.len(), 1);
        assert_eq!(exps[0].name, "_a");
        assert_eq!(exps[0].address, 0x90);
    }

    #[test]
    fn trie_cycle_terminates() {
        // root -> "x" -> root
        let t = vec![0u8, 1, b'x', 0, 0];
        let (exps, bad) = walk_export_trie(&t);
        assert!(exps.is_empty());
        assert!(bad);
    }

    #[test]
    fn trie_deep_chain_no_stack_overflow() {
        // 200k nodes chained by one-letter edges; names capped, no recursion.
        let mut t = Vec::new();
        let n = 200_000usize;
        let mut offs = Vec::with_capacity(n);
        for _ in 0..n {
            offs.push(t.len());
            t.extend_from_slice(&[0, 1, b'a', 0]);
            t.extend_from_slice(&[0, 0, 0, 0, 0]); // padded uleb slot
        }
        for i in 0..n {
            let slot = offs[i] + 4;
            let next = if i + 1 < n { offs[i + 1] as u64 } else { 0 };
            let mut enc = Vec::new();
            uleb_enc(next, &mut enc);
            // pad to 5 bytes with continuation bits
            while enc.len() < 5 {
                let l = enc.len();
                enc[l - 1] |= 0x80;
                enc.push(0);
            }
            t[slot..slot + 5].copy_from_slice(&enc);
        }
        let (exps, bad) = walk_export_trie(&t);
        assert!(exps.is_empty());
        assert!(bad);
    }

    /// Our walker must agree with goblin on well-formed system binaries.
    #[test]
    fn trie_matches_goblin_on_system_binaries() {
        let mut checked = 0;
        let extra = std::env::var("DRISHTI_TRIE_EXTRA").unwrap_or_default();
        let paths = ["/bin/ls", "/bin/zsh", "/usr/bin/ssh", "/usr/bin/curl"]
            .into_iter()
            .chain(extra.split(':').filter(|s| !s.is_empty()));
        for p in paths {
            let Ok(data) = std::fs::read(p) else { continue };
            let ranges: Vec<(usize, usize)> = match goblin::Object::parse(&data) {
                Ok(goblin::Object::Mach(goblin::mach::Mach::Fat(fat))) => fat
                    .iter_arches()
                    .flatten()
                    .map(|a| (a.offset as usize, (a.offset + a.size) as usize))
                    .collect(),
                Ok(goblin::Object::Mach(goblin::mach::Mach::Binary(_))) => vec![(0, data.len())],
                _ => continue,
            };
            for (lo, hi) in ranges {
                let Some(slice) = data.get(lo..hi) else {
                    continue;
                };
                let Ok(m) = MachO::parse(slice, 0) else {
                    continue;
                };
                let Ok(g) = m.exports() else { continue };
                let mut want: Vec<(String, u64)> = g
                    .into_iter()
                    .filter_map(|e| match e.info {
                        goblin::mach::exports::ExportInfo::Regular { address, .. } => {
                            Some((e.name, address))
                        }
                        _ => None,
                    })
                    .collect();
                let mut trie = None;
                for lc in &m.load_commands {
                    match &lc.command {
                        CommandVariant::DyldInfo(d) | CommandVariant::DyldInfoOnly(d) => {
                            trie = Some((d.export_off as usize, d.export_size as usize))
                        }
                        CommandVariant::DyldExportsTrie(c) => {
                            trie = Some((c.dataoff as usize, c.datasize as usize))
                        }
                        _ => {}
                    }
                }
                let Some((o, s)) = trie else { continue };
                let (ours, bad) = walk_export_trie(&slice[o..o + s]);
                assert!(!bad, "{p}");
                let mut got: Vec<(String, u64)> =
                    ours.into_iter().map(|e| (e.name, e.address)).collect();
                want.sort();
                got.sort();
                assert_eq!(got, want, "{p}");
                checked += 1;
            }
        }
        assert!(checked > 0 || !cfg!(target_os = "macos"));
    }
}
