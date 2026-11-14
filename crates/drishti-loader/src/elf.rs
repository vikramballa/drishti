//! ELF loader (Linux, Android, embedded).

use crate::LoadError;
use crate::image::*;
use crate::util::{demangle, entropy};
use drishti_model::{
    Addr, Arch, Endian, Format, Platform, Section, Symbol, SymbolKind, SymbolSource,
};
use goblin::elf::{Elf, header, program_header, section_header, sym};
use std::collections::HashMap;

pub(crate) fn load(img: &mut Image) -> Result<(), LoadError> {
    let blob = img.blob.clone();
    let bytes: &[u8] = blob
        .as_ref()
        .as_ref()
        .get(img.slice_offset..img.slice_offset + img.slice_len)
        .unwrap_or(&[]);
    let elf = Elf::parse(bytes).map_err(|e| LoadError::Malformed(e.to_string()))?;
    let bits = if elf.is_64 { 64 } else { 32 };
    let arch = match elf.header.e_machine {
        header::EM_386 => Arch::X86,
        header::EM_X86_64 => Arch::X86_64,
        header::EM_ARM => Arch::Arm,
        header::EM_AARCH64 => Arch::Aarch64,
        header::EM_MIPS => {
            if elf.is_64 {
                Arch::Mips64
            } else {
                Arch::Mips
            }
        }
        header::EM_RISCV => Arch::Riscv64,
        header::EM_PPC | header::EM_PPC64 => Arch::Ppc,
        _ => Arch::Unknown,
    };
    let interp = elf.interpreter.unwrap_or("");
    let platform = if interp.contains("/system/bin/linker") || elf.libraries.contains(&"liblog.so")
    {
        Platform::Android
    } else if interp.is_empty() && elf.dynamic.is_none() && matches!(arch, Arch::Arm | Arch::Mips) {
        Platform::Embedded
    } else {
        Platform::Linux
    };

    let thumb_mask = if arch == Arch::Arm { !1u64 } else { !0u64 };
    let is_rel = elf.header.e_type == header::ET_REL;

    let mut segments = Vec::new();
    for ph in &elf.program_headers {
        if ph.p_type != program_header::PT_LOAD {
            continue;
        }
        let mut p = 0;
        if ph.p_flags & program_header::PF_R != 0 {
            p |= PERM_R;
        }
        if ph.p_flags & program_header::PF_W != 0 {
            p |= PERM_W;
        }
        if ph.p_flags & program_header::PF_X != 0 {
            p |= PERM_X;
        }
        segments.push(Segment {
            vaddr: ph.p_vaddr,
            vsize: ph.p_memsz,
            file_offset: ph.p_offset,
            file_size: ph.p_filesz,
            perms: p,
        });
    }

    // Relocatable objects have no segments; lay out alloc sections ourselves.
    let mut sec_base: Vec<u64> = vec![0; elf.section_headers.len()];
    if segments.is_empty() {
        let mut cursor = 0x10000u64;
        for (i, sh) in elf.section_headers.iter().enumerate() {
            if sh.sh_flags & u64::from(section_header::SHF_ALLOC) == 0 || sh.sh_size == 0 {
                continue;
            }
            let align = sh.sh_addralign.max(1);
            let base = if sh.sh_addr != 0 {
                sh.sh_addr
            } else {
                cursor.div_ceil(align) * align
            };
            sec_base[i] = if is_rel { base } else { 0 };
            let file_size = if sh.sh_type == section_header::SHT_NOBITS {
                0
            } else {
                sh.sh_size
            };
            segments.push(Segment {
                vaddr: base,
                vsize: sh.sh_size,
                file_offset: sh.sh_offset,
                file_size,
                perms: sh_perms(sh.sh_flags),
            });
            cursor = base.saturating_add(sh.sh_size);
        }
    }
    img.segments = segments;

    let mut eh_frame = None;
    let mut init_arrays = Vec::new();
    for (i, sh) in elf.section_headers.iter().enumerate() {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        if sh.sh_type == section_header::SHT_NULL {
            continue;
        }
        let alloc = sh.sh_flags & u64::from(section_header::SHF_ALLOC) != 0;
        let vaddr = if is_rel { sec_base[i] } else { sh.sh_addr };
        let file_size = if sh.sh_type == section_header::SHT_NOBITS {
            0
        } else {
            sh.sh_size
        };
        let ent = bytes
            .get(sh.sh_offset as usize..(sh.sh_offset.saturating_add(file_size)) as usize)
            .map(entropy)
            .unwrap_or(0.0);
        if alloc && sh.sh_flags & u64::from(section_header::SHF_EXECINSTR) != 0 && sh.sh_size > 0 {
            img.code.push(CodeRange {
                start: vaddr,
                end: vaddr.saturating_add(sh.sh_size),
                name: name.clone(),
                is_stub: name.starts_with(".plt"),
            });
        }
        if alloc && name == ".eh_frame" {
            eh_frame = Some((vaddr, sh.sh_offset, file_size));
        }
        if alloc
            && (sh.sh_type == section_header::SHT_INIT_ARRAY
                || sh.sh_type == section_header::SHT_FINI_ARRAY)
        {
            init_arrays.push((vaddr, sh.sh_size));
        }
        if name == ".comment"
            && let Some(c) =
                bytes.get(sh.sh_offset as usize..(sh.sh_offset.saturating_add(file_size)) as usize)
        {
            let s = String::from_utf8_lossy(c);
            if s.contains("GCC:") {
                img.compiler_hints.push("gcc".into());
            }
            if s.contains("clang") {
                img.compiler_hints.push("clang".into());
            }
            if s.contains("rustc") {
                img.compiler_hints.push("rust".into());
            }
        }
        if name == ".gopclntab" || name == ".go.buildinfo" || name == ".note.go.buildid" {
            img.compiler_hints.push("go".into());
        }
        if name.is_empty() && !alloc {
            continue;
        }
        img.sections.push(Section {
            name,
            vaddr: Addr(vaddr),
            vsize: sh.sh_size,
            file_offset: sh.sh_offset,
            file_size,
            perms: perm_string(sh_perms(sh.sh_flags)),
            entropy: ent,
        });
    }

    // Symbols.
    let push_syms = |img: &mut Image,
                     tab: &sym::Symtab<'_>,
                     strtab: &goblin::strtab::Strtab<'_>,
                     src: SymbolSource| {
        for s in tab.iter() {
            if s.st_shndx == 0 || s.st_name == 0 {
                continue;
            }
            let ty = s.st_type();
            if ty != sym::STT_FUNC && ty != sym::STT_OBJECT && ty != sym::STT_GNU_IFUNC {
                continue;
            }
            let Some(name) = strtab.get_at(s.st_name) else {
                continue;
            };
            let base = sec_base.get(s.st_shndx).copied().unwrap_or(0);
            let addr = base.wrapping_add(s.st_value) & thumb_mask;
            let kind = if ty == sym::STT_OBJECT {
                SymbolKind::Object
            } else {
                SymbolKind::Function
            };
            if kind == SymbolKind::Function {
                img.function_hints.push(addr);
            }
            img.symbols.push(Symbol {
                name: name.to_string(),
                demangled: demangle(name),
                addr: Addr(addr),
                size: (s.st_size > 0).then_some(s.st_size),
                kind,
                library: None,
                source: src,
            });
        }
    };
    push_syms(img, &elf.syms, &elf.strtab, SymbolSource::Symtab);
    let had_symtab = !img.symbols.is_empty();
    push_syms(img, &elf.dynsyms, &elf.dynstrtab, SymbolSource::Dynsym);
    img.is_stripped = !had_symtab;

    // Exports: defined global/weak dynamic symbols.
    for s in elf.dynsyms.iter() {
        let bind = s.st_bind();
        if s.st_shndx == 0 || s.st_name == 0 || (bind != sym::STB_GLOBAL && bind != sym::STB_WEAK) {
            continue;
        }
        let Some(name) = elf.dynstrtab.get_at(s.st_name) else {
            continue;
        };
        let kind = if s.st_type() == sym::STT_OBJECT {
            SymbolKind::Object
        } else {
            SymbolKind::Export
        };
        img.exports.push(Symbol {
            name: name.to_string(),
            demangled: demangle(name),
            addr: Addr(s.st_value & thumb_mask),
            size: (s.st_size > 0).then_some(s.st_size),
            kind,
            library: None,
            source: SymbolSource::ExportTable,
        });
    }

    // Imports: undefined dynamic symbols, located at their relocation slots.
    let mut import_index: HashMap<usize, u32> = HashMap::new();
    for (i, s) in elf.dynsyms.iter().enumerate() {
        if s.st_shndx != 0 || s.st_name == 0 {
            continue;
        }
        let Some(name) = elf.dynstrtab.get_at(s.st_name) else {
            continue;
        };
        import_index.insert(i, img.imports.len() as u32);
        img.imports.push(Symbol {
            name: name.to_string(),
            demangled: demangle(name),
            addr: Addr(0),
            size: None,
            kind: SymbolKind::Import,
            library: None,
            source: SymbolSource::ImportTable,
        });
    }
    let relocs = elf
        .pltrelocs
        .iter()
        .chain(elf.dynrelas.iter())
        .chain(elf.dynrels.iter());
    let in_init = |off: u64| init_arrays.iter().any(|&(a, sz)| off >= a && off < a + sz);
    for r in relocs {
        if let Some(&idx) = import_index.get(&r.r_sym) {
            img.import_slots.insert(r.r_offset, idx);
            if let Some(imp) = img.imports.get_mut(idx as usize)
                && imp.addr.0 == 0
            {
                imp.addr = Addr(r.r_offset);
            }
        } else if r.r_sym == 0
            && in_init(r.r_offset)
            && let Some(a) = r.r_addend
        {
            img.function_hints.push(a as u64 & thumb_mask);
        }
    }
    img.libraries = elf.libraries.iter().map(|s| s.to_string()).collect();

    img.arch = arch;
    img.bits = bits;
    img.endian = if elf.little_endian {
        Endian::Little
    } else {
        Endian::Big
    };
    img.platform = platform;
    img.format = Format::Elf;
    img.image_base = img.segments.iter().map(|s| s.vaddr).min().unwrap_or(0);
    if elf.entry != 0 {
        img.entry = Some(elf.entry & thumb_mask);
        img.function_hints.push(elf.entry & thumb_mask);
    }
    drop(elf);

    // init/fini array pointers stored in-file (non-PIE).
    for (a, sz) in init_arrays {
        let step = u64::from(bits / 8);
        let mut p = a;
        while p + step <= a + sz {
            if let Some(v) = img.read_ptr(p)
                && v != 0
                && v != u64::MAX
            {
                img.function_hints.push(v & thumb_mask);
            }
            p += step;
        }
    }
    if let Some((va, off, size)) = eh_frame
        && img.endian == Endian::Little
        && let Some(d) = bytes.get(off as usize..off.saturating_add(size) as usize)
    {
        let ranges: Vec<(u64, u64)> = crate::ehframe::fde_ranges(d, va, bits == 64)
            .into_iter()
            .filter(|a| img.is_code(a.0))
            .collect();
        img.function_hints.extend(ranges.iter().map(|r| r.0));
        img.function_ranges
            .extend(ranges.iter().map(|&(s, l)| (s, s.saturating_add(l))));
    }
    Ok(())
}

fn sh_perms(flags: u64) -> u8 {
    let mut p = 0;
    if flags & u64::from(section_header::SHF_ALLOC) != 0 {
        p |= PERM_R;
    }
    if flags & u64::from(section_header::SHF_WRITE) != 0 {
        p |= PERM_W;
    }
    if flags & u64::from(section_header::SHF_EXECINSTR) != 0 {
        p |= PERM_X;
    }
    p
}
