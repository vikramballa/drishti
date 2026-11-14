//! PE32 / PE32+ loader (Windows, .NET headers).

use crate::LoadError;
use crate::image::*;
use crate::util::{demangle, entropy};
use drishti_model::{
    Addr, Arch, Endian, Format, Platform, Section, Symbol, SymbolKind, SymbolSource,
};
use goblin::pe::PE;

const IMAGE_SCN_CNT_CODE: u32 = 0x20;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

pub(crate) fn load(img: &mut Image, dotnet: bool) -> Result<(), LoadError> {
    let blob = img.blob.clone();
    let bytes: &[u8] = blob
        .as_ref()
        .as_ref()
        .get(img.slice_offset..img.slice_offset + img.slice_len)
        .unwrap_or(&[]);
    let pe = PE::parse(bytes).map_err(|e| LoadError::Malformed(e.to_string()))?;
    let base = pe.image_base;
    let arch = match pe.header.coff_header.machine {
        0x14c => Arch::X86,
        0x8664 => Arch::X86_64,
        0xaa64 => Arch::Aarch64,
        0x1c0 | 0x1c4 => Arch::Arm,
        _ => Arch::Unknown,
    };
    img.arch = arch;
    img.bits = if pe.is_64 { 64 } else { 32 };
    img.endian = Endian::Little;
    img.platform = if dotnet {
        Platform::Dotnet
    } else {
        Platform::Windows
    };
    img.format = if dotnet { Format::PeDotnet } else { Format::Pe };
    img.image_base = base;

    // Headers are mapped at the image base.
    let hdr_size = pe
        .header
        .optional_header
        .map(|o| u64::from(o.windows_fields.size_of_headers))
        .unwrap_or(0x400)
        .min(bytes.len() as u64);
    img.segments.push(Segment {
        vaddr: base,
        vsize: hdr_size.max(0x1000),
        file_offset: 0,
        file_size: hdr_size,
        perms: PERM_R,
    });

    for s in &pe.sections {
        let name = s.name().map(str::to_string).unwrap_or_else(|_| {
            String::from_utf8_lossy(&s.name)
                .trim_end_matches('\0')
                .to_string()
        });
        let va = base.wrapping_add(u64::from(s.virtual_address));
        let vsize = u64::from(s.virtual_size.max(s.size_of_raw_data));
        let fsize = u64::from(s.size_of_raw_data.min(if s.virtual_size == 0 {
            s.size_of_raw_data
        } else {
            s.virtual_size
        }));
        let foff = u64::from(s.pointer_to_raw_data);
        let fsize = if foff >= bytes.len() as u64 {
            0
        } else {
            fsize.min(bytes.len() as u64 - foff)
        };
        let c = s.characteristics;
        let mut p = 0;
        if c & IMAGE_SCN_MEM_READ != 0 {
            p |= PERM_R;
        }
        if c & IMAGE_SCN_MEM_WRITE != 0 {
            p |= PERM_W;
        }
        if c & IMAGE_SCN_MEM_EXECUTE != 0 {
            p |= PERM_X;
        }
        let ent = bytes
            .get(foff as usize..(foff + fsize) as usize)
            .map(entropy)
            .unwrap_or(0.0);
        if c & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0 && vsize > 0 {
            img.code.push(CodeRange {
                start: va,
                end: va.saturating_add(vsize),
                name: name.clone(),
                is_stub: false,
            });
        }
        img.segments.push(Segment {
            vaddr: va,
            vsize,
            file_offset: foff,
            file_size: fsize,
            perms: p,
        });
        img.sections.push(Section {
            name,
            vaddr: Addr(va),
            vsize,
            file_offset: foff,
            file_size: fsize,
            perms: perm_string(p),
            entropy: ent,
        });
    }

    if pe.entry != 0 {
        let e = base.wrapping_add(u64::from(pe.entry));
        img.entry = Some(e);
        img.function_hints.push(e);
    }

    for imp in &pe.imports {
        // goblin: `offset` is the IAT slot RVA; `rva` points at the hint/name entry.
        let slot = base.wrapping_add(imp.offset as u64);
        let name = if imp.name.is_empty() {
            format!("ord_{}", imp.ordinal)
        } else {
            imp.name.to_string()
        };
        img.import_slots.insert(slot, img.imports.len() as u32);
        img.imports.push(Symbol {
            demangled: demangle(&name),
            name,
            addr: Addr(slot),
            size: None,
            kind: SymbolKind::Import,
            library: Some(imp.dll.to_string()),
            source: SymbolSource::ImportTable,
        });
    }
    for ex in &pe.exports {
        if ex.reexport.is_some() {
            continue;
        }
        let a = base.wrapping_add(ex.rva as u64);
        let name = ex
            .name
            .map(str::to_string)
            .unwrap_or_else(|| format!("export_{:x}", ex.rva));
        let is_code = img.code.iter().any(|c| a >= c.start && a < c.end);
        if is_code {
            img.function_hints.push(a);
        }
        img.exports.push(Symbol {
            demangled: demangle(&name),
            name,
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
    img.libraries = pe.libraries.iter().map(|s| s.to_string()).collect();

    // .pdata: every non-leaf function on x64/ARM64 has an entry.
    if let Some(ex) = &pe.exception_data {
        if arch == Arch::Aarch64 {
            // 8-byte entries: start + packed unwind data (with the function
            // length) or an RVA of full .xdata whose header holds the length.
            for f in ex.functions_arm64().flatten().take(1_000_000) {
                if f.flag() == goblin::pe::exception::ARM64_PDATA_PACKED_UNWIND_FRAGMENT {
                    continue; // continuation of a long function, not a start
                }
                let b = base.wrapping_add(u64::from(f.begin_address));
                let len = if f.is_packed() {
                    u64::from(f.function_length())
                } else {
                    img.read(base.wrapping_add(u64::from(f.unwind_data_rva())), 4)
                        .and_then(|h| h.get(..4))
                        .map(|h| {
                            u64::from(u32::from_le_bytes([h[0], h[1], h[2], h[3]]) & 0x3ffff) * 4
                        })
                        .unwrap_or(0)
                };
                img.function_hints.push(b);
                if len > 0 {
                    img.function_ranges.push((b, b.wrapping_add(len)));
                }
            }
        } else {
            for f in ex.functions().flatten().take(1_000_000) {
                let b = base.wrapping_add(u64::from(f.begin_address));
                img.function_hints.push(b);
                img.function_ranges
                    .push((b, base.wrapping_add(u64::from(f.end_address))));
            }
        }
    }
    if let Some(tls) = &pe.tls_data {
        for &cb in &tls.callbacks {
            img.function_hints.push(cb);
        }
    }
    if pe.header.rich_header.is_some() {
        img.compiler_hints.push("msvc".into());
    }
    if img
        .sections
        .iter()
        .any(|s| s.name.starts_with(".gopclnt") || s.name == ".symtab")
        && img
            .imports
            .iter()
            .any(|i| i.name == "WSAGetOverlappedResult")
    {
        img.compiler_hints.push("go".into());
    }
    if dotnet {
        img.compiler_hints.push("dotnet".into());
    }
    // PE rarely carries symbols; treat "no exports, no symbols" as stripped.
    img.is_stripped = true;
    Ok(())
}
