//! Drishti loader: format detection, ELF/PE/Mach-O loading, container
//! listing, strings and triage heuristics (spec §7.1, §7.2).
//!
//! Design notes:
//! - Input is memory-mapped (`Blob`), so a 1 GB binary costs page cache, not heap.
//! - Nothing here executes input. Every offset is bounds-checked; parse
//!   failures become `LoadError`/warnings, never panics.
#![deny(unsafe_code)]

mod blob;
pub mod detect;
mod ehframe;
mod elf;
pub mod image;
pub mod insights;
mod macho;
pub mod pdf;
mod pe;
pub mod triage;
pub mod util;

pub use blob::Blob;
pub use detect::{Detected, detect};
pub use image::{CodeRange, Image, Segment};

use drishti_model::{Arch, ChildFile, Container, Endian, FileInfo, Format, Platform, StringRef};
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed binary: {0}")]
    Malformed(String),
    #[error("format {0:?} has no native code loader")]
    Unsupported(Format),
    #[error("fat binary has no slice for the requested architecture")]
    NoSlice,
}

/// Open a file (memory-mapped).
pub fn open(path: &Path) -> Result<Arc<Blob>, LoadError> {
    Ok(Arc::new(Blob::open(path)?))
}

/// One architecture slice inside a fat Mach-O.
#[derive(Debug, Clone)]
pub struct FatSlice {
    pub arch: Arch,
    pub offset: usize,
    pub size: usize,
}

pub fn fat_slices(bytes: &[u8]) -> Vec<FatSlice> {
    let Ok(goblin::mach::Mach::Fat(fat)) = goblin::mach::Mach::parse(bytes) else {
        return Vec::new();
    };
    let Ok(arches) = fat.arches() else {
        return Vec::new();
    };
    arches
        .iter()
        .filter_map(|a| {
            let (arch, _) = macho::cpu_arch(a.cputype);
            let (o, s) = (a.offset as usize, a.size as usize);
            (o.checked_add(s)? <= bytes.len()).then_some(FatSlice {
                arch,
                offset: o,
                size: s,
            })
        })
        .collect()
}

/// Host architecture, used to pick the default slice of universal binaries.
pub fn host_arch() -> Arch {
    if cfg!(target_arch = "aarch64") {
        Arch::Aarch64
    } else {
        Arch::X86_64
    }
}

/// Load the native image. For fat Mach-O, `want` selects the slice (default:
/// host architecture, else the first slice).
pub fn load_image(blob: Arc<Blob>, want: Option<Arch>) -> Result<Image, LoadError> {
    let bytes = blob.as_ref().as_ref();
    let det = detect(bytes);
    let (slice_offset, slice_len, format) = match det.format {
        Format::MachoFat => {
            let slices = fat_slices(bytes);
            let pick = want
                .and_then(|w| slices.iter().find(|s| s.arch == w))
                .or_else(|| {
                    if want.is_some() {
                        None
                    } else {
                        slices
                            .iter()
                            .find(|s| s.arch == host_arch())
                            .or(slices.first())
                    }
                })
                .ok_or(LoadError::NoSlice)?;
            (pick.offset, pick.size, Format::Macho)
        }
        f => (0, bytes.len(), f),
    };
    let mut img = Image {
        blob: blob.clone(),
        slice_offset,
        slice_len,
        format,
        arch: Arch::Unknown,
        bits: 64,
        endian: Endian::Little,
        platform: Platform::Unknown,
        entry: None,
        image_base: 0,
        segments: Vec::new(),
        sections: Vec::new(),
        code: Vec::new(),
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        libraries: Vec::new(),
        function_hints: Vec::new(),
        function_ranges: Vec::new(),
        import_slots: Default::default(),
        stubs: Default::default(),
        is_stripped: false,
        compiler_hints: Vec::new(),
        warnings: Vec::new(),
    };
    match format {
        Format::Elf => elf::load(&mut img)?,
        Format::Pe => pe::load(&mut img, false)?,
        Format::PeDotnet => pe::load(&mut img, true)?,
        Format::Macho => macho::load(&mut img)?,
        f => return Err(LoadError::Unsupported(f)),
    }
    img.finish();
    Ok(img)
}

/// Build the `FileInfo` triage record. `image` is the loaded native image
/// when the format has one.
pub fn file_info(blob: &Blob, file_name: &str, image: Option<&Image>) -> FileInfo {
    let bytes = blob.as_ref();
    let det = detect(bytes);
    let mut fi = FileInfo {
        sha256: util::sha256_hex(bytes),
        md5: util::md5_hex(bytes),
        size: bytes.len() as u64,
        file_name: file_name.to_string(),
        format: det.format,
        container: None,
        arch: Arch::Unknown,
        bits: None,
        endian: None,
        platform: Platform::Unknown,
        entry_point: None,
        is_stripped: None,
        is_packed_suspected: None,
        entropy: util::entropy(bytes),
        compiler_hints: Vec::new(),
        libraries: Vec::new(),
        children: Vec::new(),
    };
    match det.format {
        Format::Dex | Format::Apk => {
            fi.arch = Arch::Dalvik;
            fi.platform = Platform::Android;
        }
        Format::JavaClass | Format::Jar => {
            fi.arch = Arch::Jvm;
            fi.platform = Platform::Java;
        }
        Format::Wasm => {
            fi.arch = Arch::Wasm;
            fi.platform = Platform::Web;
        }
        Format::Ipa => fi.platform = Platform::Ios,
        Format::Asar => {
            fi.platform = Platform::Web;
            fi.compiler_hints.push("electron".into());
        }
        _ => {}
    }
    if det.format == Format::MachoFat {
        fi.container = Some(Container::FatMacho);
        fi.children = fat_slices(bytes)
            .into_iter()
            .map(|s| ChildFile {
                path: format!("slice:{:?}", s.arch).to_lowercase(),
                sha256: bytes
                    .get(s.offset..s.offset.saturating_add(s.size))
                    .map(util::sha256_hex)
                    .unwrap_or_default(),
                format: Format::Macho,
                size: s.size as u64,
                arch: Some(s.arch),
            })
            .collect();
    }
    if matches!(
        det.format,
        Format::Apk | Format::Ipa | Format::Jar | Format::Zip | Format::Ooxml
    ) {
        fi.container = Some(Container::Zip);
        fi.children = zip_children(bytes, 5000);
    }
    if det.format == Format::Asar {
        fi.children = asar_children(bytes, 20000);
    }
    if let Some(img) = image {
        fi.arch = img.arch;
        fi.bits = Some(img.bits);
        fi.endian = Some(img.endian);
        fi.platform = img.platform;
        fi.entry_point = img.entry.map(drishti_model::Addr);
        fi.is_stripped = Some(img.is_stripped);
        fi.is_packed_suspected = Some(triage::packed_suspected(img));
        fi.compiler_hints = img.compiler_hints.clone();
        fi.libraries = img.libraries.clone();
    }
    fi
}

/// List ZIP entries and classify each by its first bytes. Only a 64-byte
/// prefix is decompressed per entry, so zip bombs cannot exhaust memory.
pub fn zip_children(bytes: &[u8], limit: usize) -> Vec<ChildFile> {
    let Ok(mut z) = zip::ZipArchive::new(Cursor::new(bytes)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for i in 0..z.len().min(limit) {
        let Ok(mut f) = z.by_index(i) else { continue };
        if f.is_dir() {
            continue;
        }
        // Path traversal guard: entries that escape the root are listed as-is
        // but never extracted.
        let Ok(name) = f.name().map(|n| n.to_string()) else {
            continue;
        };
        let size = f.size();
        let mut head = [0u8; 64];
        let mut n = 0;
        while n < head.len() {
            match f.read(&mut head[n..]) {
                Ok(0) | Err(_) => break,
                Ok(k) => n += k,
            }
        }
        let format = match detect(&head[..n]).format {
            Format::Unknown if name.ends_with(".so") => Format::Elf,
            f => f,
        };
        out.push(ChildFile {
            path: name,
            sha256: String::new(),
            format,
            size,
            arch: None,
        });
    }
    out
}

/// List files inside an Electron `app.asar` archive.
pub fn asar_children(bytes: &[u8], limit: usize) -> Vec<ChildFile> {
    let rd = |o: usize| {
        bytes
            .get(o..o + 4)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
    };
    let (Some(hsize), Some(jlen)) = (rd(4), rd(12)) else {
        return Vec::new();
    };
    let Some(json) = bytes.get(16..16usize.saturating_add(jlen)) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let data_base = 8 + hsize;
    let mut out = Vec::new();
    fn walk(
        v: &serde_json::Value,
        prefix: &str,
        bytes: &[u8],
        base: usize,
        out: &mut Vec<ChildFile>,
        limit: usize,
    ) {
        let Some(files) = v.get("files").and_then(|f| f.as_object()) else {
            return;
        };
        for (name, e) in files {
            if out.len() >= limit {
                return;
            }
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if e.get("files").is_some() {
                walk(e, &path, bytes, base, out, limit);
                continue;
            }
            let size = e.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
            let off = e
                .get("offset")
                .and_then(|s| s.as_str())
                .and_then(|s| s.parse::<usize>().ok());
            let unpacked = e.get("unpacked").and_then(|u| u.as_bool()).unwrap_or(false);
            let format = match off {
                Some(o) if !unpacked => {
                    let s = base.saturating_add(o);
                    bytes
                        .get(s..s.saturating_add((size as usize).min(64)))
                        .map(|h| detect(h).format)
                        .unwrap_or(Format::Unknown)
                }
                _ => Format::Unknown,
            };
            out.push(ChildFile {
                path,
                sha256: String::new(),
                format,
                size,
                arch: None,
            });
        }
    }
    walk(&v, "", bytes, data_base, &mut out, limit);
    out
}

/// Read one file stored inside an Electron `app.asar` archive. Returns
/// `None` for unknown paths, files kept outside the archive (`unpacked`)
/// and entries whose offset/size point outside the file.
pub fn asar_read(bytes: &[u8], path: &str) -> Option<Vec<u8>> {
    let rd = |o: usize| {
        bytes
            .get(o..o.checked_add(4)?)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
    };
    let (hsize, jlen) = (rd(4)?, rd(12)?);
    let json = bytes.get(16..16usize.checked_add(jlen)?)?;
    let v: serde_json::Value = serde_json::from_slice(json).ok()?;
    let mut cur = &v;
    for part in path.split('/').filter(|p| !p.is_empty()) {
        if part == ".." || part == "." {
            return None;
        }
        cur = cur.get("files")?.get(part)?;
    }
    if cur.get("files").is_some() || cur.get("unpacked").and_then(|u| u.as_bool()) == Some(true) {
        return None;
    }
    let size = usize::try_from(cur.get("size")?.as_u64()?).ok()?;
    let off: usize = cur.get("offset")?.as_str()?.parse().ok()?;
    let start = 8usize.checked_add(hsize)?.checked_add(off)?;
    bytes
        .get(start..start.checked_add(size)?)
        .map(<[u8]>::to_vec)
}

/// Strings in mapped, non-code sections (or the whole file for non-native
/// formats), with virtual addresses where possible.
pub fn strings(blob: &Blob, image: Option<&Image>, min: usize, limit: usize) -> Vec<StringRef> {
    let mut raw = Vec::new();
    match image {
        Some(img) => {
            let bytes = img.bytes();
            for s in &img.sections {
                if s.file_size == 0 || (s.vaddr.0 == 0 && img.format != Format::Pe) {
                    continue;
                }
                if img.is_code(s.vaddr.0) && !s.name.contains("cstring") {
                    continue;
                }
                let (o, n) = (s.file_offset as usize, s.file_size as usize);
                if let Some(d) = bytes.get(o..o.saturating_add(n)) {
                    util::extract_strings(d, s.file_offset, min, limit, &mut raw);
                }
            }
            raw.sort_by_key(|r| r.offset);
            raw.dedup_by_key(|r| r.offset);
            raw.into_iter()
                .map(|r| StringRef {
                    addr: drishti_model::Addr(img.offset_to_va(r.offset).unwrap_or(r.offset)),
                    value: r.value,
                    encoding: r.encoding,
                    xrefs: Vec::new(),
                })
                .collect()
        }
        None => {
            util::extract_strings(blob.as_ref(), 0, min, limit, &mut raw);
            raw.sort_by_key(|r| r.offset);
            raw.into_iter()
                .map(|r| StringRef {
                    addr: drishti_model::Addr(r.offset),
                    value: r.value,
                    encoding: r.encoding,
                    xrefs: Vec::new(),
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod asar_tests {
    /// Build a minimal asar: pickle header + JSON table + file data.
    fn build(json: &str, data: &[u8]) -> Vec<u8> {
        let jlen = json.len();
        let padded = (jlen + 3) & !3;
        let hsize = 8 + padded;
        let mut b = Vec::new();
        b.extend_from_slice(&4u32.to_le_bytes());
        b.extend_from_slice(&(hsize as u32).to_le_bytes());
        b.extend_from_slice(&((4 + padded) as u32).to_le_bytes());
        b.extend_from_slice(&(jlen as u32).to_le_bytes());
        b.extend_from_slice(json.as_bytes());
        b.resize(8 + hsize, 0);
        b.extend_from_slice(data);
        b
    }

    #[test]
    fn read_files() {
        let b = build(
            r#"{"files":{"main.js":{"size":5,"offset":"0"},"lib":{"files":{"a.js":{"size":3,"offset":"5"}}},"x.node":{"size":9,"unpacked":true},"bad":{"size":99,"offset":"0"}}}"#,
            b"hellobye",
        );
        assert_eq!(super::detect(&b).format, drishti_model::Format::Asar);
        assert_eq!(
            super::asar_read(&b, "main.js").as_deref(),
            Some(&b"hello"[..])
        );
        assert_eq!(
            super::asar_read(&b, "lib/a.js").as_deref(),
            Some(&b"bye"[..])
        );
        assert_eq!(super::asar_read(&b, "x.node"), None);
        assert_eq!(super::asar_read(&b, "bad"), None);
        assert_eq!(super::asar_read(&b, "lib"), None);
        assert_eq!(super::asar_read(&b, "lib/../main.js"), None);
        assert_eq!(super::asar_children(&b, 10).len(), 4);
    }
}
