//! The loaded program image: memory map, symbols, imports and analysis hints.

use crate::blob::Blob;
use drishti_model::{Arch, Endian, Format, Platform, Section, Symbol};
use std::collections::HashMap;
use std::sync::Arc;

pub const PERM_R: u8 = 1;
pub const PERM_W: u8 = 2;
pub const PERM_X: u8 = 4;

pub fn perm_string(p: u8) -> String {
    let mut s = String::with_capacity(3);
    s.push(if p & PERM_R != 0 { 'r' } else { '-' });
    s.push(if p & PERM_W != 0 { 'w' } else { '-' });
    s.push(if p & PERM_X != 0 { 'x' } else { '-' });
    s
}

/// One mapped region of the virtual address space.
#[derive(Debug, Clone)]
pub struct Segment {
    pub vaddr: u64,
    pub vsize: u64,
    /// Offset relative to the image slice start.
    pub file_offset: u64,
    pub file_size: u64,
    pub perms: u8,
}

/// An executable section worth disassembling.
#[derive(Debug, Clone)]
pub struct CodeRange {
    pub start: u64,
    pub end: u64,
    pub name: String,
    /// Import stubs / PLT: do not gap-scan, only follow calls into it.
    pub is_stub: bool,
}

/// A program loaded from ELF, PE or Mach-O. Owns an `Arc` of the file
/// bytes (memory-mapped), so it is cheap to keep around and to share.
#[derive(Debug)]
pub struct Image {
    pub blob: Arc<Blob>,
    /// Start of this image in `blob` (non-zero for fat Mach-O slices).
    pub slice_offset: usize,
    pub slice_len: usize,
    pub format: Format,
    pub arch: Arch,
    pub bits: u8,
    pub endian: Endian,
    pub platform: Platform,
    pub entry: Option<u64>,
    pub image_base: u64,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub code: Vec<CodeRange>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Symbol>,
    pub exports: Vec<Symbol>,
    pub libraries: Vec<String>,
    /// Function-start seeds (entry, exports, symbols, unwind tables...).
    pub function_hints: Vec<u64>,
    /// Known function extents `[start, end)` from unwind tables (.pdata,
    /// .eh_frame) or `LC_FUNCTION_STARTS` partitions. Code strictly inside
    /// one of these can never start a new function.
    pub function_ranges: Vec<(u64, u64)>,
    /// Pointer slot address (GOT / IAT / la_symbol_ptr) → import index.
    pub import_slots: HashMap<u64, u32>,
    /// Stub code address → import index (Mach-O `__stubs`).
    pub stubs: HashMap<u64, u32>,
    pub is_stripped: bool,
    pub compiler_hints: Vec<String>,
    /// Non-fatal parsing problems.
    pub warnings: Vec<String>,
}

impl Image {
    /// The bytes of this image (the slice for fat binaries).
    pub fn bytes(&self) -> &[u8] {
        let d = self.blob.as_ref().as_ref();
        d.get(self.slice_offset..self.slice_offset.saturating_add(self.slice_len))
            .unwrap_or(&[])
    }

    fn segment_for(&self, va: u64) -> Option<&Segment> {
        // Segments are few (< 100); a linear scan beats a tree here.
        self.segments
            .iter()
            .find(|s| va >= s.vaddr && va - s.vaddr < s.vsize.max(s.file_size))
    }

    /// File-backed bytes starting at `va`, up to `max` bytes (shorter at the
    /// end of a segment). Zero-fill regions (.bss) return `None`.
    pub fn read(&self, va: u64, max: usize) -> Option<&[u8]> {
        let s = self.segment_for(va)?;
        let delta = va - s.vaddr;
        if delta >= s.file_size {
            return None;
        }
        let avail = (s.file_size - delta).min(max as u64) as usize;
        let off = usize::try_from(s.file_offset.checked_add(delta)?).ok()?;
        self.bytes().get(off..off.checked_add(avail)?)
    }

    pub fn read_u32(&self, va: u64) -> Option<u32> {
        let b = self.read(va, 4)?;
        let a: [u8; 4] = b.get(..4)?.try_into().ok()?;
        Some(match self.endian {
            Endian::Little => u32::from_le_bytes(a),
            Endian::Big => u32::from_be_bytes(a),
        })
    }

    pub fn read_u64(&self, va: u64) -> Option<u64> {
        let b = self.read(va, 8)?;
        let a: [u8; 8] = b.get(..8)?.try_into().ok()?;
        Some(match self.endian {
            Endian::Little => u64::from_le_bytes(a),
            Endian::Big => u64::from_be_bytes(a),
        })
    }

    pub fn read_ptr(&self, va: u64) -> Option<u64> {
        if self.bits == 64 {
            self.read_u64(va)
        } else {
            self.read_u32(va).map(u64::from)
        }
    }

    pub fn perms(&self, va: u64) -> u8 {
        self.segment_for(va).map(|s| s.perms).unwrap_or(0)
    }

    pub fn is_mapped(&self, va: u64) -> bool {
        self.segment_for(va).is_some()
    }

    /// True if `va` lies in a code section (or an executable segment if the
    /// binary has no section table).
    pub fn is_code(&self, va: u64) -> bool {
        if self.code.is_empty() {
            return self.perms(va) & PERM_X != 0;
        }
        self.code.iter().any(|c| va >= c.start && va < c.end)
    }

    pub fn code_range(&self, va: u64) -> Option<&CodeRange> {
        self.code.iter().find(|c| va >= c.start && va < c.end)
    }

    /// Map a file offset (relative to the slice) to a virtual address.
    pub fn offset_to_va(&self, off: u64) -> Option<u64> {
        self.segments
            .iter()
            .find(|s| s.file_size > 0 && off >= s.file_offset && off - s.file_offset < s.file_size)
            .map(|s| s.vaddr + (off - s.file_offset))
    }

    pub fn va_to_offset(&self, va: u64) -> Option<u64> {
        let s = self.segment_for(va)?;
        let d = va - s.vaddr;
        (d < s.file_size).then_some(s.file_offset + d)
    }

    /// Name of the section containing `va`.
    pub fn section_name(&self, va: u64) -> Option<&str> {
        self.sections
            .iter()
            .find(|s| va >= s.vaddr.0 && va - s.vaddr.0 < s.vsize.max(1))
            .map(|s| s.name.as_str())
    }

    /// Import name for a pointer slot or stub address.
    pub fn import_at(&self, va: u64) -> Option<&Symbol> {
        let i = self.import_slots.get(&va).or_else(|| self.stubs.get(&va))?;
        self.imports.get(*i as usize)
    }

    /// Run the post-load heuristics shared by all formats.
    /// File bytes that really exist from `va` to the end of its segment
    /// (0 if unmapped, zero-fill, or the header points past the file), and
    /// whether the file itself is shorter than the header claims.
    fn file_backed_len(&self, va: u64) -> (u64, bool) {
        let Some(s) = self.segment_for(va) else {
            return (0, false);
        };
        let delta = va - s.vaddr;
        if delta >= s.file_size {
            return (0, false);
        }
        let Some(off) = s.file_offset.checked_add(delta) else {
            return (0, true);
        };
        let in_file = (self.slice_len as u64).saturating_sub(off);
        let claimed = s.file_size - delta;
        (claimed.min(in_file), in_file < claimed)
    }

    pub(crate) fn finish(&mut self) {
        // Code ranges come from section headers, i.e. file data: clip each
        // to bytes that exist in the file (following contiguous segments).
        // A fuzzed header claiming a 9.2e18-byte code section made gap
        // scanning walk it byte by byte (a hang).
        let mut code = std::mem::take(&mut self.code);
        for c in &mut code {
            let mut pos = c.start;
            let mut truncated = false;
            for _ in 0..=self.segments.len() {
                if pos >= c.end {
                    break;
                }
                let (n, t) = self.file_backed_len(pos);
                truncated |= t;
                if n == 0 {
                    break;
                }
                pos = pos.saturating_add(n);
            }
            let end = pos.min(c.end);
            // A zero-fill tail (PE VirtualSize > SizeOfRawData) is normal:
            // clip silently. Only a header pointing past the file is news.
            if end < c.end && !truncated && end > c.start {
                c.end = end;
            } else if end <= c.start {
                self.warnings.push(format!(
                    "code section {} has no data in the file; skipped",
                    c.name
                ));
                c.end = c.start;
            } else if end < c.end {
                self.warnings.push(format!(
                    "code section {} extends past the file data; analysed up to {end:#x}",
                    c.name
                ));
                c.end = end;
            }
        }
        code.retain(|c| c.end > c.start);
        self.code = code;
        self.function_hints.retain(|&a| a != 0);
        self.function_hints.sort_unstable();
        self.function_hints.dedup();
        self.compiler_hints.sort();
        self.compiler_hints.dedup();
        self.symbols.sort_by_key(|s| s.addr);
        self.function_ranges.retain(|&(s, e)| e > s);
        self.function_ranges.sort_unstable();
        self.function_ranges.dedup();
    }

    /// The known extent that starts exactly at `va`, if any.
    pub fn known_range_at(&self, va: u64) -> Option<(u64, u64)> {
        let i = self.function_ranges.partition_point(|&(s, _)| s < va);
        self.function_ranges.get(i).copied().filter(|r| r.0 == va)
    }

    /// True if `va` lies strictly inside a known function extent.
    pub fn inside_known_range(&self, va: u64) -> bool {
        let i = self.function_ranges.partition_point(|&(s, _)| s < va);
        // Check a few preceding ranges (they may nest, e.g. chained FDEs).
        self.function_ranges[..i]
            .iter()
            .rev()
            .take(4)
            .any(|&(s, e)| va > s && va < e)
    }
}

/// Capability categories used to group imports in the triage view.
pub fn import_capability(name: &str) -> Option<&'static str> {
    let n = name.trim_start_matches('_');
    let l = n.to_ascii_lowercase();
    const NET: &[&str] = &[
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "send",
        "recv",
        "getaddrinfo",
        "gethostbyname",
        "wsastartup",
        "internetopen",
        "internetconnect",
        "httpopenrequest",
        "httpsendrequest",
        "urldownloadtofile",
        "winhttp",
        "curl_",
        "nsurlsession",
        "cfnetwork",
        "nw_connection",
        "inet_",
    ];
    const FILE: &[&str] = &[
        "createfile",
        "readfile",
        "writefile",
        "deletefile",
        "copyfile",
        "movefile",
        "findfirstfile",
        "fopen",
        "fread",
        "fwrite",
        "open",
        "openat",
        "unlink",
        "rename",
        "mkdir",
        "opendir",
        "readdir",
        "stat",
        "lstat",
        "fstat",
        "ftruncate",
    ];
    const CRYPTO: &[&str] = &[
        "crypt",
        "bcrypt",
        "ncrypt",
        "evp_",
        "aes_",
        "sha1",
        "sha256",
        "md5",
        "rsa_",
        "cccrypt",
        "cc_sha",
        "cc_md5",
        "seckey",
        "rand_bytes",
    ];
    const PROC: &[&str] = &[
        "createprocess",
        "openprocess",
        "terminateprocess",
        "createremotethread",
        "writeprocessmemory",
        "readprocessmemory",
        "virtualallocex",
        "ntcreatethreadex",
        "shellexecute",
        "winexec",
        "fork",
        "execve",
        "execv",
        "posix_spawn",
        "system",
        "popen",
        "ptrace",
        "task_for_pid",
        "mach_vm_write",
        "dlopen",
        "loadlibrary",
        "getprocaddress",
        "dlsym",
    ];
    const REG: &[&str] = &[
        "regopenkey",
        "regsetvalue",
        "regcreatekey",
        "regdeletekey",
        "regqueryvalue",
        "regenumkey",
    ];
    const MEM: &[&str] = &[
        "virtualalloc",
        "virtualprotect",
        "mprotect",
        "mmap",
        "vm_protect",
        "heapcreate",
    ];
    const ANTI: &[&str] = &[
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "outputdebugstring",
        "sysctl",
        "gettickcount",
        "queryperformancecounter",
    ];
    let has = |list: &[&str]| list.iter().any(|p| l.starts_with(p));
    if has(PROC) {
        Some("process")
    } else if has(NET) {
        Some("network")
    } else if has(CRYPTO) {
        Some("crypto")
    } else if has(REG) {
        Some("registry")
    } else if has(MEM) {
        Some("memory")
    } else if has(ANTI) {
        Some("anti-debug")
    } else if has(FILE) {
        Some("file")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn caps() {
        assert_eq!(import_capability("CreateRemoteThread"), Some("process"));
        assert_eq!(import_capability("_socket"), Some("network"));
        assert_eq!(import_capability("RegOpenKeyExW"), Some("registry"));
        assert_eq!(import_capability("strlen"), None);
        assert_eq!(perm_string(PERM_R | PERM_X), "r-x");
    }
}
