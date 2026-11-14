//! Hashing, entropy, string extraction and demangling helpers.

use drishti_model::StringEncoding;
use md5::Md5;
use sha2::{Digest, Sha256};

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lower-case hex encoding without an extra dependency.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn md5_hex(data: &[u8]) -> String {
    hex(&Md5::digest(data))
}

/// Shannon entropy in bits per byte (0..8).
pub fn entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut hist = [0u64; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut e = 0.0f64;
    for &c in &hist {
        if c > 0 {
            let p = c as f64 / n;
            e -= p * p.log2();
        }
    }
    // Round to 3 decimals so JSON stays compact and stable.
    ((e * 1000.0).round() / 1000.0) as f32
}

#[inline]
fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

/// A raw string hit: file offset, encoding and decoded text.
#[derive(Debug, Clone)]
pub struct RawString {
    pub offset: u64,
    pub encoding: StringEncoding,
    pub value: String,
}

/// Extract ASCII and UTF-16LE strings of at least `min` characters.
///
/// `limit` caps the number of results so huge binaries cannot exhaust
/// memory; strings longer than 1 KiB are truncated for the same reason.
pub fn extract_strings(
    data: &[u8],
    base_offset: u64,
    min: usize,
    limit: usize,
    out: &mut Vec<RawString>,
) {
    let min = min.max(2);
    const MAX_LEN: usize = 1024;
    // ASCII pass.
    let mut start = 0usize;
    let mut run = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if printable(b) {
            if run == 0 {
                start = i;
            }
            run += 1;
        } else {
            if run >= min {
                if out.len() >= limit {
                    return;
                }
                let end = start + run.min(MAX_LEN);
                out.push(RawString {
                    offset: base_offset + start as u64,
                    encoding: StringEncoding::Ascii,
                    value: String::from_utf8_lossy(&data[start..end]).into_owned(),
                });
            }
            run = 0;
        }
    }
    if run >= min && out.len() < limit {
        let end = start + run.min(MAX_LEN);
        out.push(RawString {
            offset: base_offset + start as u64,
            encoding: StringEncoding::Ascii,
            value: String::from_utf8_lossy(&data[start..end]).into_owned(),
        });
    }
    // UTF-16LE pass (printable ASCII range only, which covers most Windows strings).
    for phase in 0..2usize {
        let mut i = phase;
        let mut start = 0usize;
        let mut buf = String::new();
        while i + 1 < data.len() {
            let (lo, hi) = (data[i], data[i + 1]);
            if hi == 0 && printable(lo) {
                if buf.is_empty() {
                    start = i;
                }
                if buf.len() < MAX_LEN {
                    buf.push(lo as char);
                }
            } else {
                if buf.len() >= min {
                    if out.len() >= limit {
                        return;
                    }
                    out.push(RawString {
                        offset: base_offset + start as u64,
                        encoding: StringEncoding::Utf16le,
                        value: std::mem::take(&mut buf),
                    });
                }
                buf.clear();
            }
            i += 2;
        }
        if buf.len() >= min && out.len() < limit {
            out.push(RawString {
                offset: base_offset + start as u64,
                encoding: StringEncoding::Utf16le,
                value: buf,
            });
        }
    }
}

/// Demangle C++ (Itanium, MSVC) and Rust symbols. Returns `None` if the
/// name is not mangled or demangling fails.
pub fn demangle(name: &str) -> Option<String> {
    // Mach-O prefixes C symbols with one underscore.
    let candidates: [&str; 2] = [name, name.strip_prefix('_').unwrap_or("")];
    for n in candidates {
        if n.is_empty() {
            continue;
        }
        if (n.starts_with("_ZN") || n.starts_with("_R"))
            && let Ok(d) = rustc_demangle::try_demangle(n)
        {
            let s = format!("{d:#}");
            if s != n {
                return Some(s);
            }
        }
        if n.starts_with("_Z")
            && let Ok(sym) = cpp_demangle::Symbol::new(n)
            && let Ok(s) = sym.demangle()
        {
            return Some(s);
        }
        if n.starts_with('?')
            && let Ok(s) = msvc_demangler::demangle(n, msvc_demangler::DemangleFlags::llvm())
        {
            return Some(s);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[0u8; 100]), 0.0);
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((entropy(&all) - 8.0).abs() < 0.001);
    }

    #[test]
    fn strings_ascii_and_utf16() {
        let mut d = b"\x00\x01hello world\x00ab\x00".to_vec();
        d.extend_from_slice(&[b'W', 0, b'i', 0, b'd', 0, b'e', 0, 0, 0]);
        let mut out = Vec::new();
        extract_strings(&d, 0x100, 4, 100, &mut out);
        assert!(
            out.iter()
                .any(|s| s.value == "hello world" && s.offset == 0x102)
        );
        assert!(
            out.iter()
                .any(|s| s.value.ends_with("Wide") && s.encoding == StringEncoding::Utf16le)
        );
        assert!(!out.iter().any(|s| s.value == "ab"));
    }

    #[test]
    fn demangling() {
        assert_eq!(demangle("_ZN3foo3barE").as_deref(), Some("foo::bar"));
        assert_eq!(demangle("__ZN3foo3barE").as_deref(), Some("foo::bar"));
        assert!(demangle("_Z3addii").unwrap().starts_with("add(int, int)"));
        assert_eq!(demangle("main"), None);
    }
}
