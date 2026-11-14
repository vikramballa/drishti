//! Where a file on disk came from: macOS download metadata.
//!
//! Browsers, Mail and AirDrop tag downloaded files with two extended
//! attributes: `com.apple.metadata:kMDItemWhereFroms` (a binary plist array
//! with the download URL and the page that linked to it, or a mail sender
//! and subject) and `com.apple.quarantine` (`flags;hex-time;agent;uuid`).
//! They are read with the system `xattr` tool, so no unsafe FFI is needed;
//! the input file itself is never executed. Uploads through the browser lose
//! these attributes, so this only works for files opened in place.

use drishti_model::FileOrigin;
use std::path::Path;
use std::process::Command;

const XATTR: &str = "/usr/bin/xattr";

fn xattr(path: &Path, name: &str, hex: bool) -> Option<Vec<u8>> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let mut c = Command::new(XATTR);
    c.arg(if hex { "-px" } else { "-p" }).arg(name).arg(path);
    let out = c.output().ok()?;
    if !out.status.success() {
        return None;
    }
    if !hex {
        return Some(out.stdout);
    }
    let txt = String::from_utf8_lossy(&out.stdout);
    let mut bytes = Vec::new();
    for tok in txt.split_ascii_whitespace() {
        bytes.push(u8::from_str_radix(tok, 16).ok()?);
    }
    Some(bytes)
}

/// Read the download origin of `path`. Returns `None` when the file carries
/// no such metadata (created locally, copied, or not on macOS).
pub fn file_origin(path: &Path) -> Option<FileOrigin> {
    let mut o = FileOrigin::default();
    if let Some(b) = xattr(path, "com.apple.metadata:kMDItemWhereFroms", true) {
        o.where_from = bplist_strings(&b)
            .into_iter()
            .filter(|s| !s.trim().is_empty())
            .take(8)
            .collect();
    }
    if let Some(q) = xattr(path, "com.apple.quarantine", false) {
        let q = String::from_utf8_lossy(&q);
        let parts: Vec<&str> = q.trim().split(';').collect();
        o.quarantined = true;
        if let Some(t) = parts.get(1).and_then(|h| i64::from_str_radix(h, 16).ok()) {
            o.downloaded_at = Some(utc(t));
        }
        if let Some(a) = parts.get(2).filter(|a| !a.is_empty()) {
            o.downloaded_by = Some(a.to_string());
        }
    }
    (o.quarantined || !o.where_from.is_empty()).then_some(o)
}

fn utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{d} {} {y} {:02}:{:02} UTC",
        months[(m - 1).clamp(0, 11) as usize],
        rem / 3600,
        rem % 3600 / 60
    )
}

/// Strings from a binary plist whose top object is a string or an array of
/// strings (the shape of `kMDItemWhereFroms`). Anything else yields nothing.
pub fn bplist_strings(b: &[u8]) -> Vec<String> {
    let Some(tr) = b.len().checked_sub(32).and_then(|s| b.get(s..)) else {
        return Vec::new();
    };
    if !b.starts_with(b"bplist00") {
        return Vec::new();
    }
    let be = |s: &[u8]| s.iter().fold(0u64, |a, &x| a << 8 | u64::from(x));
    let off_size = tr[6] as usize;
    let ref_size = tr[7] as usize;
    let num = be(&tr[8..16]) as usize;
    let top = be(&tr[16..24]) as usize;
    let table = be(&tr[24..32]) as usize;
    if !(1..=8).contains(&off_size) || !(1..=8).contains(&ref_size) || num > 10_000 {
        return Vec::new();
    }
    let offset = |i: usize| -> Option<usize> {
        let s = table.checked_add(i.checked_mul(off_size)?)?;
        Some(be(b.get(s..s + off_size)?) as usize)
    };
    // Length that follows a marker: low nibble, or an int object when 0xF.
    let len_at = |p: usize| -> Option<(usize, usize)> {
        let m = *b.get(p)?;
        if m & 0x0f != 0x0f {
            return Some(((m & 0x0f) as usize, p + 1));
        }
        let im = *b.get(p + 1)?;
        if im & 0xf0 != 0x10 {
            return None;
        }
        let n = 1usize << (im & 0x0f).min(3);
        Some((be(b.get(p + 2..p + 2 + n)?) as usize, p + 2 + n))
    };
    let string = |i: usize| -> Option<String> {
        let p = offset(i)?;
        let m = *b.get(p)?;
        let (n, s) = len_at(p)?;
        match m >> 4 {
            0x5 => Some(String::from_utf8_lossy(b.get(s..s.checked_add(n)?)?).into_owned()),
            0x6 => {
                let raw = b.get(s..s.checked_add(n.checked_mul(2)?)?)?;
                let u: Vec<u16> = raw
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                Some(String::from_utf16_lossy(&u))
            }
            _ => None,
        }
    };
    let Some(p) = offset(top) else {
        return Vec::new();
    };
    match b.get(p).map(|m| m >> 4) {
        Some(0xa) => {
            let Some((n, s)) = len_at(p) else {
                return Vec::new();
            };
            (0..n.min(64))
                .filter_map(|k| {
                    let r = s.checked_add(k.checked_mul(ref_size)?)?;
                    string(be(b.get(r..r + ref_size)?) as usize)
                })
                .collect()
        }
        Some(0x5 | 0x6) => string(top).into_iter().collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn where_froms_plist() {
        // ["https://e.com/a.pdf", "https://e.com/"] as produced by Safari.
        let mut b = b"bplist00".to_vec();
        let o1 = b.len();
        b.push(0xa2);
        b.extend_from_slice(&[1, 2]);
        let o2 = b.len();
        b.push(0x5f);
        b.extend_from_slice(&[0x10, 19]);
        b.extend_from_slice(b"https://e.com/a.pdf");
        let o3 = b.len();
        b.push(0x5e);
        b.extend_from_slice(b"https://e.com/");
        let table = b.len();
        b.extend_from_slice(&[o1 as u8, o2 as u8, o3 as u8]);
        let mut tr = vec![0u8; 6];
        tr.extend_from_slice(&[1, 1]);
        tr.extend_from_slice(&3u64.to_be_bytes());
        tr.extend_from_slice(&0u64.to_be_bytes());
        tr.extend_from_slice(&(table as u64).to_be_bytes());
        b.extend_from_slice(&tr);
        assert_eq!(
            bplist_strings(&b),
            vec![
                "https://e.com/a.pdf".to_string(),
                "https://e.com/".to_string()
            ]
        );
        assert!(bplist_strings(&b[..20]).is_empty());
        assert!(bplist_strings(b"bplist00garbagegarbagegarbagegarbagegarbage").is_empty());
    }

    #[test]
    fn utc_format() {
        assert_eq!(utc(0), "1 Jan 1970 00:00 UTC");
        assert_eq!(utc(1_700_000_000), "14 Nov 2023 22:13 UTC");
    }
}
