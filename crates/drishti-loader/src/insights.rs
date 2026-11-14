//! Security insights that need only the loaded image: hardening checks
//! (checksec-style), Mach-O code-signing details and entitlements,
//! indicators of compromise in strings, and well-known crypto constants.

use crate::image::Image;
use drishti_model::{Addr, Finding, FindingKind, Format, Severity, StringRef};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: &'static str,
    /// "good" | "bad" | "info"
    pub status: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Signing {
    pub signed: bool,
    pub adhoc: bool,
    pub identifier: Option<String>,
    pub team_id: Option<String>,
    pub hardened_runtime: bool,
    pub entitlements: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ioc {
    pub kind: &'static str,
    pub value: String,
    pub addr: Addr,
}

fn check(name: &'static str, ok: bool, good: &str, bad: &str) -> Check {
    Check {
        name,
        status: if ok { "good" } else { "bad" },
        detail: if ok { good } else { bad }.to_string(),
    }
}

fn has_import(img: &Image, names: &[&str]) -> bool {
    img.imports.iter().any(|i| {
        let n = i.name.trim_start_matches('_');
        names.iter().any(|w| n.eq_ignore_ascii_case(w))
    })
}

fn le32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn be32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o.checked_add(4)?)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}
fn le16(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

/// Exploit-mitigation and signing checks for the image's format.
pub fn hardening(img: &Image) -> (Vec<Check>, Option<Signing>) {
    let b = img.bytes();
    let canary = has_import(
        img,
        &["stack_chk_fail", "stack_chk_guard", "security_check_cookie"],
    );
    let mut out = Vec::new();
    let mut signing = None;
    match img.format {
        Format::Macho => {
            let is64 = b.get(..4) == Some(&[0xcf, 0xfa, 0xed, 0xfe]);
            let flags = le32(b, 24).unwrap_or(0);
            out.push(check(
                "PIE / ASLR",
                flags & 0x20_0000 != 0 || le32(b, 12) != Some(2),
                "Position independent; address space is randomised",
                "Fixed load address (no ASLR)",
            ));
            out.push(check(
                "Stack execution",
                flags & 0x2_0000 == 0,
                "Stack is not executable",
                "MH_ALLOW_STACK_EXECUTION is set",
            ));
            out.push(check(
                "Stack canary",
                canary,
                "Uses stack protector (__stack_chk_fail)",
                "No stack protector references found",
            ));
            if img.compiler_hints.iter().any(|h| h == "objc") {
                out.push(check(
                    "ARC",
                    has_import(
                        img,
                        &[
                            "objc_release",
                            "objc_retain",
                            "objc_storeStrong",
                            "objc_autoreleaseReturnValue",
                        ],
                    ),
                    "Automatic reference counting in use",
                    "No ARC runtime calls found",
                ));
            }
            // Walk load commands for the code signature and encryption info.
            let mut off = if is64 { 32 } else { 28 };
            let mut sig = None;
            let mut encrypted = false;
            let mut restrict = false;
            for _ in 0..le32(b, 16).unwrap_or(0).min(4096) {
                let (Some(cmd), Some(size)) = (le32(b, off), le32(b, off + 4)) else {
                    break;
                };
                match cmd {
                    0x1d => sig = le32(b, off + 8).zip(le32(b, off + 12)),
                    0x21 | 0x2c => encrypted |= le32(b, off + 16).unwrap_or(0) != 0,
                    0x19 | 0x1 => restrict |= b.get(off + 8..off + 18) == Some(b"__RESTRICT"),
                    _ => {}
                }
                if size < 8 {
                    break;
                }
                off += size as usize;
            }
            let s = sig
                .and_then(|(o, n)| b.get(o as usize..(o as usize).checked_add(n as usize)?))
                .map(parse_codesig)
                .unwrap_or_default();
            out.push(Check {
                name: "Code signature",
                status: if s.signed && !s.adhoc {
                    "good"
                } else if s.signed {
                    "info"
                } else {
                    "bad"
                },
                detail: if !s.signed {
                    "Not signed".into()
                } else if s.adhoc {
                    "Ad-hoc signed (no developer identity)".into()
                } else {
                    format!(
                        "Signed{}",
                        s.team_id
                            .as_ref()
                            .map(|t| format!(" by team {t}"))
                            .unwrap_or_default()
                    )
                },
            });
            if s.signed {
                out.push(check(
                    "Hardened runtime",
                    s.hardened_runtime,
                    "Hardened runtime enabled",
                    "Hardened runtime not enabled",
                ));
            }
            if encrypted {
                out.push(Check {
                    name: "Encryption",
                    status: "info",
                    detail: "App Store (FairPlay) encrypted".into(),
                });
            }
            if restrict {
                out.push(Check {
                    name: "__RESTRICT segment",
                    status: "info",
                    detail: "Blocks dyld environment variables (anti-injection)".into(),
                });
            }
            signing = Some(s);
        }
        Format::Elf => {
            if let Ok(elf) = goblin::elf::Elf::parse(b) {
                let stack = elf.program_headers.iter().find(|p| p.p_type == 0x6474_e551);
                let relro = elf.program_headers.iter().any(|p| p.p_type == 0x6474_e552);
                let now = elf.dynamic.as_ref().is_some_and(|d| {
                    d.dyns.iter().any(|x| {
                        x.d_tag == 24
                            || (x.d_tag == 30 && x.d_val & 8 != 0)
                            || (x.d_tag == 0x6fff_fffb && x.d_val & 1 != 0)
                    })
                });
                out.push(check(
                    "PIE / ASLR",
                    elf.header.e_type == 3,
                    "Position-independent executable",
                    "Fixed load address (no PIE)",
                ));
                out.push(check(
                    "NX stack",
                    stack.is_some_and(|p| p.p_flags & 1 == 0),
                    "Stack is not executable",
                    "Stack may be executable",
                ));
                out.push(Check {
                    name: "RELRO",
                    status: if relro && now {
                        "good"
                    } else if relro {
                        "info"
                    } else {
                        "bad"
                    },
                    detail: if relro && now {
                        "Full RELRO (GOT is read-only)"
                    } else if relro {
                        "Partial RELRO"
                    } else {
                        "No RELRO"
                    }
                    .into(),
                });
                out.push(check(
                    "Stack canary",
                    canary,
                    "Uses stack protector",
                    "No stack protector references found",
                ));
                let fortify = img.imports.iter().any(|i| {
                    i.name.starts_with("__")
                        && i.name.ends_with("_chk")
                        && i.name != "__stack_chk_fail"
                });
                out.push(Check {
                    name: "FORTIFY_SOURCE",
                    status: if fortify { "good" } else { "info" },
                    detail: if fortify {
                        "Fortified libc calls present"
                    } else {
                        "No fortified libc calls"
                    }
                    .into(),
                });
            }
        }
        Format::Pe | Format::PeDotnet => {
            if let Some(lfanew) = le32(b, 0x3c).map(|v| v as usize) {
                let opt = lfanew + 24;
                let dc = le16(b, opt + 70).unwrap_or(0);
                let pe32p = le16(b, opt) == Some(0x20b);
                let dd = opt + if pe32p { 112 } else { 96 };
                let cert = le32(b, dd + 4 * 8 + 4).unwrap_or(0) != 0;
                out.push(check(
                    "ASLR",
                    dc & 0x40 != 0,
                    "DYNAMIC_BASE set",
                    "No ASLR (DYNAMIC_BASE not set)",
                ));
                if pe32p {
                    out.push(check(
                        "High-entropy ASLR",
                        dc & 0x20 != 0,
                        "HIGH_ENTROPY_VA set",
                        "HIGH_ENTROPY_VA not set",
                    ));
                }
                out.push(check(
                    "DEP / NX",
                    dc & 0x100 != 0,
                    "NX_COMPAT set",
                    "NX_COMPAT not set",
                ));
                out.push(check(
                    "Control Flow Guard",
                    dc & 0x4000 != 0,
                    "GUARD_CF set",
                    "No CFG",
                ));
                out.push(check(
                    "Authenticode",
                    cert,
                    "Carries a signature",
                    "Not signed",
                ));
                // /GS: the load-config directory (data directory 10) records
                // the address of __security_cookie; the check itself is
                // statically linked from the CRT, so imports rarely show it.
                let cookie = le32(b, dd + 10 * 8)
                    .filter(|&rva| rva != 0)
                    .and_then(|rva| {
                        let lc = img.read(img.image_base.wrapping_add(u64::from(rva)), 0x60)?;
                        let size = le32(lc, 0)? as usize;
                        let (off, w) = if pe32p { (0x58, 8) } else { (0x3c, 4) };
                        if size < off + w {
                            return None;
                        }
                        let v = if pe32p {
                            u64::from(le32(lc, off)?) | u64::from(le32(lc, off + 4)?) << 32
                        } else {
                            u64::from(le32(lc, off)?)
                        };
                        Some(v != 0)
                    })
                    .unwrap_or(false);
                out.push(Check {
                    name: "Stack cookie",
                    status: if cookie || canary { "good" } else { "info" },
                    detail: if cookie {
                        "/GS security cookie registered in the load configuration"
                    } else if canary {
                        "Uses /GS cookie check"
                    } else {
                        "No /GS security cookie found (load config or imports)"
                    }
                    .into(),
                });
            }
        }
        _ => {}
    }
    (out, signing)
}

/// Parse an embedded signature SuperBlob (big-endian).
fn parse_codesig(d: &[u8]) -> Signing {
    let mut s = Signing::default();
    if be32(d, 0) != Some(0xfade_0cc0) {
        return s;
    }
    s.signed = true;
    let mut has_cms = false;
    for i in 0..be32(d, 8).unwrap_or(0).min(64) as usize {
        let Some(off) = be32(d, 12 + i * 8 + 4).map(|v| v as usize) else {
            break;
        };
        let (Some(magic), Some(len)) = (be32(d, off), be32(d, off + 4)) else {
            continue;
        };
        let Some(blob) = d.get(off..off.saturating_add(len as usize)) else {
            continue;
        };
        match magic {
            0xfade_0c02 => {
                let flags = be32(blob, 12).unwrap_or(0);
                s.adhoc = flags & 0x2 != 0;
                s.hardened_runtime = flags & 0x1_0000 != 0;
                let cstr = |o: usize| {
                    blob.get(o..).and_then(|t| {
                        t.iter()
                            .position(|&c| c == 0)
                            .map(|n| String::from_utf8_lossy(&t[..n]).into_owned())
                    })
                };
                s.identifier = be32(blob, 20).and_then(|o| cstr(o as usize));
                if be32(blob, 8).unwrap_or(0) >= 0x2_0200 {
                    s.team_id = be32(blob, 48)
                        .filter(|&o| o != 0)
                        .and_then(|o| cstr(o as usize));
                }
            }
            0xfade_7171 => {
                s.entitlements =
                    parse_entitlements(&String::from_utf8_lossy(blob.get(8..).unwrap_or(&[])))
            }
            0xfade_0b01 => has_cms = len > 8,
            _ => {}
        }
    }
    if !has_cms {
        s.adhoc = true;
    }
    s
}

/// Flatten an entitlements XML plist into (key, value) pairs.
fn parse_entitlements(xml: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(k) = rest.find("<key>") {
        let after = &rest[k + 5..];
        let Some(e) = after.find("</key>") else { break };
        let key = after[..e].to_string();
        let tail = after[e + 6..].trim_start();
        let val = if tail.starts_with("<true/>") {
            "true".to_string()
        } else if tail.starts_with("<false/>") {
            "false".to_string()
        } else if let Some(t) = tail.strip_prefix("<string>") {
            t.split("</string>").next().unwrap_or("").to_string()
        } else if tail.starts_with("<array>") {
            let body = tail.split("</array>").next().unwrap_or("");
            body.split("<string>")
                .skip(1)
                .filter_map(|x| x.split("</string>").next())
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            "…".to_string()
        };
        out.push((key, val));
        rest = &after[e + 6..];
        if out.len() >= 200 {
            break;
        }
    }
    out
}

fn is_ipv4(tok: &str) -> bool {
    let parts: Vec<&str> = tok.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let nums: Vec<u32> = parts
        .iter()
        .filter_map(|p| {
            if p.is_empty() || p.len() > 3 || (p.len() > 1 && p.starts_with('0')) {
                None
            } else {
                p.parse().ok()
            }
        })
        .collect();
    if nums.len() != 4 || nums.iter().any(|&n| n > 255) || nums[0] == 0 {
        return false;
    }
    // Version-like quads (1.2.3.4) are noise, except well-known resolvers.
    nums.iter().any(|&n| n > 9)
        || matches!(
            tok,
            "8.8.8.8" | "8.8.4.4" | "1.1.1.1" | "1.0.0.1" | "9.9.9.9"
        )
}

fn is_email(tok: &str) -> bool {
    let Some((l, d)) = tok.split_once('@') else {
        return false;
    };
    let tld = d.rsplit('.').next().unwrap_or("");
    !l.is_empty()
        && d.contains('.')
        && !d.starts_with('.')
        && !d.contains('@')
        && tld.len() >= 2
        && tld.chars().all(|c| c.is_ascii_alphabetic())
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !tok.ends_with(".png")
        && !tok.contains("@2x")
        && !tok.contains("@3x")
}

/// URLs, IPs, e-mail addresses, registry keys, interesting paths and
/// shell commands found in strings (deduplicated, capped per kind).
pub fn iocs(strings: &[StringRef]) -> Vec<Ioc> {
    use std::collections::{HashMap, HashSet};
    let mut seen: HashSet<(&'static str, String)> = HashSet::new();
    let mut count: HashMap<&'static str, usize> = HashMap::new();
    let mut out = Vec::new();
    let mut push = |kind: &'static str, value: &str, addr: Addr, out: &mut Vec<Ioc>| {
        let c = count.entry(kind).or_default();
        if *c >= 150 || value.len() < 4 || value.len() > 300 {
            return;
        }
        if seen.insert((kind, value.to_string())) {
            *c += 1;
            out.push(Ioc {
                kind,
                value: value.to_string(),
                addr,
            });
        }
    };
    const PATHS: &[&str] = &[
        "/etc/",
        "/tmp/",
        "/var/",
        "/Library/Launch",
        "~/Library/",
        "/usr/bin/",
        "/bin/sh",
        "/bin/bash",
        "/dev/",
        "/proc/",
        "C:\\",
        "%APPDATA%",
        "%TEMP%",
        "\\\\.\\",
    ];
    const CMDS: &[&str] = &[
        "powershell",
        "cmd.exe",
        "cmd /c",
        "curl ",
        "wget ",
        "chmod +x",
        "launchctl ",
        "osascript",
        "/bin/sh -c",
        "bash -c",
        "schtasks",
        "reg add",
        "vssadmin",
        "base64 -d",
        "nc -e",
    ];
    for s in strings {
        let v = s.value.as_str();
        for scheme in ["https://", "http://", "wss://", "ws://", "ftp://"] {
            let mut from = 0;
            while let Some(i) = v[from..].find(scheme) {
                let st = from + i;
                let end = v[st..]
                    .find(|c: char| {
                        c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | ')' | '`')
                    })
                    .map(|e| st + e)
                    .unwrap_or(v.len());
                if end - st > scheme.len() + 3 {
                    push("url", &v[st..end], s.addr, &mut out);
                }
                from = end.max(st + 1);
                if from >= v.len() {
                    break;
                }
            }
        }
        if v.contains('@') {
            for tok in v.split(|c: char| {
                !(c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '-' | '+'))
            }) {
                if is_email(tok) {
                    push("email", tok, s.addr, &mut out);
                }
            }
        }
        if v.len() >= 7 && v.as_bytes().iter().any(u8::is_ascii_digit) && v.contains('.') {
            for tok in v.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
                if is_ipv4(tok) {
                    push("ip", tok, s.addr, &mut out);
                }
            }
        }
        if v.contains("HKEY_")
            || v.contains("SOFTWARE\\Microsoft")
            || v.contains("CurrentVersion\\Run")
        {
            push("registry", v, s.addr, &mut out);
        }
        if v.contains(".onion") {
            push("onion", v, s.addr, &mut out);
        }
        if PATHS.iter().any(|p| v.starts_with(p)) && !v.contains(' ') {
            push("path", v, s.addr, &mut out);
        }
        let lower = v.to_ascii_lowercase();
        if CMDS.iter().any(|c| lower.contains(c)) {
            push("command", v, s.addr, &mut out);
        }
    }
    out
}

const CRYPTO: &[(&str, &[u8])] = &[
    (
        "AES S-box",
        &[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
        ],
    ),
    (
        "AES inverse S-box",
        &[
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
        ],
    ),
    (
        "AES T-table (Te0)",
        &[0xa5, 0x63, 0x63, 0xc6, 0x84, 0x7c, 0x7c, 0xf8],
    ),
    (
        "SHA-256 constants",
        &[0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71],
    ),
    (
        "SHA-256 constants (BE)",
        &[0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91],
    ),
    (
        "SHA-512 constants",
        &[0x22, 0xae, 0x28, 0xd7, 0x98, 0x2f, 0x8a, 0x42],
    ),
    (
        "MD5 table",
        &[0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8],
    ),
    (
        "SHA-1 / MD5 init",
        &[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
        ],
    ),
    (
        "CRC-32 table",
        &[0x96, 0x30, 0x07, 0x77, 0x2c, 0x61, 0x0e, 0xee],
    ),
    (
        "Blowfish P-array",
        &[0x88, 0x6a, 0x3f, 0x24, 0xd3, 0x08, 0xa3, 0x85],
    ),
    ("ChaCha/Salsa constant", b"expand 32-byte k"),
    (
        "Base64 alphabet",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    ),
    (
        "Curve25519 base constant",
        &[
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ],
    ),
];

/// Scan file-backed sections for well-known cryptographic tables. One pass
/// with a first-byte filter keeps this fast on large binaries.
pub fn crypto_constants(img: &Image) -> Vec<Finding> {
    let mut first = [false; 256];
    for (_, p) in CRYPTO {
        first[p[0] as usize] = true;
    }
    let mut hits: Vec<Vec<u64>> = vec![Vec::new(); CRYPTO.len()];
    let bytes = img.bytes();
    let mut budget = 400usize << 20;
    for s in &img.sections {
        if s.file_size == 0 || budget == 0 {
            continue;
        }
        let n = (s.file_size as usize).min(budget);
        budget -= n;
        let Some(d) = bytes.get(s.file_offset as usize..(s.file_offset as usize).saturating_add(n))
        else {
            continue;
        };
        for (i, &b) in d.iter().enumerate() {
            if !first[b as usize] {
                continue;
            }
            for (k, (_, p)) in CRYPTO.iter().enumerate() {
                if hits[k].len() < 4 && d[i..].starts_with(p) {
                    hits[k].push(s.vaddr.0 + i as u64);
                }
            }
        }
    }
    CRYPTO
        .iter()
        .zip(hits)
        .filter(|(_, h)| !h.is_empty())
        .map(|((name, _), h)| Finding {
            kind: FindingKind::Other,
            severity: Severity::Info,
            title: format!("Crypto constant: {name}"),
            detail:
                "Known constant table; code that references it likely implements this algorithm."
                    .into(),
            addrs: h.into_iter().map(Addr).collect(),
            source: "rule".into(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use drishti_model::StringEncoding;

    fn s(v: &str) -> StringRef {
        StringRef {
            addr: Addr(1),
            value: v.into(),
            encoding: StringEncoding::Ascii,
            xrefs: vec![],
        }
    }

    #[test]
    fn finds_iocs() {
        let v = iocs(&[
            s("GET https://example.org/a?b=1 now"),
            s("contact admin@example.org"),
            s("dns 192.168.1.10 v1.2.3.4"),
            s("/etc/passwd"),
            s("icon@2x.png"),
        ]);
        let has = |k: &str, val: &str| v.iter().any(|i| i.kind == k && i.value == val);
        assert!(has("url", "https://example.org/a?b=1"));
        assert!(has("email", "admin@example.org"));
        assert!(has("ip", "192.168.1.10"));
        assert!(!v.iter().any(|i| i.value == "1.2.3.4"));
        assert!(has("path", "/etc/passwd"));
        assert_eq!(v.iter().filter(|i| i.kind == "email").count(), 1);
    }

    #[test]
    fn entitlements_parse() {
        let e = parse_entitlements(
            "<dict><key>com.apple.security.app-sandbox</key><true/><key>groups</key><array><string>a</string><string>b</string></array></dict>",
        );
        assert_eq!(
            e[0],
            ("com.apple.security.app-sandbox".into(), "true".into())
        );
        assert_eq!(e[1].1, "a, b");
    }
}
