//! Search engine shared by the API, the CLI and the MCP server.
//!
//! * Byte searches over the raw file: text (UTF-8 / UTF-16, case-insensitive),
//!   YARA-style hex patterns, regular expressions over bytes, and numbers
//!   (every integer width / float, either byte order).
//! * Instruction patterns over the disassembly, including sequences
//!   (`mov edi, *; call *malloc`).
//! * A small query language over functions
//!   (`calls:SecItemCopyMatching size>200 -is:thunk`).
//!
//! Everything compiles to `regex` automata, so matching is linear in the
//! input; results are capped and time-boxed so a huge file or a pattern that
//! matches everywhere stays responsive.

use crate::analyze::{Analysis, Func};
use drishti_loader::Image;
use drishti_model::{NameSource, StringRef};
use regex::bytes::{Regex, RegexBuilder};
use std::fmt::Write as _;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- byte search

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Text,
    Hex,
    Regex,
    Number,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        Some(match s {
            "text" => Mode::Text,
            "hex" => Mode::Hex,
            "regex" | "re" => Mode::Regex,
            "number" | "num" | "int" => Mode::Number,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enc {
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl Enc {
    pub fn parse_list(s: &str) -> Result<Vec<Enc>, String> {
        let mut v = Vec::new();
        for p in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let e = match p.to_ascii_lowercase().as_str() {
                "utf8" | "utf-8" | "ascii" => Enc::Utf8,
                "utf16le" | "utf-16le" | "utf16" | "wide" => Enc::Utf16Le,
                "utf16be" | "utf-16be" => Enc::Utf16Be,
                _ => {
                    return Err(format!(
                        "unknown encoding `{p}` (use utf8, utf16le, utf16be)"
                    ));
                }
            };
            if !v.contains(&e) {
                v.push(e);
            }
        }
        Ok(v)
    }
    fn label(self) -> &'static str {
        match self {
            Enc::Utf8 => "utf-8",
            Enc::Utf16Le => "utf-16le",
            Enc::Utf16Be => "utf-16be",
        }
    }
}

/// Byte order for number searches. `None` in [`ByteQuery::endian`] = both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Little,
    Big,
}

#[derive(Debug, Clone)]
pub struct ByteQuery {
    pub mode: Mode,
    pub query: String,
    pub case_sensitive: bool,
    /// Text mode; empty = UTF-8 + UTF-16LE.
    pub encodings: Vec<Enc>,
    /// Number mode: 1, 2, 4 or 8 bytes; `None` = every width the value fits
    /// in (at least 2 bytes).
    pub width: Option<u8>,
    /// Number mode; `None` = both byte orders.
    pub endian: Option<Order>,
}

impl ByteQuery {
    pub fn new(mode: Mode, query: impl Into<String>) -> Self {
        ByteQuery {
            mode,
            query: query.into(),
            case_sensitive: false,
            encodings: Vec::new(),
            width: None,
            endian: Some(Order::Little),
        }
    }
}

/// A compiled byte query: one automaton per variant (encoding, width...).
#[derive(Debug)]
pub struct Compiled {
    pats: Vec<(Regex, String)>,
}

const MAX_QUERY: usize = 4096;

fn bytes_re(src: &str) -> Result<Regex, String> {
    RegexBuilder::new(src)
        .unicode(false)
        .dot_matches_new_line(true)
        .size_limit(32 << 20)
        .dfa_size_limit(32 << 20)
        .build()
        .map_err(|e| short_err(&e.to_string()))
}

fn short_err(e: &str) -> String {
    // regex errors are multi-line with a caret diagram; keep the last line.
    let last = e.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or(e);
    format!(
        "invalid pattern: {}",
        last.trim().trim_start_matches("error: ")
    )
}

fn push_byte(s: &mut String, b: u8) {
    let _ = write!(s, "\\x{b:02x}");
}

fn literal_re(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 4);
    for &b in bytes {
        push_byte(&mut s, b);
    }
    s
}

pub fn compile(q: &ByteQuery) -> Result<Compiled, String> {
    if q.query.is_empty() {
        return Err("type something to search for".into());
    }
    if q.query.len() > MAX_QUERY {
        return Err(format!("query is longer than {MAX_QUERY} characters"));
    }
    let pats = match q.mode {
        Mode::Text => text_patterns(q)?,
        Mode::Hex => vec![(bytes_re(&hex_to_regex(&q.query)?)?, "hex".into())],
        Mode::Regex => {
            let re = RegexBuilder::new(&q.query)
                .unicode(false)
                .case_insensitive(!q.case_sensitive)
                .dot_matches_new_line(false)
                .size_limit(32 << 20)
                .dfa_size_limit(32 << 20)
                .build()
                .map_err(|e| short_err(&e.to_string()))?;
            vec![(re, "regex".into())]
        }
        Mode::Number => number_patterns(q)?
            .into_iter()
            .map(|(b, l)| Ok((bytes_re(&literal_re(&b))?, l)))
            .collect::<Result<_, String>>()?,
    };
    Ok(Compiled { pats })
}

fn text_patterns(q: &ByteQuery) -> Result<Vec<(Regex, String)>, String> {
    let encs = if q.encodings.is_empty() {
        vec![Enc::Utf8, Enc::Utf16Le]
    } else {
        q.encodings.clone()
    };
    let mut out = Vec::new();
    for e in encs {
        let re = match e {
            Enc::Utf8 => RegexBuilder::new(&regex::escape(&q.query))
                .case_insensitive(!q.case_sensitive)
                .size_limit(32 << 20)
                .build()
                .map_err(|e| short_err(&e.to_string()))?,
            Enc::Utf16Le | Enc::Utf16Be => {
                let mut s = String::new();
                for c in q.query.chars() {
                    let mut buf = [0u16; 2];
                    for &u in c.encode_utf16(&mut buf).iter() {
                        let [lo, hi] = u.to_le_bytes();
                        if e == Enc::Utf16Le {
                            push_low(&mut s, lo, hi, q.case_sensitive);
                            push_byte(&mut s, hi);
                        } else {
                            push_byte(&mut s, hi);
                            push_low(&mut s, lo, hi, q.case_sensitive);
                        }
                    }
                }
                bytes_re(&s)?
            }
        };
        out.push((re, e.label().to_string()));
    }
    Ok(out)
}

/// Low byte of a UTF-16 code unit; ASCII letters match either case.
fn push_low(s: &mut String, lo: u8, hi: u8, case_sensitive: bool) {
    if !case_sensitive && hi == 0 && lo.is_ascii_alphabetic() {
        let (a, b) = (lo.to_ascii_lowercase(), lo.to_ascii_uppercase());
        let _ = write!(s, "[\\x{a:02x}\\x{b:02x}]");
    } else {
        push_byte(s, lo);
    }
}

/// YARA-style hex string → byte regex.
///
/// `48 8b ?? 05` (wildcard byte), `4?` / `?5` (nibble), `~00` (any byte but),
/// `[4]` / `[2-6]` / `[2-]` (jump), `( 90 | cc cc )` (alternatives).
pub fn hex_to_regex(src: &str) -> Result<String, String> {
    let c: Vec<char> = src.chars().collect();
    let mut i = 0;
    let mut out = String::new();
    let mut concrete = 0usize;
    let mut depth = 0i32;
    let hexv = |ch: char| ch.to_digit(16).map(|d| d as u8);
    let next_nonspace = |i: &mut usize| -> Option<char> {
        while *i < c.len() && c[*i].is_whitespace() {
            *i += 1;
        }
        let r = c.get(*i).copied();
        *i += 1;
        r
    };
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() || ch == ',' {
            i += 1;
            continue;
        }
        match ch {
            '(' => {
                depth += 1;
                out += "(?:";
                i += 1;
            }
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return Err("unbalanced `)` in hex pattern".into());
                }
                out += ")";
                i += 1;
            }
            '|' => {
                if depth == 0 {
                    return Err("`|` must be inside ( … )".into());
                }
                out += "|";
                i += 1;
            }
            '[' => {
                let end = c[i..]
                    .iter()
                    .position(|&x| x == ']')
                    .ok_or("jump `[` without `]`")?;
                let inner: String = c[i + 1..i + end]
                    .iter()
                    .filter(|x| !x.is_whitespace())
                    .collect();
                i += end + 1;
                let num = |s: &str| -> Result<u32, String> {
                    s.parse::<u32>()
                        .ok()
                        .filter(|&n| n <= 4096)
                        .ok_or_else(|| format!("jump size `{s}` must be 0–4096"))
                };
                let rep = match inner.split_once('-') {
                    None => {
                        let n = num(&inner)?;
                        format!("{{{n}}}")
                    }
                    Some((a, b)) => {
                        let lo = if a.is_empty() { 0 } else { num(a)? };
                        if b.is_empty() {
                            format!("{{{lo},}}")
                        } else {
                            let hi = num(b)?;
                            if hi < lo {
                                return Err(format!("jump [{lo}-{hi}] is backwards"));
                            }
                            format!("{{{lo},{hi}}}")
                        }
                    }
                };
                out += "(?:.)";
                out += &rep;
            }
            '~' => {
                i += 1;
                let (a, b) = (next_nonspace(&mut i), next_nonspace(&mut i));
                let v = match (a.and_then(hexv), b.and_then(hexv)) {
                    (Some(h), Some(l)) => h << 4 | l,
                    _ => return Err("`~` must be followed by a byte, e.g. ~00".into()),
                };
                let _ = write!(out, "[^\\x{v:02x}]");
                concrete += 1;
            }
            _ => {
                let a = next_nonspace(&mut i).unwrap_or(' ');
                let b = next_nonspace(&mut i).ok_or_else(|| {
                    format!("`{a}` is half a byte; hex bytes are two digits like `0{a}`")
                })?;
                match (a, b, hexv(a), hexv(b)) {
                    ('?', '?', _, _) => out += "(?:.)",
                    (_, _, Some(h), Some(l)) => {
                        push_byte(&mut out, h << 4 | l);
                        concrete += 1;
                    }
                    ('?', _, None, Some(l)) => {
                        out += "[";
                        for h in 0..16u8 {
                            push_byte(&mut out, h << 4 | l);
                        }
                        out += "]";
                        concrete += 1;
                    }
                    (_, '?', Some(h), None) => {
                        let (lo, hi) = (h << 4, h << 4 | 0xf);
                        let _ = write!(out, "[\\x{lo:02x}-\\x{hi:02x}]");
                        concrete += 1;
                    }
                    _ => {
                        return Err(format!(
                            "`{a}{b}` is not a hex byte (use 00–ff, ?? for any byte)"
                        ));
                    }
                }
            }
        }
    }
    if depth != 0 {
        return Err("unbalanced `(` in hex pattern".into());
    }
    if concrete == 0 {
        return Err("pattern needs at least one concrete byte".into());
    }
    Ok(out)
}

/// Encodings of a number: (bytes, label like "u32 le").
fn number_patterns(q: &ByteQuery) -> Result<Vec<(Vec<u8>, String)>, String> {
    let raw: String = q
        .query
        .trim()
        .chars()
        .filter(|&c| c != '_' && c != ',')
        .collect();
    let orders: &[Order] = match q.endian {
        Some(Order::Little) => &[Order::Little],
        Some(Order::Big) => &[Order::Big],
        None => &[Order::Little, Order::Big],
    };
    let tag = |o: Order| if o == Order::Little { "le" } else { "be" };
    let mut out: Vec<(Vec<u8>, String)> = Vec::new();
    let (neg, body) = match raw.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, raw.as_str()),
    };
    let int: Option<i128> =
        if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
            i128::from_str_radix(h, 16).ok()
        } else if let Some(b) = body.strip_prefix("0b") {
            i128::from_str_radix(b, 2).ok()
        } else if body.chars().all(|c| c.is_ascii_digit()) && !body.is_empty() {
            body.parse::<i128>().ok()
        } else {
            None
        }
        .map(|v| if neg { -v } else { v });

    if let Some(v) = int {
        let widths: Vec<u8> = match q.width {
            Some(w) => vec![w],
            None => [2u8, 4, 8].into_iter().filter(|&w| fits(v, w)).collect(),
        };
        if widths.is_empty() || widths.iter().any(|&w| !fits(v, w)) {
            return Err(match q.width {
                Some(w) => format!(
                    "{} doesn't fit in {} bits",
                    q.query.trim(),
                    u32::from(w) * 8
                ),
                None => format!("{} is too large (max 64-bit)", q.query.trim()),
            });
        }
        for w in widths {
            let le = (v as u128).to_le_bytes();
            for &o in orders {
                let mut b = le[..w as usize].to_vec();
                if o == Order::Big {
                    b.reverse();
                }
                let kind = if v < 0 { "i" } else { "u" };
                let label = if w == 1 {
                    format!("{kind}8")
                } else {
                    format!("{kind}{} {}", u32::from(w) * 8, tag(o))
                };
                if !out.iter().any(|(x, _)| *x == b) {
                    out.push((b, label));
                }
            }
        }
        return Ok(out);
    }
    let f: f64 = raw.parse().map_err(|_| {
        format!(
            "`{}` isn't a number (try 4096, 0x1f, -1 or 3.14)",
            q.query.trim()
        )
    })?;
    if !f.is_finite() {
        return Err("number must be finite".into());
    }
    let want32 = q.width.is_none_or(|w| w == 4);
    let want64 = q.width.is_none_or(|w| w == 8);
    if !want32 && !want64 {
        return Err("decimals can be searched as 32- or 64-bit floats only".into());
    }
    // `3.14f` in source is stored as the nearest f32, so both are useful.
    for &o in orders {
        if want32 {
            let v = f as f32;
            let b = if o == Order::Little {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            };
            out.push((b.to_vec(), format!("f32 {}", tag(o))));
        }
        if want64 {
            let b = if o == Order::Little {
                f.to_le_bytes()
            } else {
                f.to_be_bytes()
            };
            out.push((b.to_vec(), format!("f64 {}", tag(o))));
        }
    }
    Ok(out)
}

fn fits(v: i128, w: u8) -> bool {
    let bits = u32::from(w) * 8;
    let umax = (1i128 << bits) - 1;
    let smin = -(1i128 << (bits - 1));
    v >= smin && v <= umax
}

#[derive(Debug, Clone)]
pub struct RawHit {
    /// Absolute offset in the searched buffer.
    pub offset: usize,
    pub len: usize,
    /// Which variant matched: encoding, number width, "hex", "regex".
    pub label: String,
}

#[derive(Debug, Default)]
pub struct ScanOut {
    pub hits: Vec<RawHit>,
    /// Number of matches (exact unless `capped`).
    pub total: usize,
    /// Stopped at `max_hits`; `total` is a lower bound.
    pub capped: bool,
    /// Ran out of time; `total` is a lower bound.
    pub timed_out: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Matches remembered (and counted) before stopping.
    pub max_hits: usize,
    pub deadline: Instant,
}

impl Limits {
    pub fn new(max_hits: usize, budget: Duration) -> Self {
        Limits {
            max_hits,
            deadline: Instant::now() + budget,
        }
    }
}

/// Run `c` over `data` restricted to the `[start, end)` ranges. Hits come
/// back sorted by offset; where variants hit the same offset only the
/// longest is kept (a u64 match hides the u32 inside it).
pub fn scan(data: &[u8], ranges: &[(usize, usize)], c: &Compiled, lim: Limits) -> ScanOut {
    let mut out = ScanOut::default();
    'pats: for (re, label) in &c.pats {
        for &(lo, hi) in ranges {
            let (lo, hi) = (lo.min(data.len()), hi.min(data.len()));
            if lo >= hi {
                continue;
            }
            for (n, m) in re.find_iter(&data[lo..hi]).enumerate() {
                if m.is_empty() {
                    continue;
                }
                out.hits.push(RawHit {
                    offset: lo + m.start(),
                    len: m.len(),
                    label: label.clone(),
                });
                if out.hits.len() >= lim.max_hits {
                    out.capped = true;
                    break 'pats;
                }
                if n % 4096 == 4095 && Instant::now() > lim.deadline {
                    out.timed_out = true;
                    break 'pats;
                }
            }
            if Instant::now() > lim.deadline {
                out.timed_out = true;
                break 'pats;
            }
        }
    }
    out.hits
        .sort_unstable_by(|a, b| a.offset.cmp(&b.offset).then(b.len.cmp(&a.len)));
    out.hits.dedup_by_key(|h| h.offset);
    out.total = out.hits.len();
    out
}

/// Where to search in a loaded program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    All,
    Code,
    Data,
    Section(String),
}

impl Scope {
    pub fn parse(s: &str) -> Scope {
        match s {
            "" | "all" | "file" => Scope::All,
            "code" => Scope::Code,
            "data" => Scope::Data,
            other => Scope::Section(other.strip_prefix("section:").unwrap_or(other).to_string()),
        }
    }
}

/// File-offset ranges (absolute in the blob) for `scope`.
pub fn scope_ranges(
    data_len: usize,
    img: Option<&Image>,
    scope: &Scope,
) -> Result<Vec<(usize, usize)>, String> {
    let Some(img) = img else {
        return match scope {
            Scope::All => Ok(vec![(0, data_len)]),
            _ => Err("this file has no sections to narrow the search to".into()),
        };
    };
    let base = img.slice_offset;
    let to_abs = |off: u64, len: u64| -> Option<(usize, usize)> {
        let s = base.checked_add(usize::try_from(off).ok()?)?;
        let e = s.checked_add(usize::try_from(len).ok()?)?.min(data_len);
        (s < e).then_some((s, e))
    };
    let code: Vec<(u64, u64)> = img.code.iter().map(|c| (c.start, c.end)).collect();
    let is_code = |va: u64, size: u64| {
        code.iter()
            .any(|&(s, e)| va < e && va.saturating_add(size.max(1)) > s)
    };
    let mut v: Vec<(usize, usize)> = match scope {
        Scope::All => return Ok(vec![(0, data_len)]),
        Scope::Code => img
            .code
            .iter()
            .filter_map(|c| {
                let off = img.va_to_offset(c.start)?;
                let len = img
                    .read(c.start, usize::MAX)?
                    .len()
                    .min(usize::try_from(c.end.saturating_sub(c.start)).ok()?);
                to_abs(off, len as u64)
            })
            .collect(),
        Scope::Data => img
            .sections
            .iter()
            .filter(|s| s.file_size > 0 && !is_code(s.vaddr.0, s.vsize))
            .filter_map(|s| to_abs(s.file_offset, s.file_size))
            .collect(),
        Scope::Section(name) => {
            let v: Vec<_> = img
                .sections
                .iter()
                .filter(|s| s.name == *name && s.file_size > 0)
                .filter_map(|s| to_abs(s.file_offset, s.file_size))
                .collect();
            if v.is_empty() {
                return Err(format!("no section named `{name}` with file contents"));
            }
            v
        }
    };
    v.sort_unstable();
    // Merge overlaps so a byte is never searched (or reported) twice.
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match merged.last_mut() {
            Some(l) if s <= l.1 => l.1 = l.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    Ok(merged)
}

/// Printable rendering of bytes: ASCII as is, everything else as `·`.
pub fn printable(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if (0x20..0x7f).contains(&c) {
                c as char
            } else {
                '·'
            }
        })
        .collect()
}

/// Human-readable text of a match (UTF-16 decoded when that's what matched).
pub fn match_text(data: &[u8], h: &RawHit) -> String {
    let end = (h.offset + h.len.min(320)).min(data.len());
    let m = &data[h.offset.min(end)..end];
    let wide = |be: bool| {
        let units: Vec<u16> = m
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| {
                if be {
                    u16::from_be_bytes([p[0], p[1]])
                } else {
                    u16::from_le_bytes([p[0], p[1]])
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
            .chars()
            .map(|c| if c.is_control() { '·' } else { c })
            .collect()
    };
    match h.label.as_str() {
        "utf-16le" => wide(false),
        "utf-16be" => wide(true),
        "utf-8" => String::from_utf8_lossy(m)
            .chars()
            .map(|c| if c.is_control() { '·' } else { c })
            .collect(),
        _ => printable(m),
    }
}

// ---------------------------------------------------------- instruction search

/// One instruction line used for matching: `mnemonic operands ; comment`.
pub fn insn_line(mnemonic: &str, operands: &str, comment: Option<&str>) -> String {
    let mut s = String::with_capacity(mnemonic.len() + operands.len() + 16);
    s += mnemonic;
    if !operands.is_empty() {
        s.push(' ');
        s += operands;
    }
    if let Some(c) = comment.filter(|c| !c.is_empty()) {
        s += " ; ";
        s += c;
    }
    s
}

/// Consecutive-instruction pattern. Parts are separated by `;` or newlines.
/// Without `regex`, `*` matches anything and everything else is literal.
#[derive(Debug)]
pub struct InsnPattern {
    parts: Vec<regex::Regex>,
}

impl InsnPattern {
    pub fn compile(src: &str, regex: bool, case_sensitive: bool) -> Result<Self, String> {
        // `;` also starts the comment part of a line, so `; ;` would be
        // ambiguous: split on `;` only when followed by whitespace or end,
        // and always on newlines.
        let mut parts = Vec::new();
        for line in src.split('\n') {
            for p in split_parts(line) {
                let p = p.trim();
                if p.is_empty() {
                    continue;
                }
                let re_src = if regex {
                    p.to_string()
                } else {
                    let mut s = String::new();
                    let chunks: Vec<&str> = p.split('*').collect();
                    let n = chunks.len();
                    for (i, chunk) in chunks.into_iter().enumerate() {
                        if i > 0 {
                            s += ".*";
                        }
                        // Whole words at the ends: `0x1` doesn't match
                        // `0x10`, `xor` doesn't match `pxor`. Next to a `*`
                        // anything goes.
                        let t = chunk.trim_matches(|c: char| c.is_whitespace() || c == ',');
                        let word =
                            |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
                        let (pre, post) = (
                            i == 0 && word(t.chars().next()),
                            i + 1 == n && word(t.chars().last()),
                        );
                        if pre {
                            s += r"\b";
                        }
                        // Any run of spaces in the pattern matches any run in
                        // the listing ("mov  eax,1" == "mov eax, 1").
                        let words: Vec<String> = chunk
                            .split(|c: char| c.is_whitespace() || c == ',')
                            .filter(|w| !w.is_empty())
                            .map(number_word)
                            .collect();
                        s += &words.join(r"[\s,]+");
                        if post {
                            s += r"\b";
                        }
                    }
                    s
                };
                let re = regex::RegexBuilder::new(&re_src)
                    .case_insensitive(!case_sensitive)
                    .size_limit(8 << 20)
                    .build()
                    .map_err(|e| short_err(&e.to_string()))?;
                parts.push(re);
            }
        }
        if parts.is_empty() {
            return Err("type an instruction pattern, e.g. `call *malloc`".into());
        }
        if parts.len() > 16 {
            return Err("at most 16 instructions in a sequence".into());
        }
        Ok(InsnPattern { parts })
    }
    pub fn len(&self) -> usize {
        self.parts.len()
    }
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }
    /// Does the sequence match starting at `lines[i]`?
    pub fn matches_at(&self, lines: &[String], i: usize) -> bool {
        i + self.parts.len() <= lines.len()
            && self
                .parts
                .iter()
                .enumerate()
                .all(|(k, re)| re.is_match(&lines[i + k]))
    }
}

/// A pattern word; numbers match in either base with an optional `#`
/// (`0x10` ≡ `16` ≡ `#0x10`), since x86 listings print hex and AArch64 small
/// immediates print in decimal.
fn number_word(w: &str) -> String {
    let (neg, body) = match w.trim_start_matches('#').strip_prefix('-') {
        Some(b) => ("-", b),
        None => ("", w.trim_start_matches('#')),
    };
    let v = if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if !body.is_empty() && body.chars().all(|c| c.is_ascii_digit()) {
        body.parse::<u64>().ok()
    } else {
        None
    };
    match v {
        Some(v) => format!("#?{neg}(?:{v}|0x0*{v:x})"),
        None => regex::escape(w),
    }
}

fn split_parts(line: &str) -> Vec<&str> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    for (i, &c) in b.iter().enumerate() {
        if c == b';' && b.get(i + 1).is_none_or(|n| n.is_ascii_whitespace()) {
            out.push(&line[start..i]);
            start = i + 1;
        }
    }
    out.push(&line[start..]);
    out
}

#[derive(Debug, Clone)]
pub struct InsnHit {
    pub addr: u64,
    pub function: u64,
    pub lines: Vec<String>,
}

#[derive(Debug, Default)]
pub struct InsnOut {
    pub hits: Vec<InsnHit>,
    pub total: usize,
    pub capped: bool,
    pub timed_out: bool,
    pub functions_scanned: usize,
    pub instructions_scanned: u64,
}

/// Search the disassembly of every function (or only `only`) for `pat`.
/// Functions are independent, so the work is spread over up to 8 threads
/// (rendering AArch64 text through Capstone dominates the cost).
pub fn search_insns(
    img: &Image,
    a: &Analysis,
    namer: &(dyn Fn(u64) -> Option<String> + Sync),
    pat: &InsnPattern,
    only: Option<u64>,
    lim: Limits,
) -> InsnOut {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let funcs: Vec<&Func> = match only {
        Some(e) => a.function_containing(e).into_iter().collect(),
        None => a.functions.iter().collect(),
    };
    const CHUNK: usize = 1024;
    let next = AtomicUsize::new(0);
    let found = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let timed_out = AtomicBool::new(false);
    let merged = Mutex::new(InsnOut::default());
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, 8)
        .min(funcs.len().div_ceil(CHUNK).max(1));
    let work = || {
        let mut local = InsnOut::default();
        let mut lines: Vec<String> = Vec::new();
        let mut addrs: Vec<u64> = Vec::new();
        'outer: loop {
            let i = next.fetch_add(CHUNK, Ordering::Relaxed);
            if i >= funcs.len() || stop.load(Ordering::Relaxed) {
                break;
            }
            for f in &funcs[i..(i + CHUNK).min(funcs.len())] {
                if stop.load(Ordering::Relaxed) {
                    break 'outer;
                }
                if Instant::now() > lim.deadline {
                    timed_out.store(true, Ordering::Relaxed);
                    stop.store(true, Ordering::Relaxed);
                    break 'outer;
                }
                lines.clear();
                addrs.clear();
                for &(lo, hi) in f.ranges.iter() {
                    let mut at = lo;
                    while at < hi {
                        let chunk = crate::render::disasm_bounded(img, at, 2048, hi, namer);
                        let Some(last) = chunk.last() else { break };
                        let next_at = last.addr.0 + u64::from(last.size.max(1));
                        for ins in chunk {
                            lines.push(insn_line(
                                &ins.mnemonic,
                                &ins.operands,
                                ins.comment.as_deref(),
                            ));
                            addrs.push(ins.addr.0);
                        }
                        if next_at <= at {
                            break;
                        }
                        at = next_at;
                    }
                }
                local.functions_scanned += 1;
                local.instructions_scanned += lines.len() as u64;
                let mut k = 0;
                while k < lines.len() {
                    if pat.matches_at(&lines, k) {
                        local.hits.push(InsnHit {
                            addr: addrs[k],
                            function: f.entry,
                            lines: lines[k..k + pat.len()].to_vec(),
                        });
                        if found.fetch_add(1, Ordering::Relaxed) + 1 >= lim.max_hits {
                            stop.store(true, Ordering::Relaxed);
                            break 'outer;
                        }
                        k += pat.len();
                    } else {
                        k += 1;
                    }
                }
            }
        }
        if let Ok(mut m) = merged.lock() {
            m.functions_scanned += local.functions_scanned;
            m.instructions_scanned += local.instructions_scanned;
            m.hits.append(&mut local.hits);
        }
    };
    if threads <= 1 {
        work();
    } else {
        std::thread::scope(|sc| {
            for _ in 0..threads {
                sc.spawn(work);
            }
        });
    }
    let mut out = merged.into_inner().unwrap_or_default();
    out.hits.sort_unstable_by_key(|h| h.addr);
    out.capped = out.hits.len() >= lim.max_hits;
    out.hits.truncate(lim.max_hits);
    out.total = out.hits.len();
    out.timed_out = timed_out.load(Ordering::Relaxed);
    out
}

// ------------------------------------------------------------ function query

#[derive(Debug)]
enum Text {
    Sub(String),
    Re(regex::Regex),
}

impl Text {
    fn parse(v: &str) -> Result<Text, String> {
        if v.len() >= 2 && v.starts_with('/') && v.ends_with('/') {
            let re = regex::RegexBuilder::new(&v[1..v.len() - 1])
                .case_insensitive(true)
                .size_limit(4 << 20)
                .build()
                .map_err(|e| short_err(&e.to_string()))?;
            Ok(Text::Re(re))
        } else {
            Ok(Text::Sub(v.to_lowercase()))
        }
    }
    fn is(&self, s: &str) -> bool {
        match self {
            Text::Sub(n) => n.is_empty() || s.to_lowercase().contains(n.as_str()),
            Text::Re(r) => r.is_match(s),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Field {
    Size,
    Blocks,
    Insns,
    Calls,
    Callers,
    Complexity,
    Edges,
}

#[derive(Debug, Clone, Copy)]
enum Op {
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
}

#[derive(Debug, Clone, Copy)]
enum Flag {
    Thunk,
    NoReturn,
    Leaf,
    Unreferenced,
    Renamed,
    Named,
    Recursive,
}

#[derive(Debug)]
enum Term {
    NameOrAddr(Text),
    Name(Text),
    Calls(Text),
    CalledBy(Text),
    Str(Text),
    Refs(Text),
    Section(Text),
    Cmp(Field, Op, u64),
    Is(Flag),
}

impl Term {
    /// Rough cost; cheap terms run first.
    fn cost(&self) -> u8 {
        match self {
            Term::Cmp(..) | Term::Is(_) => 0,
            Term::NameOrAddr(_) | Term::Name(_) | Term::Section(_) => 1,
            Term::Calls(_) | Term::CalledBy(_) => 2,
            Term::Str(_) | Term::Refs(_) => 3,
        }
    }
}

/// Parsed function query. Terms are ANDed; `-term` negates.
#[derive(Debug, Default)]
pub struct FnQuery {
    terms: Vec<(bool, Term)>,
}

/// What a function query may look at besides the function itself.
pub struct FnCtx<'a> {
    pub analysis: &'a Analysis,
    pub image: Option<&'a Image>,
    /// Sorted by address.
    pub strings: &'a [StringRef],
    /// Display name for any address (renames first).
    pub name_of: &'a dyn Fn(u64) -> Option<String>,
    pub is_renamed: &'a dyn Fn(u64) -> bool,
}

/// Split respecting double quotes and `/regex/` (which may contain spaces).
fn tokens(q: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote = false;
    let mut slash = false;
    let mut prev = ' ';
    for ch in q.chars() {
        match ch {
            '"' if !slash => quote = !quote,
            '/' if !quote
                && (prev == ':' || prev == ' ' || prev == '-' || cur.is_empty())
                && !slash =>
            {
                slash = true;
                cur.push(ch);
            }
            '/' if slash && prev != '\\' => {
                slash = false;
                cur.push(ch);
            }
            c if c.is_whitespace() && !quote && !slash => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
        prev = ch;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim().replace('_', "");
    let (s, mul) = match s.to_ascii_lowercase() {
        x if x.ends_with('k') => (x[..x.len() - 1].to_string(), 1024),
        x => (x, 1),
    };
    let v = if let Some(h) = s.strip_prefix("0x") {
        u64::from_str_radix(h, 16).ok()?
    } else {
        s.parse().ok()?
    };
    v.checked_mul(mul)
}

impl FnQuery {
    pub fn parse(q: &str) -> Result<FnQuery, String> {
        let mut terms = Vec::new();
        for tok in tokens(q) {
            let (neg, t) = match tok.strip_prefix('-') {
                Some(r) if !r.is_empty() => (true, r.to_string()),
                _ => (false, tok.clone()),
            };
            terms.push((neg, Self::term(&t)?));
        }
        terms.sort_by_key(|(_, t)| t.cost());
        Ok(FnQuery { terms })
    }

    fn term(t: &str) -> Result<Term, String> {
        // field OP number, e.g. size>200, callers=0, blocks<=3, size:>1k
        let field = |k: &str| -> Option<Field> {
            Some(match k {
                "size" | "bytes" => Field::Size,
                "blocks" | "bb" => Field::Blocks,
                "insns" | "instructions" => Field::Insns,
                "ncalls" | "calls" | "callees" => Field::Calls,
                "ncallers" | "callers" | "xrefs" => Field::Callers,
                "complexity" | "cc" | "cyclomatic" => Field::Complexity,
                "edges" => Field::Edges,
                _ => return None,
            })
        };
        if let Some(p) = t.find(['>', '<', '=']) {
            let key = t[..p].trim_end_matches(':').to_ascii_lowercase();
            let rest = &t[p..];
            let (op, n) = if let Some(r) = rest.strip_prefix(">=") {
                (Op::Ge, r)
            } else if let Some(r) = rest.strip_prefix("<=") {
                (Op::Le, r)
            } else if let Some(r) = rest.strip_prefix('>') {
                (Op::Gt, r)
            } else if let Some(r) = rest.strip_prefix('<') {
                (Op::Lt, r)
            } else {
                (Op::Eq, rest.trim_start_matches('='))
            };
            if let Some(f) = field(&key) {
                let v = parse_num(n).ok_or_else(|| format!("`{n}` in `{t}` isn't a number"))?;
                return Ok(Term::Cmp(f, op, v));
            }
        }
        if let Some((k, v)) = t.split_once(':') {
            let k = k.to_ascii_lowercase();
            // `size:100`, `callers:0`: equality. `calls:`/`callers:` take a
            // name unless the value is all digits.
            if let Some(f) = field(&k) {
                let names_too = matches!(k.as_str(), "calls" | "callers");
                if !names_too || (!v.is_empty() && v.chars().all(|c| c.is_ascii_digit())) {
                    let n = parse_num(v).ok_or_else(|| format!("`{v}` in `{t}` isn't a number"))?;
                    return Ok(Term::Cmp(f, Op::Eq, n));
                }
            }
            let txt = || Text::parse(v);
            return Ok(match k.as_str() {
                "name" | "n" => Term::Name(txt()?),
                "calls" | "call" | "callee" => Term::Calls(txt()?),
                "callers" | "caller" | "calledby" | "called_by" | "from" => Term::CalledBy(txt()?),
                "str" | "string" | "strings" => Term::Str(txt()?),
                "refs" | "ref" | "uses" => Term::Refs(txt()?),
                "section" | "sect" | "in" => Term::Section(txt()?),
                "is" | "has" => Term::Is(match v.to_ascii_lowercase().as_str() {
                    "thunk" | "stub" => Flag::Thunk,
                    "noreturn" => Flag::NoReturn,
                    "leaf" => Flag::Leaf,
                    "unreferenced" | "orphan" | "unused" => Flag::Unreferenced,
                    "renamed" => Flag::Renamed,
                    "named" | "symbol" => Flag::Named,
                    "recursive" => Flag::Recursive,
                    other => {
                        return Err(format!(
                            "unknown flag `is:{other}` (thunk, noreturn, leaf, unreferenced, renamed, named, recursive)"
                        ));
                    }
                }),
                _ => Term::NameOrAddr(Text::parse(t)?),
            });
        }
        Ok(Term::NameOrAddr(Text::parse(t)?))
    }

    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    /// Does `f` (shown as `name`) match every term?
    pub fn matches(&self, f: &Func, name: &str, cx: &FnCtx) -> bool {
        self.terms
            .iter()
            .all(|(neg, t)| Self::eval(t, f, name, cx) != *neg)
    }

    fn eval(t: &Term, f: &Func, name: &str, cx: &FnCtx) -> bool {
        let named = |a: u64| (cx.name_of)(a).unwrap_or_default();
        match t {
            Term::NameOrAddr(x) => x.is(name) || x.is(&format!("{:#x}", f.entry)),
            Term::Name(x) => x.is(name),
            Term::Calls(x) => f.calls.iter().any(|&c| x.is(&named(c))),
            Term::CalledBy(x) => f.called_by.iter().any(|&c| {
                let n = cx
                    .analysis
                    .function_containing(c)
                    .map(|g| named(g.entry))
                    .unwrap_or_else(|| named(c));
                x.is(&n)
            }),
            Term::Str(x) => f.ranges.iter().any(|&(lo, hi)| {
                cx.analysis.xrefs_from(lo, hi).iter().any(|r| {
                    cx.strings
                        .binary_search_by_key(&r.to, |s| s.addr.0)
                        .is_ok_and(|i| x.is(&cx.strings[i].value))
                })
            }),
            Term::Refs(x) => f.ranges.iter().any(|&(lo, hi)| {
                cx.analysis
                    .xrefs_from(lo, hi)
                    .iter()
                    .any(|r| x.is(&named(r.to)))
            }),
            Term::Section(x) => cx
                .image
                .and_then(|i| i.section_name(f.entry))
                .is_some_and(|s| x.is(s)),
            Term::Cmp(fl, op, v) => {
                let have = match fl {
                    Field::Size => f.size,
                    Field::Blocks => u64::from(f.nblocks),
                    Field::Insns => u64::from(f.insns),
                    Field::Calls => f.calls.len() as u64,
                    Field::Callers => f.called_by.len() as u64,
                    Field::Complexity => u64::from(f.cyclomatic()),
                    Field::Edges => u64::from(f.nedges),
                };
                match op {
                    Op::Gt => have > *v,
                    Op::Ge => have >= *v,
                    Op::Lt => have < *v,
                    Op::Le => have <= *v,
                    Op::Eq => have == *v,
                }
            }
            Term::Is(fl) => match fl {
                Flag::Thunk => f.is_thunk,
                Flag::NoReturn => f.noreturn,
                Flag::Leaf => f.calls.is_empty(),
                Flag::Unreferenced => f.called_by.is_empty(),
                Flag::Renamed => (cx.is_renamed)(f.entry),
                Flag::Named => !matches!(f.name_source, NameSource::Engine),
                Flag::Recursive => f.calls.contains(&f.entry),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(q: &ByteQuery, data: &[u8]) -> Vec<(usize, String)> {
        let c = compile(q).unwrap();
        scan(
            data,
            &[(0, data.len())],
            &c,
            Limits::new(1000, Duration::from_secs(5)),
        )
        .hits
        .into_iter()
        .map(|h| (h.offset, h.label))
        .collect()
    }

    #[test]
    fn text_case_and_utf16() {
        let mut d = b"xxPassWord..".to_vec();
        d.extend("pass".encode_utf16().flat_map(|u| u.to_le_bytes()));
        d.extend("PASS".encode_utf16().flat_map(|u| u.to_be_bytes()));
        let mut q = ByteQuery::new(Mode::Text, "pass");
        assert_eq!(
            run(&q, &d),
            vec![(2, "utf-8".into()), (12, "utf-16le".into())]
        );
        q.encodings = vec![Enc::Utf16Be];
        assert_eq!(run(&q, &d), vec![(20, "utf-16be".into())]);
        q.encodings = vec![];
        q.case_sensitive = true;
        q.query = "Pass".into();
        assert_eq!(run(&q, &d).len(), 1);
    }

    #[test]
    fn hex_yara_syntax() {
        let d = [0x48u8, 0x8b, 0x05, 0x10, 0x90, 0xcc, 0x41, 0x42, 0x43, 0xc3];
        let h = |p: &str| run(&ByteQuery::new(Mode::Hex, p), &d);
        assert_eq!(h("48 8b ?? 10").len(), 1);
        assert_eq!(h("48 8? 0? 10").len(), 1);
        assert_eq!(h("?8 8b").len(), 1);
        assert_eq!(h("48 [3] 90").len(), 1);
        assert_eq!(h("48 [2] 90").len(), 0);
        assert_eq!(h("48 [1-3] 90").len(), 1);
        assert_eq!(h("48 [3-] c3").len(), 1);
        assert_eq!(h("( 41 | 42 ) 43").len(), 1);
        assert_eq!(h("90 ~cd").len(), 1);
        assert_eq!(h("90 ~cc").len(), 0);
        assert!(compile(&ByteQuery::new(Mode::Hex, "?? ??")).is_err());
        assert!(compile(&ByteQuery::new(Mode::Hex, "4")).is_err());
        assert!(compile(&ByteQuery::new(Mode::Hex, "zz")).is_err());
        assert!(compile(&ByteQuery::new(Mode::Hex, "(41")).is_err());
    }

    #[test]
    fn numbers() {
        let mut d = vec![0u8; 4];
        d.extend(0xdeadbeefu32.to_le_bytes());
        d.extend(0xdeadbeefu32.to_be_bytes());
        d.extend(4096u64.to_le_bytes());
        d.extend(1.5f64.to_le_bytes());
        let mut q = ByteQuery::new(Mode::Number, "0xdeadbeef");
        assert_eq!(run(&q, &d), vec![(4, "u32 le".into())]);
        q.endian = None;
        assert_eq!(run(&q, &d).len(), 2);
        // 4096 as u64 hides the u16/u32 at the same offset.
        let q = ByteQuery::new(Mode::Number, "4096");
        assert_eq!(run(&q, &d), vec![(12, "u64 le".into())]);
        let q = ByteQuery::new(Mode::Number, "1.5");
        assert_eq!(run(&q, &d), vec![(20, "f64 le".into())]);
        let mut q = ByteQuery::new(Mode::Number, "70000");
        q.width = Some(2);
        assert!(compile(&q).is_err());
        assert!(compile(&ByteQuery::new(Mode::Number, "abc")).is_err());
        let d = (-2i32).to_le_bytes();
        assert_eq!(
            run(&ByteQuery::new(Mode::Number, "-2"), &d),
            vec![(0, "i32 le".into())]
        );
    }

    #[test]
    fn regex_bytes_and_ranges() {
        let d = b"see https://example.com/a and HTTP://x.org ok";
        let q = ByteQuery::new(Mode::Regex, r"https?://[a-z.]+");
        assert_eq!(run(&q, d).len(), 2);
        let c = compile(&q).unwrap();
        let r = scan(d, &[(0, 20)], &c, Limits::new(10, Duration::from_secs(1)));
        assert_eq!(r.total, 1);
        let r = scan(
            d,
            &[(0, d.len())],
            &c,
            Limits::new(1, Duration::from_secs(1)),
        );
        assert!(r.capped);
        assert!(compile(&ByteQuery::new(Mode::Regex, "(")).is_err());
    }

    #[test]
    fn insn_patterns() {
        let lines: Vec<String> = ["mov edi, 0x10", "call 0x1000 ; malloc", "test rax, rax"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let p = InsnPattern::compile("mov edi, *; call *malloc", false, false).unwrap();
        assert!(p.matches_at(&lines, 0));
        assert!(!p.matches_at(&lines, 1));
        let p = InsnPattern::compile("TEST  RAX,RAX", false, false).unwrap();
        assert!(p.matches_at(&lines, 2));
        let p = InsnPattern::compile("mov edi, 0x1", false, false).unwrap();
        assert!(!p.matches_at(&lines, 0));
        let p = InsnPattern::compile("mov edi, 0x10", false, false).unwrap();
        assert!(p.matches_at(&lines, 0));
        let p = InsnPattern::compile("mov edi, 16", false, false).unwrap();
        assert!(p.matches_at(&lines, 0));
        let a64: Vec<String> = vec!["mov w0, #1".into()];
        assert!(
            InsnPattern::compile("mov w0, 0x1", false, false)
                .unwrap()
                .matches_at(&a64, 0)
        );
        assert!(
            !InsnPattern::compile("mov w0, 0x10", false, false)
                .unwrap()
                .matches_at(&a64, 0)
        );
        let p = InsnPattern::compile("call *alloc", false, false).unwrap();
        assert!(p.matches_at(&lines, 1));
        let p = InsnPattern::compile(r"^call\b", true, false).unwrap();
        assert!(p.matches_at(&lines, 1));
        assert!(InsnPattern::compile("  ", false, false).is_err());
    }

    #[test]
    fn fn_query_parse() {
        assert!(FnQuery::parse("calls:malloc size>200 -is:thunk").is_ok());
        assert!(FnQuery::parse("size>1k callers=0 name:/^sub_/").is_ok());
        assert!(FnQuery::parse("calls:\"Sec Item\"").is_ok());
        assert!(FnQuery::parse("size>abc").is_err());
        assert!(FnQuery::parse("is:bogus").is_err());
        assert!(FnQuery::parse("name:/(/").is_err());
        assert_eq!(
            tokens(r#"a:"b c" name:/x y/ -d"#),
            vec!["a:b c", "name:/x y/", "-d"]
        );
    }
}
