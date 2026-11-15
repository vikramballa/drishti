//! PDF provenance and safety triage (spec §7.1 "pdfid-style PDF triage").
//!
//! Answers two questions for people who are not PDF experts:
//! *where did this document come from?* (software, device, author, dates,
//! edits, signatures, time zone, paper size) and *is it safe to open?*
//! (scripts, auto-run actions, attachments, external launches).
//!
//! The parser is deliberately tolerant and bounded: it scans for `N G obj`
//! headers instead of trusting the cross-reference table (which is often
//! broken or hostile), decompresses only object streams and the XMP packet
//! (never page content), and caps every size, count and recursion depth.
//! It never renders or executes the document.

use drishti_model::{
    Confidence, DocFeature, DocSignature, DocumentReport, HistoryEvent, MetaField, OriginClue,
    Severity,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;

const MAX_DEPTH: usize = 48;
const MAX_ITEMS: usize = 20_000;
const MAX_STRING: usize = 1 << 20;
const MAX_OBJECTS: usize = 400_000;
const MAX_OBJSTM_OUT: usize = 16 << 20;
const MAX_OBJSTM_TOTAL: usize = 96 << 20;
const MAX_XMP: usize = 4 << 20;
const MAX_LIST: usize = 200;

// ---------------------------------------------------------------- objects

#[derive(Debug, Clone)]
enum Obj {
    Null,
    Bool,
    Num(f64),
    Name(String),
    Str(Vec<u8>),
    Arr(Vec<Obj>),
    Dict(Vec<(String, Obj)>),
    Ref(u32),
}

impl Obj {
    fn get(&self, k: &str) -> Option<&Obj> {
        match self {
            Obj::Dict(d) => d.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v),
            _ => None,
        }
    }
    fn name(&self) -> Option<&str> {
        match self {
            Obj::Name(n) => Some(n),
            _ => None,
        }
    }
    fn is_name(&self, n: &str) -> bool {
        self.name() == Some(n)
    }
    fn num(&self) -> Option<f64> {
        match self {
            Obj::Num(n) => Some(*n),
            _ => None,
        }
    }
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Obj::Str(s) => Some(s),
            _ => None,
        }
    }
    fn text(&self) -> Option<String> {
        self.bytes().map(decode_text).filter(|s| !s.is_empty())
    }
    fn reference(&self) -> Option<u32> {
        match self {
            Obj::Ref(n) => Some(*n),
            _ => None,
        }
    }
    fn dict_keys(&self) -> impl Iterator<Item = &str> {
        let d: &[(String, Obj)] = match self {
            Obj::Dict(d) => d,
            _ => &[],
        };
        d.iter().map(|(k, _)| k.as_str())
    }
    /// The `/Type` name, or `/S` (action type) when there is no type.
    fn type_is(&self, t: &str) -> bool {
        self.get("Type").is_some_and(|v| v.is_name(t))
    }
    /// Names in a `/Filter` value (single name or array).
    fn filters(&self) -> Vec<&str> {
        match self.get("Filter") {
            Some(Obj::Name(n)) => vec![n.as_str()],
            Some(Obj::Arr(a)) => a.iter().filter_map(Obj::name).collect(),
            _ => Vec::new(),
        }
    }
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' | b'\0')
}
fn is_delim(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn new(b: &'a [u8], i: usize) -> Self {
        Parser { b, i }
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if is_ws(c) {
                self.i += 1;
            } else if c == b'%' {
                while let Some(c) = self.peek() {
                    if c == b'\r' || c == b'\n' {
                        break;
                    }
                    self.i += 1;
                }
            } else {
                break;
            }
        }
    }
    fn starts(&self, kw: &[u8]) -> bool {
        self.b.get(self.i..).is_some_and(|r| r.starts_with(kw))
    }
    /// A bare keyword (regular characters up to whitespace or a delimiter).
    fn word(&mut self) -> &'a [u8] {
        let s = self.i;
        while let Some(c) = self.peek() {
            if is_ws(c) || is_delim(c) {
                break;
            }
            self.i += 1;
        }
        &self.b[s..self.i]
    }

    fn object(&mut self, depth: usize) -> Option<Obj> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.skip_ws();
        let c = self.peek()?;
        match c {
            b'/' => {
                self.i += 1;
                Some(Obj::Name(self.name_body()))
            }
            b'(' => {
                self.i += 1;
                Some(Obj::Str(self.literal()))
            }
            b'<' if self.b.get(self.i + 1) == Some(&b'<') => {
                self.i += 2;
                let mut d = Vec::new();
                loop {
                    self.skip_ws();
                    match self.peek() {
                        None => break,
                        Some(b'>') => {
                            self.i += if self.starts(b">>") { 2 } else { 1 };
                            break;
                        }
                        Some(b'/') => {
                            self.i += 1;
                            let k = self.name_body();
                            let v = self.object(depth + 1).unwrap_or(Obj::Null);
                            if d.len() < MAX_ITEMS {
                                d.push((k, v));
                            }
                        }
                        Some(_) => {
                            // Junk inside a dictionary: skip one token.
                            let before = self.i;
                            if self.object(depth + 1).is_none() || self.i == before {
                                self.i += 1;
                            }
                        }
                    }
                }
                Some(Obj::Dict(d))
            }
            b'<' => {
                self.i += 1;
                Some(Obj::Str(self.hex()))
            }
            b'[' => {
                self.i += 1;
                let mut a = Vec::new();
                loop {
                    self.skip_ws();
                    match self.peek() {
                        None => break,
                        Some(b']') => {
                            self.i += 1;
                            break;
                        }
                        Some(_) => {
                            let before = self.i;
                            match self.object(depth + 1) {
                                Some(o) if a.len() < MAX_ITEMS => a.push(o),
                                Some(_) => {}
                                None => {
                                    if self.i == before {
                                        self.i += 1;
                                    }
                                }
                            }
                        }
                    }
                }
                Some(Obj::Arr(a))
            }
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                let n = self.number()?;
                // `N G R` reference?
                if n.fract() == 0.0 && n >= 0.0 && n <= f64::from(u32::MAX) {
                    let save = self.i;
                    self.skip_ws();
                    let gs = self.i;
                    while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                        self.i += 1;
                    }
                    if self.i > gs && self.i - gs <= 5 {
                        self.skip_ws();
                        if self.peek() == Some(b'R')
                            && self
                                .b
                                .get(self.i + 1)
                                .is_none_or(|&c| is_ws(c) || is_delim(c))
                        {
                            self.i += 1;
                            return Some(Obj::Ref(n as u32));
                        }
                    }
                    self.i = save;
                }
                Some(Obj::Num(n))
            }
            b')' | b'>' | b']' | b'}' | b'{' => {
                self.i += 1;
                None
            }
            _ => {
                let w = self.word();
                match w {
                    b"true" | b"false" => Some(Obj::Bool),
                    b"null" => Some(Obj::Null),
                    [] => {
                        self.i += 1;
                        None
                    }
                    _ => None,
                }
            }
        }
    }

    fn number(&mut self) -> Option<f64> {
        let s = self.i;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || matches!(c, b'+' | b'-' | b'.') {
                self.i += 1;
            } else {
                break;
            }
        }
        let t = std::str::from_utf8(&self.b[s..self.i]).ok()?;
        t.parse::<f64>().ok().or_else(|| {
            // Malformed numbers like "--5" or "1.2.3": keep the leading part.
            let lead: String = t
                .trim_start_matches(['+', '-'])
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            lead.split('.').next()?.parse::<f64>().ok()
        })
    }

    fn name_body(&mut self) -> String {
        let mut out = Vec::new();
        while let Some(c) = self.peek() {
            if is_ws(c) || is_delim(c) {
                break;
            }
            self.i += 1;
            if c == b'#'
                && let Some(h) = self.b.get(self.i..self.i + 2)
                && let Ok(v) = u8::from_str_radix(std::str::from_utf8(h).unwrap_or("zz"), 16)
            {
                // `#4A` escapes are a classic way to hide `/JavaScript`.
                out.push(v);
                self.i += 2;
                continue;
            }
            if out.len() < 256 {
                out.push(c);
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn literal(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut depth = 1usize;
        while let Some(c) = self.peek() {
            self.i += 1;
            match c {
                b'\\' => {
                    let Some(e) = self.peek() else { break };
                    self.i += 1;
                    let v = match e {
                        b'n' => Some(b'\n'),
                        b'r' => Some(b'\r'),
                        b't' => Some(b'\t'),
                        b'b' => Some(8),
                        b'f' => Some(12),
                        b'\r' => {
                            if self.peek() == Some(b'\n') {
                                self.i += 1;
                            }
                            None
                        }
                        b'\n' => None,
                        b'0'..=b'7' => {
                            let mut v = u32::from(e - b'0');
                            for _ in 0..2 {
                                match self.peek() {
                                    Some(d @ b'0'..=b'7') => {
                                        v = v * 8 + u32::from(d - b'0');
                                        self.i += 1;
                                    }
                                    _ => break,
                                }
                            }
                            Some((v & 0xff) as u8)
                        }
                        other => Some(other),
                    };
                    if let Some(v) = v
                        && out.len() < MAX_STRING
                    {
                        out.push(v);
                    }
                }
                b'(' => {
                    depth += 1;
                    if out.len() < MAX_STRING {
                        out.push(c);
                    }
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    if out.len() < MAX_STRING {
                        out.push(c);
                    }
                }
                _ => {
                    if out.len() < MAX_STRING {
                        out.push(c);
                    }
                }
            }
        }
        out
    }

    fn hex(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut hi: Option<u8> = None;
        while let Some(c) = self.peek() {
            self.i += 1;
            if c == b'>' {
                break;
            }
            let v = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => continue,
            };
            match hi.take() {
                None => hi = Some(v),
                Some(h) => {
                    if out.len() < MAX_STRING {
                        out.push(h << 4 | v);
                    }
                }
            }
        }
        if let Some(h) = hi
            && out.len() < MAX_STRING
        {
            out.push(h << 4);
        }
        out
    }
}

/// PDF text string → Rust string (UTF-16BE with BOM, UTF-8 with BOM, or
/// PDFDocEncoding, approximated as Latin-1).
fn decode_text(b: &[u8]) -> String {
    let s = if let Some(r) = b.strip_prefix(&[0xfe, 0xff]) {
        let u: Vec<u16> = r
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u)
    } else if let Some(r) = b.strip_prefix(&[0xff, 0xfe]) {
        let u: Vec<u16> = r
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u)
    } else if let Some(r) = b.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        String::from_utf8_lossy(r).into_owned()
    } else if let Ok(s) = std::str::from_utf8(b) {
        s.to_string()
    } else {
        b.iter().map(|&c| c as char).collect()
    };
    let clean: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect::<String>()
        .trim()
        .to_string();
    clip(&clean, 2000)
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

// ---------------------------------------------------------------- scanning

fn find(h: &[u8], n: &[u8], from: usize) -> Option<usize> {
    if n.is_empty() || from >= h.len() {
        return None;
    }
    h.get(from..)?
        .windows(n.len())
        .position(|w| w == n)
        .map(|p| p + from)
}

fn count(h: &[u8], n: &[u8]) -> usize {
    let mut c = 0;
    let mut i = 0;
    while let Some(p) = find(h, n, i) {
        c += 1;
        i = p + n.len();
    }
    c
}

/// Every `N G obj` header: (object number, offset just after `obj`).
fn object_headers(b: &[u8]) -> Vec<(u32, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = find(b, b"obj", i) {
        i = p + 3;
        // Must be followed by whitespace or a delimiter, not "objstm"/"object".
        if b.get(p + 3).is_some_and(|&c| !is_ws(c) && !is_delim(c)) {
            continue;
        }
        let mut j = p;
        let back_ws = |j: &mut usize| {
            let s = *j;
            while *j > 0 && is_ws(b[*j - 1]) {
                *j -= 1;
            }
            *j < s
        };
        if !back_ws(&mut j) {
            continue;
        }
        let ge = j;
        while j > 0 && b[j - 1].is_ascii_digit() && ge - j < 6 {
            j -= 1;
        }
        if j == ge {
            continue;
        }
        if !back_ws(&mut j) {
            continue;
        }
        let ne = j;
        while j > 0 && b[j - 1].is_ascii_digit() && ne - j < 10 {
            j -= 1;
        }
        if j == ne || (j > 0 && !is_ws(b[j - 1]) && !is_delim(b[j - 1])) {
            continue;
        }
        let Some(num) = std::str::from_utf8(&b[j..ne])
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        out.push((num, p + 3));
        if out.len() >= MAX_OBJECTS {
            break;
        }
    }
    out
}

/// Inflate a FlateDecode stream with an output cap. Truncated or corrupt
/// streams return whatever decoded before the error.
fn inflate(data: &[u8], cap: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut d = flate2::read::ZlibDecoder::new(data).take(cap as u64);
    let mut buf = [0u8; 16 << 10];
    loop {
        match d.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    if out.is_empty() {
        // Some writers emit raw deflate without the zlib header.
        let mut d = flate2::read::DeflateDecoder::new(data).take(cap as u64);
        loop {
            match d.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    }
    out
}

// ---------------------------------------------------------------- collection

#[derive(Default)]
struct Collect {
    info_versions: Vec<(u32, Vec<(String, String)>)>,
    trailers: Vec<Obj>,
    catalog: Option<Obj>,
    xmp: HashMap<u32, String>,
    xmp_any: Vec<String>,
    xmp_bytes: usize,
    pages_count: Option<u32>,
    page_objects: u32,
    first_mediabox: Option<(f64, f64)>,
    fonts: BTreeSet<String>,
    images: u32,
    links: Vec<String>,
    embedded: Vec<String>,
    sigs: Vec<DocSignature>,
    feat: BTreeMap<&'static str, u32>,
    open_action_script: bool,
    /// Small dictionaries reachable from the catalog's `/Names` (name trees),
    /// kept so document-level scripts can be resolved.
    name_dicts: HashMap<u32, Obj>,
    linearized: bool,
    objstm_total: usize,
    objstm_failed: u32,
    objects: usize,
}

impl Collect {
    fn bump(&mut self, k: &'static str) {
        *self.feat.entry(k).or_default() += 1;
    }

    /// Walk any object (recursing into arrays and dictionaries).
    fn walk(&mut self, o: &Obj, file_len: usize, depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        match o {
            Obj::Arr(a) => {
                for x in a {
                    self.walk(x, file_len, depth + 1);
                }
            }
            Obj::Dict(d) => {
                self.dict(o, file_len);
                for (_, v) in d {
                    self.walk(v, file_len, depth + 1);
                }
            }
            _ => {}
        }
    }

    fn dict(&mut self, o: &Obj, file_len: usize) {
        for k in o.dict_keys() {
            match k {
                "JS" => self.bump("javascript"),
                "AA" => self.bump("auto_action"),
                "OpenAction" => self.bump("open_action"),
                "AcroForm" => self.bump("form"),
                "XFA" => self.bump("xfa"),
                "EmbeddedFiles" => self.bump("embedded_file"),
                "Linearized" => self.linearized = true,
                _ => {}
            }
        }
        if let Some(s) = o.get("S").and_then(Obj::name) {
            match s {
                "JavaScript" => {
                    if o.get("JS").is_none() {
                        self.bump("javascript");
                    }
                }
                "Launch" => self.bump("launch"),
                "SubmitForm" => self.bump("submit_form"),
                "ImportData" => self.bump("import_data"),
                "GoToR" | "GoToE" => self.bump("remote_goto"),
                "URI" => {
                    if let Some(u) = o.get("URI").and_then(Obj::text)
                        && self.links.len() < MAX_LIST
                        && !self.links.contains(&u)
                    {
                        self.links.push(clip(&u, 500));
                    }
                }
                _ => {}
            }
        }
        if let Some(t) = o.get("Type").and_then(Obj::name) {
            match t {
                "Catalog" => {
                    if let Some(oa) = o.get("OpenAction")
                        && (oa.get("S").is_some_and(|s| s.is_name("JavaScript"))
                            || oa.get("JS").is_some()
                            || oa.reference().is_some())
                    {
                        // A reference may point at a script; a destination
                        // array (`[page /Fit]`) just opens a page.
                        self.open_action_script |= oa.reference().is_none();
                    }
                    self.catalog = Some(o.clone());
                }
                "Pages" => {
                    if o.get("Parent").is_none()
                        && let Some(n) = o.get("Count").and_then(Obj::num)
                        && n >= 0.0
                    {
                        self.pages_count = Some(n as u32);
                    }
                    if self.first_mediabox.is_none()
                        && o.get("Parent").is_none()
                        && let Some(mb) = mediabox(o)
                    {
                        self.first_mediabox = Some(mb);
                    }
                }
                "Page" => {
                    self.page_objects += 1;
                    if let Some(mb) = mediabox(o)
                        && (self.page_objects == 1 || self.first_mediabox.is_none())
                    {
                        self.first_mediabox = Some(mb);
                    }
                }
                "Font" => {
                    if let Some(f) = o.get("BaseFont").and_then(Obj::name)
                        && self.fonts.len() < MAX_LIST
                    {
                        let f = match f.split_once('+') {
                            Some((pre, rest)) if pre.len() == 6 => rest,
                            _ => f,
                        };
                        self.fonts.insert(f.to_string());
                    }
                }
                "EmbeddedFile" => self.bump("embedded_file"),
                "Filespec" => {
                    if let Some(n) = o
                        .get("UF")
                        .or_else(|| o.get("F"))
                        .and_then(Obj::text)
                        .filter(|_| o.get("EF").is_some())
                        && self.embedded.len() < MAX_LIST
                        && !self.embedded.contains(&n)
                    {
                        self.embedded.push(n);
                    }
                }
                _ => {}
            }
        }
        if o.get("Subtype").is_some_and(|s| s.is_name("Image")) {
            self.images += 1;
        }
        if o.get("Subtype").is_some_and(|s| s.is_name("RichMedia")) {
            self.bump("rich_media");
        }
        // Signature dictionaries carry a /ByteRange over the signed bytes.
        if let Some(Obj::Arr(br)) = o.get("ByteRange")
            && (o.type_is("Sig") || o.get("Contents").is_some())
            && self.sigs.len() < 50
        {
            let nums: Vec<f64> = br.iter().filter_map(Obj::num).collect();
            let covers = nums.len() == 4 && (nums[2] + nums[3]) as usize >= file_len;
            let (leaf, issuer, names) = o
                .get("Contents")
                .and_then(Obj::bytes)
                .map(signer_of)
                .unwrap_or_default();
            self.sigs.push(DocSignature {
                signer: o.get("Name").and_then(Obj::text).or(leaf),
                issuer,
                signed_at: o.get("M").and_then(Obj::text).map(|d| pretty_date(&d)),
                reason: o.get("Reason").and_then(Obj::text),
                location: o
                    .get("Location")
                    .and_then(Obj::text)
                    .or_else(|| o.get("ContactInfo").and_then(Obj::text)),
                certificate_names: names,
                covers_whole_file: covers,
            });
        }
    }
}

fn mediabox(o: &Obj) -> Option<(f64, f64)> {
    let Some(Obj::Arr(a)) = o.get("MediaBox") else {
        return None;
    };
    let n: Vec<f64> = a.iter().filter_map(Obj::num).collect();
    (n.len() == 4).then(|| ((n[2] - n[0]).abs(), (n[3] - n[1]).abs()))
}

fn info_fields(o: &Obj) -> Option<Vec<(String, String)>> {
    if o.get("Type").is_some() {
        return None;
    }
    let Obj::Dict(d) = o else { return None };
    let std_key = d.iter().any(|(k, v)| {
        matches!(
            k.as_str(),
            "Producer" | "Creator" | "CreationDate" | "ModDate" | "Author" | "Title"
        ) && matches!(v, Obj::Str(_))
    });
    if !std_key {
        return None;
    }
    let mut out = Vec::new();
    for (k, v) in d {
        if let Some(t) = v.text() {
            out.push((k.clone(), t));
        } else if let Obj::Name(n) = v {
            out.push((k.clone(), n.clone()));
        }
    }
    Some(out)
}

/// One certificate's subject and issuer, as "CN (O)".
#[derive(Debug, Clone, PartialEq)]
struct Cert {
    subject: String,
    issuer: String,
    timestamping: bool,
}

/// DER header at `i`: (tag, content start, content end). Definite lengths only.
fn der_at(b: &[u8], i: usize) -> Option<(u8, usize, usize)> {
    let tag = *b.get(i)?;
    let l0 = *b.get(i + 1)?;
    let (len, hdr) = if l0 < 0x80 {
        (l0 as usize, 2)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let v = b
            .get(i + 2..i + 2 + n)?
            .iter()
            .fold(0usize, |a, &x| a << 8 | x as usize);
        (v, 2 + n)
    };
    let s = i + hdr;
    let e = s.checked_add(len)?;
    (e <= b.len()).then_some((tag, s, e))
}

/// Children of a constructed DER value.
fn der_children(b: &[u8], s: usize, e: usize) -> Vec<(u8, usize, usize, usize)> {
    let mut out = Vec::new();
    let mut i = s;
    while i < e && out.len() < 16 {
        let Some((t, cs, ce)) = der_at(b, i) else {
            break;
        };
        out.push((t, i, cs, ce));
        i = ce;
    }
    out
}

/// Value of the first attribute with `oid` (e.g. CN `55 04 03`) in a range.
fn der_attr(b: &[u8], oid: &[u8], s: usize, e: usize) -> Option<String> {
    let r = b.get(s..e)?;
    let mut pat = vec![0x06, oid.len() as u8];
    pat.extend_from_slice(oid);
    let p = s + find(r, &pat, 0)? + pat.len();
    let (tag, vs, ve) = der_at(b, p).filter(|x| x.2 <= e)?;
    let v = b.get(vs..ve)?;
    let t = match tag {
        0x0c | 0x13 | 0x16 | 0x14 => String::from_utf8_lossy(v).into_owned(),
        0x1e => {
            let u: Vec<u16> = v
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&u)
        }
        _ => return None,
    };
    let t = t.trim().to_string();
    (!t.is_empty()).then_some(t)
}

fn der_name(b: &[u8], s: usize, e: usize) -> String {
    let cn = der_attr(b, &[0x55, 0x04, 0x03], s, e);
    let o = der_attr(b, &[0x55, 0x04, 0x0a], s, e);
    match (cn, o) {
        (Some(c), Some(o)) if c != o => format!("{c} ({o})"),
        (Some(c), _) => c,
        (None, Some(o)) => o,
        _ => String::new(),
    }
}

/// X.509 certificates inside a PKCS#7/CMS signature blob. Found by trying
/// every SEQUENCE as `Certificate { TBSCertificate { [0]? serial alg issuer
/// validity subject … } … }`, so BER wrappers around them don't matter.
fn certificates(b: &[u8]) -> Vec<Cert> {
    let mut out: Vec<Cert> = Vec::new();
    let mut i = 0;
    while i + 4 < b.len() && out.len() < 16 {
        if b[i] == 0x30
            && let Some((_, cs, ce)) = der_at(b, i)
            && let Some((0x30, ts, te)) = der_at(b, cs)
            && te <= ce
        {
            let kids = der_children(b, ts, te);
            let k: Vec<u8> = kids.iter().map(|x| x.0).collect();
            let base = usize::from(k.first() == Some(&0xa0));
            if k.len() >= base + 6
                && k[base] == 0x02
                && k[base + 1..base + 5] == [0x30, 0x30, 0x30, 0x30]
            {
                let (_, _, is, ie) = kids[base + 2];
                let (_, _, ss, se) = kids[base + 4];
                let c = Cert {
                    subject: der_name(b, ss, se),
                    issuer: der_name(b, is, ie),
                    // extKeyUsage id-kp-timeStamping (1.3.6.1.5.5.7.3.8).
                    timestamping: find(
                        &b[ts..te],
                        &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08],
                        0,
                    )
                    .is_some(),
                };
                if !c.subject.is_empty() && !out.contains(&c) {
                    out.push(c);
                }
                i = ce;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// (signer, issuer, all names) from a signature's certificates. The signer
/// is a leaf: a certificate that issued no other certificate and is not a
/// time-stamping authority.
fn signer_of(der: &[u8]) -> (Option<String>, Option<String>, Vec<String>) {
    let certs = certificates(der);
    let leaf = certs.iter().find(|c| {
        !c.timestamping && c.subject != c.issuer && !certs.iter().any(|o| o.issuer == c.subject)
    });
    let mut names: Vec<String> = Vec::new();
    for c in &certs {
        for n in [&c.subject, &c.issuer] {
            if !n.is_empty() && !names.contains(n) {
                names.push(n.clone());
            }
        }
    }
    (
        leaf.map(|c| c.subject.clone()),
        leaf.map(|c| c.issuer.clone()).filter(|s| !s.is_empty()),
        names,
    )
}

// ---------------------------------------------------------------- dates

#[derive(Debug, Clone, Copy, PartialEq)]
struct Date {
    y: i64,
    mo: u32,
    d: u32,
    h: u32,
    mi: u32,
    s: u32,
    /// Offset from UTC in minutes, when recorded.
    tz: Option<i32>,
}

impl Date {
    fn epoch(&self) -> i64 {
        // Days from civil (Howard Hinnant), then seconds.
        let (y, m) = if self.mo <= 2 {
            (self.y - 1, self.mo + 9)
        } else {
            (self.y, self.mo - 3)
        };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let doy = (153 * m as i64 + 2) / 5 + self.d as i64 - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        days * 86_400 + (self.h * 3600 + self.mi * 60 + self.s) as i64
            - self.tz.unwrap_or(0) as i64 * 60
    }
    fn show(&self) -> String {
        let months = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let mon = months
            .get((self.mo.max(1) - 1) as usize)
            .copied()
            .unwrap_or("?");
        let mut s = format!(
            "{} {mon} {} {:02}:{:02}:{:02}",
            self.d, self.y, self.h, self.mi, self.s
        );
        if let Some(tz) = self.tz {
            s.push_str(&format!(" {}", tz_str(tz)));
        }
        s
    }
}

fn tz_str(tz: i32) -> String {
    if tz == 0 {
        "UTC".into()
    } else {
        let sign = if tz < 0 { '-' } else { '+' };
        format!("UTC{sign}{:02}:{:02}", tz.abs() / 60, tz.abs() % 60)
    }
}

/// Parse a PDF date (`D:YYYYMMDDHHmmSSOHH'mm'`) or an XMP/ISO 8601 date.
fn parse_date(s: &str) -> Option<Date> {
    let s = s.trim();
    let s = s.strip_prefix("D:").unwrap_or(s);
    // ISO: 2023-10-05T12:30:45.123+05:30 — strip separators up to the zone.
    let (body, zone) = if s.contains('-') && s.get(4..5) == Some("-") {
        let t = s.find('T').map(|p| p + 1).unwrap_or(s.len());
        let z = s[t..]
            .find(['+', '-', 'Z'])
            .map(|p| t + p)
            .unwrap_or(s.len());
        let body: String = s[..z].chars().filter(|c| c.is_ascii_digit()).collect();
        let body: String = if let Some(dot) = s[..z].find('.') {
            s[..dot].chars().filter(|c| c.is_ascii_digit()).collect()
        } else {
            body
        };
        (body, &s[z..])
    } else {
        let n = s
            .char_indices()
            .find(|(_, c)| !c.is_ascii_digit())
            .map(|(i, _)| i)
            .unwrap_or(s.len());
        (s[..n].to_string(), &s[n..])
    };
    if body.len() < 4 {
        return None;
    }
    let f = |a: usize, b: usize, def: u32| -> u32 {
        body.get(a..b).and_then(|x| x.parse().ok()).unwrap_or(def)
    };
    let y: i64 = body.get(0..4)?.parse().ok()?;
    let mut d = Date {
        y,
        mo: f(4, 6, 1).clamp(1, 12),
        d: f(6, 8, 1).clamp(1, 31),
        h: f(8, 10, 0).min(23),
        mi: f(10, 12, 0).min(59),
        s: f(12, 14, 0).min(59),
        tz: None,
    };
    let z = zone.trim();
    if z.starts_with('Z') {
        d.tz = Some(0);
    } else if let Some(sign) = z.chars().next().filter(|c| *c == '+' || *c == '-') {
        let zd: String = z[1..].chars().filter(|c| c.is_ascii_digit()).collect();
        let hh: i32 = zd.get(0..2).and_then(|x| x.parse().ok()).unwrap_or(0);
        let mm: i32 = zd.get(2..4).and_then(|x| x.parse().ok()).unwrap_or(0);
        if hh <= 14 && mm < 60 {
            let m = hh * 60 + mm;
            d.tz = Some(if sign == '-' { -m } else { m });
        }
    }
    (1970..=2200).contains(&d.y).then_some(d)
}

fn pretty_date(s: &str) -> String {
    parse_date(s)
        .map(|d| d.show())
        .unwrap_or_else(|| s.to_string())
}

/// Places that commonly use a UTC offset. The offset comes from the clock
/// of the device that wrote the file, so it is a hint, not proof.
fn tz_region(tz: i32) -> Option<&'static str> {
    Some(match tz {
        330 => "India or Sri Lanka",
        345 => "Nepal",
        300 => "Pakistan, Uzbekistan or the Maldives",
        360 => "Bangladesh",
        390 => "Myanmar",
        420 => "Thailand, Vietnam, Indonesia (west)",
        480 => "China, Singapore, Malaysia, the Philippines or Western Australia",
        540 => "Japan or Korea",
        570 => "Central Australia",
        600 => "Eastern Australia",
        660 => "Eastern Australia (summer time)",
        720 | 780 => "New Zealand",
        240 => "the UAE, Oman or the Caucasus",
        270 => "Afghanistan",
        210 => "Iran",
        180 => "Russia (Moscow), Turkey, Saudi Arabia or East Africa",
        120 => "Eastern Europe, Egypt or South Africa",
        60 => "Central Europe or West Africa",
        -180 => "Brazil or Argentina",
        -240 => "the US East Coast (summer) or the Atlantic",
        -300 => "the US East Coast or Central US (summer)",
        -360 => "Central US or Mexico",
        -420 => "the US Mountain or Pacific (summer) time zone",
        -480 => "the US West Coast",
        _ => return None,
    })
}

// ---------------------------------------------------------------- XMP

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#xA;", "\n")
        .replace("&#10;", "\n")
        .replace("&amp;", "&")
}

fn strip_tags(s: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for c in s.chars() {
        match c {
            '<' => inside = true,
            '>' => inside = false,
            c if !inside => out.push(c),
            _ => {}
        }
    }
    out
}

/// Value of an XMP property, as an attribute (`ns:Prop="v"`) or element
/// (`<ns:Prop>v</ns:Prop>`, possibly wrapping `rdf:Alt/Seq/Bag` lists, in
/// which case list items are joined with ", ").
fn xmp_get(xml: &str, tag: &str) -> Option<String> {
    let mut from = 0;
    while let Some(p) = xml.get(from..)?.find(tag).map(|p| p + from) {
        from = p + tag.len();
        let before = xml[..p].chars().next_back();
        let after = &xml[p + tag.len()..];
        // Attribute form.
        if before.is_some_and(char::is_whitespace) {
            let a = after.trim_start();
            if let Some(a) = a.strip_prefix('=') {
                let a = a.trim_start();
                let q = a.chars().next()?;
                if q == '"' || q == '\'' {
                    let end = a[1..].find(q)?;
                    let v = xml_unescape(a[1..1 + end].trim());
                    if !v.is_empty() {
                        return Some(clip(&v, 2000));
                    }
                }
            }
        }
        // Element form.
        if before == Some('<') && after.starts_with(['>', ' ', '\n', '\r', '\t']) {
            let open_end = after.find('>')?;
            if after[..open_end].ends_with('/') {
                continue;
            }
            let content = &after[open_end + 1..];
            let close = format!("</{tag}>");
            let end = content.find(&close)?;
            let inner = &content[..end];
            let v = if inner.contains("<rdf:li") {
                inner
                    .split("<rdf:li")
                    .skip(1)
                    .filter_map(|li| {
                        let gt = li.find('>')?;
                        if li[..gt].ends_with('/') {
                            return None;
                        }
                        let body = &li[gt + 1..];
                        let e = body.find("</rdf:li>").unwrap_or(body.len());
                        let t = xml_unescape(strip_tags(&body[..e]).trim());
                        (!t.is_empty()).then_some(t)
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                xml_unescape(strip_tags(inner).trim())
            };
            if !v.is_empty() {
                return Some(clip(&v, 2000));
            }
        }
    }
    None
}

fn xmp_history(xml: &str) -> Vec<HistoryEvent> {
    let Some(s) = xml.find("<xmpMM:History") else {
        return Vec::new();
    };
    let e = xml[s..]
        .find("</xmpMM:History>")
        .map(|e| s + e)
        .unwrap_or(xml.len());
    xml[s..e]
        .split("<rdf:li")
        .skip(1)
        .take(MAX_LIST)
        .filter_map(|li| {
            let li = format!(" {li}");
            let action = xmp_get(&li, "stEvt:action")?;
            Some(HistoryEvent {
                when: xmp_get(&li, "stEvt:when").map(|d| pretty_date(&d)),
                action,
                software: xmp_get(&li, "stEvt:softwareAgent"),
            })
        })
        .collect()
}

// ---------------------------------------------------------------- origin rules

struct Tool {
    pat: &'static str,
    name: &'static str,
    kind: Kind,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Office,
    Apple,
    Google,
    Browser,
    Latex,
    Adobe,
    Design,
    Generator,
    Scanner,
    Online,
    Esign,
    Viewer,
}

const TOOLS: &[Tool] = &[
    Tool {
        pat: "google docs renderer",
        name: "Google Docs",
        kind: Kind::Google,
    },
    Tool {
        pat: "google slides",
        name: "Google Slides",
        kind: Kind::Google,
    },
    Tool {
        pat: "google sheets",
        name: "Google Sheets",
        kind: Kind::Google,
    },
    Tool {
        pat: "microsoft: print to pdf",
        name: "Windows \u{201c}Microsoft Print to PDF\u{201d}",
        kind: Kind::Office,
    },
    Tool {
        pat: "microsoft® word",
        name: "Microsoft Word",
        kind: Kind::Office,
    },
    Tool {
        pat: "microsoft word",
        name: "Microsoft Word",
        kind: Kind::Office,
    },
    Tool {
        pat: "microsoft® excel",
        name: "Microsoft Excel",
        kind: Kind::Office,
    },
    Tool {
        pat: "microsoft excel",
        name: "Microsoft Excel",
        kind: Kind::Office,
    },
    Tool {
        pat: "microsoft® powerpoint",
        name: "Microsoft PowerPoint",
        kind: Kind::Office,
    },
    Tool {
        pat: "microsoft powerpoint",
        name: "Microsoft PowerPoint",
        kind: Kind::Office,
    },
    Tool {
        pat: "microsoft® publisher",
        name: "Microsoft Publisher",
        kind: Kind::Office,
    },
    Tool {
        pat: "microsoft® onenote",
        name: "Microsoft OneNote",
        kind: Kind::Office,
    },
    Tool {
        pat: "microsoft® visio",
        name: "Microsoft Visio",
        kind: Kind::Office,
    },
    Tool {
        pat: "pscript5.dll",
        name: "a Windows PostScript printer driver",
        kind: Kind::Office,
    },
    Tool {
        pat: "libreoffice",
        name: "LibreOffice",
        kind: Kind::Office,
    },
    Tool {
        pat: "openoffice",
        name: "OpenOffice",
        kind: Kind::Office,
    },
    Tool {
        pat: "wps office",
        name: "WPS Office",
        kind: Kind::Office,
    },
    Tool {
        pat: "wps writer",
        name: "WPS Office",
        kind: Kind::Office,
    },
    Tool {
        pat: "pages",
        name: "Apple Pages",
        kind: Kind::Apple,
    },
    Tool {
        pat: "keynote",
        name: "Apple Keynote",
        kind: Kind::Apple,
    },
    Tool {
        pat: "numbers",
        name: "Apple Numbers",
        kind: Kind::Apple,
    },
    Tool {
        pat: "preview",
        name: "Apple Preview",
        kind: Kind::Apple,
    },
    Tool {
        pat: "quartz pdfcontext",
        name: "Apple\u{2019}s built-in PDF engine (macOS/iOS)",
        kind: Kind::Apple,
    },
    Tool {
        pat: "skia/pdf",
        name: "Google Chrome / Chromium \u{201c}Save as PDF\u{201d}",
        kind: Kind::Browser,
    },
    Tool {
        pat: "headlesschrome",
        name: "headless Chrome (automated)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "puppeteer",
        name: "Puppeteer (automated Chrome)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "playwright",
        name: "Playwright (automated browser)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "mozilla",
        name: "Firefox",
        kind: Kind::Browser,
    },
    Tool {
        pat: "cairo",
        name: "Cairo (Linux/GTK apps, Firefox)",
        kind: Kind::Browser,
    },
    Tool {
        pat: "pdftex",
        name: "LaTeX (pdfTeX)",
        kind: Kind::Latex,
    },
    Tool {
        pat: "xetex",
        name: "LaTeX (XeTeX)",
        kind: Kind::Latex,
    },
    Tool {
        pat: "luatex",
        name: "LaTeX (LuaTeX)",
        kind: Kind::Latex,
    },
    Tool {
        pat: "dvipdfm",
        name: "LaTeX (dvipdfmx)",
        kind: Kind::Latex,
    },
    Tool {
        pat: "latex",
        name: "LaTeX",
        kind: Kind::Latex,
    },
    Tool {
        pat: "overleaf",
        name: "Overleaf (online LaTeX)",
        kind: Kind::Latex,
    },
    Tool {
        pat: "typst",
        name: "Typst",
        kind: Kind::Latex,
    },
    Tool {
        pat: "pandoc",
        name: "Pandoc",
        kind: Kind::Latex,
    },
    Tool {
        pat: "adobe indesign",
        name: "Adobe InDesign",
        kind: Kind::Design,
    },
    Tool {
        pat: "adobe illustrator",
        name: "Adobe Illustrator",
        kind: Kind::Design,
    },
    Tool {
        pat: "illustrator",
        name: "Adobe Illustrator",
        kind: Kind::Design,
    },
    Tool {
        pat: "adobe photoshop",
        name: "Adobe Photoshop",
        kind: Kind::Design,
    },
    Tool {
        pat: "canva",
        name: "Canva",
        kind: Kind::Design,
    },
    Tool {
        pat: "figma",
        name: "Figma",
        kind: Kind::Design,
    },
    Tool {
        pat: "affinity",
        name: "Affinity (Serif)",
        kind: Kind::Design,
    },
    Tool {
        pat: "coreldraw",
        name: "CorelDRAW",
        kind: Kind::Design,
    },
    Tool {
        pat: "quarkxpress",
        name: "QuarkXPress",
        kind: Kind::Design,
    },
    Tool {
        pat: "inkscape",
        name: "Inkscape",
        kind: Kind::Design,
    },
    Tool {
        pat: "acrobat paper capture",
        name: "Adobe Acrobat OCR (scanned pages)",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "adobe scan",
        name: "Adobe Scan (phone scanner app)",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "acrobat distiller",
        name: "Adobe Acrobat Distiller",
        kind: Kind::Adobe,
    },
    Tool {
        pat: "adobe acrobat",
        name: "Adobe Acrobat",
        kind: Kind::Adobe,
    },
    Tool {
        pat: "acrobat pro",
        name: "Adobe Acrobat",
        kind: Kind::Adobe,
    },
    Tool {
        pat: "adobe pdf library",
        name: "Adobe PDF Library (Adobe apps)",
        kind: Kind::Adobe,
    },
    Tool {
        pat: "adobe experience manager",
        name: "Adobe Experience Manager (server)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "camscanner",
        name: "CamScanner (phone scanner app)",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "microsoft lens",
        name: "Microsoft Lens (phone scanner app)",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "office lens",
        name: "Microsoft Office Lens (phone scanner app)",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "genius scan",
        name: "Genius Scan (phone scanner app)",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "scanner pro",
        name: "Scanner Pro (phone scanner app)",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "tiny scanner",
        name: "Tiny Scanner (phone scanner app)",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "scansnap",
        name: "Fujitsu ScanSnap scanner",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "epson scan",
        name: "Epson scanner",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "naps2",
        name: "NAPS2 scanner software",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "hp scan",
        name: "HP scanner",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "canon",
        name: "a Canon scanner or printer",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "xerox",
        name: "a Xerox copier/scanner",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "ricoh",
        name: "a Ricoh copier/scanner",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "konica",
        name: "a Konica Minolta copier/scanner",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "kyocera",
        name: "a Kyocera copier/scanner",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "brother",
        name: "a Brother scanner",
        kind: Kind::Scanner,
    },
    Tool {
        pat: "itext",
        name: "iText (server-side PDF library)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "pdfsharp",
        name: "PDFsharp (.NET library)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "reportlab",
        name: "ReportLab (Python library)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "fpdf",
        name: "FPDF (PHP/Python library)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "tcpdf",
        name: "TCPDF (PHP library)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "dompdf",
        name: "Dompdf (PHP library)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "mpdf",
        name: "mPDF (PHP library)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "wkhtmltopdf",
        name: "wkhtmltopdf (HTML to PDF)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "qt ",
        name: "a Qt application (often wkhtmltopdf)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "prince",
        name: "Prince (HTML to PDF)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "weasyprint",
        name: "WeasyPrint (HTML to PDF)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "apache fop",
        name: "Apache FOP",
        kind: Kind::Generator,
    },
    Tool {
        pat: "jasperreports",
        name: "JasperReports",
        kind: Kind::Generator,
    },
    Tool {
        pat: "crystal reports",
        name: "Crystal Reports",
        kind: Kind::Generator,
    },
    Tool {
        pat: "aspose",
        name: "Aspose (server-side library)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "pdflib",
        name: "PDFlib",
        kind: Kind::Generator,
    },
    Tool {
        pat: "pdfkit",
        name: "PDFKit",
        kind: Kind::Generator,
    },
    Tool {
        pat: "pdf-lib",
        name: "pdf-lib (JavaScript)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "jspdf",
        name: "jsPDF (JavaScript in a web page)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "pdfmake",
        name: "pdfmake (JavaScript)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "react-pdf",
        name: "react-pdf (JavaScript)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "pypdf",
        name: "pypdf (Python)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "pdfbox",
        name: "Apache PDFBox (Java)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "openpdf",
        name: "OpenPDF (Java)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "ghostscript",
        name: "Ghostscript",
        kind: Kind::Generator,
    },
    Tool {
        pat: "gpl ghostscript",
        name: "Ghostscript",
        kind: Kind::Generator,
    },
    Tool {
        pat: "qpdf",
        name: "qpdf",
        kind: Kind::Generator,
    },
    Tool {
        pat: "mupdf",
        name: "MuPDF",
        kind: Kind::Viewer,
    },
    Tool {
        pat: "pdfium",
        name: "PDFium (Chrome\u{2019}s PDF engine)",
        kind: Kind::Viewer,
    },
    Tool {
        pat: "sap netweaver",
        name: "SAP (business system)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "tally",
        name: "Tally (accounting)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "quickbooks",
        name: "QuickBooks (accounting)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "intuit",
        name: "Intuit (accounting)",
        kind: Kind::Generator,
    },
    Tool {
        pat: "zoho",
        name: "Zoho",
        kind: Kind::Generator,
    },
    Tool {
        pat: "notion",
        name: "Notion",
        kind: Kind::Generator,
    },
    Tool {
        pat: "smallpdf",
        name: "Smallpdf (online PDF service)",
        kind: Kind::Online,
    },
    Tool {
        pat: "ilovepdf",
        name: "iLovePDF (online PDF service)",
        kind: Kind::Online,
    },
    Tool {
        pat: "sejda",
        name: "Sejda (online PDF service)",
        kind: Kind::Online,
    },
    Tool {
        pat: "pdf24",
        name: "PDF24",
        kind: Kind::Online,
    },
    Tool {
        pat: "pdfescape",
        name: "PDFescape (online editor)",
        kind: Kind::Online,
    },
    Tool {
        pat: "pdffiller",
        name: "pdfFiller (online editor)",
        kind: Kind::Online,
    },
    Tool {
        pat: "foxit",
        name: "Foxit PDF",
        kind: Kind::Viewer,
    },
    Tool {
        pat: "nitro",
        name: "Nitro PDF",
        kind: Kind::Viewer,
    },
    Tool {
        pat: "pdfelement",
        name: "Wondershare PDFelement",
        kind: Kind::Viewer,
    },
    Tool {
        pat: "wondershare",
        name: "Wondershare PDFelement",
        kind: Kind::Viewer,
    },
    Tool {
        pat: "pdf-xchange",
        name: "PDF-XChange",
        kind: Kind::Viewer,
    },
    Tool {
        pat: "bluebeam",
        name: "Bluebeam Revu",
        kind: Kind::Viewer,
    },
    Tool {
        pat: "docusign",
        name: "DocuSign (e-signature)",
        kind: Kind::Esign,
    },
    Tool {
        pat: "adobe sign",
        name: "Adobe Acrobat Sign (e-signature)",
        kind: Kind::Esign,
    },
    Tool {
        pat: "echosign",
        name: "Adobe Sign (e-signature)",
        kind: Kind::Esign,
    },
    Tool {
        pat: "hellosign",
        name: "Dropbox Sign (e-signature)",
        kind: Kind::Esign,
    },
    Tool {
        pat: "dropbox sign",
        name: "Dropbox Sign (e-signature)",
        kind: Kind::Esign,
    },
    Tool {
        pat: "pandadoc",
        name: "PandaDoc (e-signature)",
        kind: Kind::Esign,
    },
    Tool {
        pat: "digilocker",
        name: "DigiLocker (Government of India)",
        kind: Kind::Esign,
    },
    Tool {
        pat: "google",
        name: "a Google app (Docs, Slides or Sheets)",
        kind: Kind::Google,
    },
];

/// Browsers that write their user-agent string as the PDF creator.
const UA_TOOLS: &[Tool] = &[
    Tool {
        pat: "edg/",
        name: "Microsoft Edge (printing a web page)",
        kind: Kind::Browser,
    },
    Tool {
        pat: "opr/",
        name: "Opera (printing a web page)",
        kind: Kind::Browser,
    },
    Tool {
        pat: "chrome/",
        name: "Google Chrome (printing a web page)",
        kind: Kind::Browser,
    },
    Tool {
        pat: "firefox/",
        name: "Firefox (printing a web page)",
        kind: Kind::Browser,
    },
    Tool {
        pat: "safari/",
        name: "Safari (printing a web page)",
        kind: Kind::Browser,
    },
];

fn tool_for(s: &str) -> Option<&'static Tool> {
    let l = s.to_lowercase();
    if l.starts_with("mozilla/") {
        return UA_TOOLS.iter().find(|t| l.contains(t.pat));
    }
    TOOLS.iter().find(|t| {
        if t.pat.len() <= 6 {
            // Short words ("pages", "canon") must match a whole word.
            l.split(|c: char| !c.is_alphanumeric() && c != '-')
                .any(|w| w == t.pat.trim())
        } else {
            l.contains(t.pat)
        }
    })
}

fn kind_text(k: Kind) -> &'static str {
    match k {
        Kind::Office => {
            "an office program, so a person most likely wrote it and saved or exported it as PDF"
        }
        Kind::Apple => "an Apple device (a Mac, iPhone or iPad)",
        Kind::Google => "Google\u{2019}s online office apps, downloaded as PDF",
        Kind::Browser => {
            "a web browser, usually by printing a web page or using \u{201c}Save as PDF\u{201d}"
        }
        Kind::Latex => "a typesetting system popular in universities and research",
        Kind::Adobe => "Adobe\u{2019}s PDF software",
        Kind::Design => {
            "a design or layout program, typical for brochures, posters and printed material"
        }
        Kind::Generator => {
            "software that generates PDFs automatically, typical of websites and business systems (invoices, statements, tickets, reports)"
        }
        Kind::Scanner => {
            "a scanner or a phone scanning app, so it is probably a scan of a paper document"
        }
        Kind::Online => {
            "an online PDF service, so it was uploaded to and processed by that website"
        }
        Kind::Esign => "an electronic-signature service",
        Kind::Viewer => "a PDF editor or viewer that re-saved it",
    }
}

fn feature_info(k: &str) -> (&'static str, Severity, &'static str) {
    match k {
        "javascript" => (
            "JavaScript",
            Severity::Medium,
            "Contains scripts. Most PDFs never need scripts; they are a common way to attack PDF readers.",
        ),
        "open_action" => (
            "Action when opened",
            Severity::Low,
            "Does something as soon as the document opens (often just jumping to a page).",
        ),
        "auto_action" => (
            "Automatic actions",
            Severity::Medium,
            "Runs actions automatically on events such as opening a page or clicking a field.",
        ),
        "launch" => (
            "Launches programs",
            Severity::High,
            "Can ask the reader to open another file or run a program. Legitimate documents almost never do this.",
        ),
        "embedded_file" => (
            "Attached files",
            Severity::Medium,
            "Has files attached inside it. Check what they are before opening them.",
        ),
        "form" => (
            "Fillable form",
            Severity::Info,
            "Has form fields (common for applications and tax forms).",
        ),
        "xfa" => (
            "XFA form",
            Severity::Medium,
            "Uses the old XFA form technology, which has been abused by exploits and only works in Adobe readers.",
        ),
        "submit_form" => (
            "Sends form data",
            Severity::Low,
            "Can send what you type in its form to a web address.",
        ),
        "import_data" => (
            "Imports data",
            Severity::Low,
            "Can pull data in from another file.",
        ),
        "remote_goto" => (
            "Opens other documents",
            Severity::Low,
            "Links that open other files or documents.",
        ),
        "rich_media" => (
            "Embedded media/Flash",
            Severity::Medium,
            "Contains embedded media (historically Flash), an old attack route.",
        ),
        _ => ("Other", Severity::Info, ""),
    }
}

const RISKY_EXT: &[&str] = &[
    ".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
    ".lnk", ".msi", ".dll", ".jar", ".app", ".pkg", ".dmg", ".sh", ".docm", ".xlsm", ".pptm",
    ".iso", ".img", ".zip", ".rar", ".7z",
];

// ---------------------------------------------------------------- entry

/// Analyse PDF bytes. Never fails: problems become `warnings`.
pub fn analyze(b: &[u8]) -> DocumentReport {
    let mut r = DocumentReport {
        kind: "pdf".into(),
        revisions: 1,
        ..Default::default()
    };
    let head = b.get(..1024).unwrap_or(b);
    if let Some(p) = find(head, b"%PDF-", 0) {
        let v: String = head[p + 5..]
            .iter()
            .take(4)
            .take_while(|c| c.is_ascii_digit() || **c == b'.')
            .map(|&c| c as char)
            .collect();
        if !v.is_empty() {
            r.version = Some(v);
        }
    }

    let mut c = Collect::default();
    let headers = object_headers(b);
    if headers.len() >= MAX_OBJECTS {
        r.warnings.push(format!(
            "Only the first {MAX_OBJECTS} objects were inspected."
        ));
    }
    // Raw object positions for resolving `/Length N 0 R`.
    let mut raw: HashMap<u32, usize> = HashMap::with_capacity(headers.len());
    for &(n, off) in &headers {
        raw.insert(n, off);
    }
    let resolve_int = |o: &Obj| -> Option<usize> {
        match o {
            Obj::Num(n) if *n >= 0.0 => Some(*n as usize),
            Obj::Ref(n) => {
                let off = *raw.get(n)?;
                Parser::new(b, off)
                    .object(0)
                    .and_then(|x| x.num())
                    .filter(|n| *n >= 0.0)
                    .map(|n| n as usize)
            }
            _ => None,
        }
    };

    for &(num, off) in &headers {
        let mut p = Parser::new(b, off);
        let Some(obj) = p.object(0) else { continue };
        c.objects += 1;
        // Stream?
        let mut stream: Option<&[u8]> = None;
        if matches!(obj, Obj::Dict(_)) {
            p.skip_ws();
            if p.starts(b"stream") {
                let mut s = p.i + 6;
                if b.get(s) == Some(&b'\r') {
                    s += 1;
                }
                if b.get(s) == Some(&b'\n') {
                    s += 1;
                }
                let by_len = obj
                    .get("Length")
                    .and_then(&resolve_int)
                    .and_then(|l| s.checked_add(l))
                    .filter(|&e| e <= b.len())
                    .filter(|&e| {
                        b.get(e..(e + 32).min(b.len()))
                            .is_some_and(|w| find(w, b"endstream", 0).is_some())
                    });
                let end = by_len.or_else(|| find(b, b"endstream", s));
                stream = end.and_then(|e| b.get(s..e));
            }
        }
        handle(&mut c, num, &obj, stream, b.len());
        if obj.type_is("ObjStm")
            && let Some(data) = stream
        {
            objstm(&mut c, &obj, data, b.len());
        }
        if obj.type_is("XRef") {
            c.trailers.push(obj.clone());
        }
    }
    // Classic trailers.
    let mut i = 0;
    while let Some(p) = find(b, b"trailer", i) {
        i = p + 7;
        if let Some(t @ Obj::Dict(_)) = Parser::new(b, i).object(0) {
            c.walk(&t, b.len(), 0);
            c.trailers.push(t);
        }
        if c.trailers.len() > 1000 {
            break;
        }
    }
    if c.objstm_failed > 0 {
        r.warnings.push(format!(
            "{} compressed object group(s) could not be decoded; some details may be missing.",
            c.objstm_failed
        ));
    }

    // Fallback XMP: an uncompressed packet anywhere in the file.
    if c.xmp.is_empty()
        && c.xmp_any.is_empty()
        && let Some(s) = find(b, b"<x:xmpmeta", 0)
    {
        let e = find(b, b"</x:xmpmeta>", s)
            .map(|e| e + 12)
            .unwrap_or((s + MAX_XMP).min(b.len()));
        if let Some(x) = b.get(s..e.min(s + MAX_XMP)) {
            c.xmp_any.push(String::from_utf8_lossy(x).into_owned());
        }
    }

    // ---- interpret
    let startxrefs = count(b, b"startxref") as u32;
    r.linearized = c.linearized;
    r.revisions = startxrefs
        .saturating_sub(u32::from(c.linearized && startxrefs > 1))
        .max(1);
    let latest = |k: &str| c.trailers.iter().rev().find_map(|t| t.get(k).cloned());
    r.encrypted = latest("Encrypt").is_some();
    let ids: Vec<Vec<u8>> = match latest("ID") {
        Some(Obj::Arr(a)) => a
            .iter()
            .filter_map(|x| x.bytes().map(<[u8]>::to_vec))
            .collect(),
        _ => Vec::new(),
    };
    let hex = |v: &[u8]| v.iter().map(|b| format!("{b:02x}")).collect::<String>();

    // Information dictionary: the trailer's /Info, latest version wins; older
    // versions of the same object show how the metadata changed.
    let info_num = latest("Info").and_then(|o| o.reference());
    let pick: Vec<&(u32, Vec<(String, String)>)> = match info_num {
        Some(n) => c.info_versions.iter().filter(|(m, _)| *m == n).collect(),
        None => c.info_versions.iter().collect(),
    };
    let info: Vec<(String, String)> = match latest("Info") {
        Some(d @ Obj::Dict(_)) => info_fields(&d).unwrap_or_default(),
        _ => pick.last().map(|(_, f)| f.clone()).unwrap_or_default(),
    };
    let previous: Vec<(String, String)> = if pick.len() > 1 {
        pick[pick.len() - 2].1.clone()
    } else {
        Vec::new()
    };
    let iget = |k: &str| {
        info.iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
    };

    // XMP: the catalog's /Metadata stream, else any document-level packet.
    let cat_meta = c
        .catalog
        .as_ref()
        .and_then(|cat| cat.get("Metadata"))
        .and_then(Obj::reference);
    let xmp: Option<&String> = cat_meta
        .and_then(|n| c.xmp.get(&n))
        .or_else(|| {
            c.xmp
                .values()
                .chain(c.xmp_any.iter())
                .find(|x| x.contains("CreatorTool") || x.contains("pdf:Producer"))
        })
        .or_else(|| c.xmp_any.first());
    let x = |k: &str| xmp.and_then(|x| xmp_get(x, k));

    let producer = iget("Producer");
    let creator = iget("Creator");
    let author = iget("Author");
    let x_producer = x("pdf:Producer");
    let x_tool = x("xmp:CreatorTool");
    let x_author = x("dc:creator");
    let created_s = iget("CreationDate").or_else(|| x("xmp:CreateDate"));
    let modified_s = iget("ModDate").or_else(|| x("xmp:ModifyDate"));
    let created = created_s.as_deref().and_then(parse_date);
    let modified = modified_s.as_deref().and_then(parse_date);

    let mut meta = |key: &str, value: Option<String>, source: &str| {
        if let Some(v) = value.filter(|v| !v.trim().is_empty()) {
            r.metadata.push(MetaField {
                key: key.into(),
                value: v,
                source: source.into(),
            });
        }
    };
    meta("Title", iget("Title"), "info");
    meta("Author", author.clone(), "info");
    meta("Subject", iget("Subject"), "info");
    meta("Keywords", iget("Keywords"), "info");
    meta("Made with (Creator)", creator.clone(), "info");
    meta("Converted by (Producer)", producer.clone(), "info");
    meta(
        "Created",
        iget("CreationDate").map(|d| pretty_date(&d)),
        "info",
    );
    meta("Modified", iget("ModDate").map(|d| pretty_date(&d)), "info");
    meta("Trapped", iget("Trapped"), "info");
    let standard = [
        "Title",
        "Author",
        "Subject",
        "Keywords",
        "Creator",
        "Producer",
        "CreationDate",
        "ModDate",
        "Trapped",
    ];
    for (k, v) in &info {
        if !standard.contains(&k.as_str()) {
            meta(k, Some(v.clone()), "info");
        }
    }
    meta(
        "Title",
        x("dc:title").filter(|t| Some(t) != iget("Title").as_ref()),
        "xmp",
    );
    meta(
        "Author",
        x_author.clone().filter(|a| Some(a) != author.as_ref()),
        "xmp",
    );
    meta("Description", x("dc:description"), "xmp");
    meta("Made with (Creator tool)", x_tool.clone(), "xmp");
    meta(
        "Converted by (Producer)",
        x_producer.clone().filter(|p| Some(p) != producer.as_ref()),
        "xmp",
    );
    meta(
        "Created",
        x("xmp:CreateDate")
            .filter(|_| iget("CreationDate").is_none())
            .map(|d| pretty_date(&d)),
        "xmp",
    );
    meta(
        "Modified",
        x("xmp:ModifyDate")
            .filter(|_| iget("ModDate").is_none())
            .map(|d| pretty_date(&d)),
        "xmp",
    );
    meta(
        "Metadata changed",
        x("xmp:MetadataDate").map(|d| pretty_date(&d)),
        "xmp",
    );
    meta("Document ID", x("xmpMM:DocumentID"), "xmp");
    meta("Instance ID", x("xmpMM:InstanceID"), "xmp");
    meta("Original document ID", x("xmpMM:OriginalDocumentID"), "xmp");
    meta("Derived from", x("stRef:documentID"), "xmp");
    meta("Rights", x("dc:rights"), "xmp");
    meta(
        "PDF/A conformance",
        x("pdfaid:part")
            .map(|p| format!("PDF/A-{p}{}", x("pdfaid:conformance").unwrap_or_default())),
        "xmp",
    );
    meta(
        "Language",
        c.catalog
            .as_ref()
            .and_then(|k| k.get("Lang"))
            .and_then(Obj::text),
        "catalog",
    );
    if let Some(a) = ids.first() {
        meta("File ID (original)", Some(hex(a)), "trailer");
    }
    if let (Some(a), Some(z)) = (ids.first(), ids.get(1))
        && a != z
    {
        meta("File ID (current)", Some(hex(z)), "trailer");
    }
    for (k, v) in &previous {
        if iget(k).as_deref() != Some(v.as_str()) {
            let v = if k.ends_with("Date") {
                pretty_date(v)
            } else {
                v.clone()
            };
            meta(&format!("Earlier {k}"), Some(v), "previous");
        }
    }
    r.history = xmp.map(|x| xmp_history(x)).unwrap_or_default();

    r.pages = c
        .pages_count
        .or((c.page_objects > 0).then_some(c.page_objects));
    r.page_size = c.first_mediabox.map(|(w, h)| paper(w, h));
    r.fonts = c.fonts.iter().cloned().collect();
    r.images = c.images;
    r.links = c.links.clone();
    r.embedded_files = c.embedded.clone();
    r.signatures = c.sigs.clone();

    // ---- features + verdict
    // Document-level scripts: catalog /Names /JavaScript name tree. They
    // run when the document opens. Google exports often carry an empty or
    // dangling tree, which is harmless.
    let lookup = |o: &Obj| -> Option<Obj> {
        match o {
            Obj::Ref(n) => c.name_dicts.get(n).cloned(),
            d @ Obj::Dict(_) => Some(d.clone()),
            _ => None,
        }
    };
    let js_tree = c
        .catalog
        .as_ref()
        .and_then(|cat| cat.get("Names"))
        .and_then(&lookup);
    let has_tree_key = js_tree
        .as_ref()
        .is_some_and(|n| n.get("JavaScript").is_some());
    let doc_scripts = js_tree
        .as_ref()
        .and_then(|n| n.get("JavaScript"))
        .and_then(&lookup)
        .map(|t| tree_entries(&t, &lookup, 0))
        .unwrap_or(0);
    if doc_scripts > 0 {
        *c.feat.entry("javascript").or_default() += doc_scripts;
        c.open_action_script = true;
    }
    // Last resort for objects the parser couldn't read: the raw token.
    let raw_js = count(b, b"/JavaScript") as u32;
    if !c.feat.contains_key("javascript") && raw_js > u32::from(has_tree_key) {
        c.feat
            .insert("javascript", raw_js - u32::from(has_tree_key));
    }
    if !c.open_action_script {
        c.feat.remove("open_action");
    }
    for (k, n) in &c.feat {
        let (name, sev, expl) = feature_info(k);
        r.features.push(DocFeature {
            name: name.into(),
            count: *n,
            severity: sev,
            explanation: expl.into(),
        });
    }
    let risky_attach: Vec<&String> = r
        .embedded_files
        .iter()
        .filter(|f| {
            let l = f.to_lowercase();
            RISKY_EXT.iter().any(|e| l.ends_with(e))
        })
        .collect();
    if !risky_attach.is_empty() {
        r.features.push(DocFeature {
            name: "Risky attachment".into(),
            count: risky_attach.len() as u32,
            severity: Severity::High,
            explanation: format!(
                "Attached file(s) that can run code or hide other files: {}.",
                risky_attach
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        });
    }
    let js = c.feat.contains_key("javascript");
    let auto = c.feat.contains_key("auto_action") || c.open_action_script;
    if js && auto {
        r.features.push(DocFeature {
            name: "Script runs on open".into(),
            count: 1,
            severity: Severity::High,
            explanation: "A script is set to run automatically, without you clicking anything. This is the pattern most malicious PDFs use.".into(),
        });
    }
    r.features.sort_by_key(|f| std::cmp::Reverse(f.severity));
    r.risk = r
        .features
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);
    r.verdict = match r.risk {
        Severity::High => "Be careful: this PDF has features that are typical of malicious documents. Don\u{2019}t open it in Adobe Reader or click its links unless you trust the sender.".into(),
        Severity::Medium => format!(
            "Use caution: this PDF has active content ({}). It may be legitimate, but treat it carefully if you weren\u{2019}t expecting it.",
            r.features.iter().filter(|f| f.severity >= Severity::Medium).map(|f| f.name.to_lowercase()).collect::<Vec<_>>().join(", ")
        ),
        _ => "No risky features found: no scripts, auto-run actions, program launches or attached files.".into(),
    };
    if r.encrypted {
        r.warnings.push("The PDF is encrypted, so text inside it (including some metadata) can\u{2019}t be read without the password.".into());
    }

    // ---- origin clues
    let mut clue = |topic: &str, text: String, conf: Confidence| {
        if !r.clues.iter().any(|c| c.text == text) {
            r.clues.push(OriginClue {
                topic: topic.into(),
                text,
                confidence: conf,
            });
        }
    };
    let mut tools_seen: Vec<&'static str> = Vec::new();
    let mut sources: Vec<(&str, String)> = Vec::new();
    for (role, v) in [
        ("creator", creator.clone()),
        ("creator", x_tool.clone()),
        ("producer", producer.clone()),
        ("producer", x_producer.clone()),
    ] {
        if let Some(v) = v {
            sources.push((role, v));
        }
    }
    for ev in &r.history {
        if let Some(s) = &ev.software {
            sources.push(("history", s.clone()));
        }
    }
    let mut first_kind: Option<Kind> = None;
    for (role, v) in &sources {
        if let Some(t) = tool_for(v)
            && !tools_seen.contains(&t.name)
        {
            tools_seen.push(t.name);
            let conf = if *role == "history" {
                Confidence::Medium
            } else {
                Confidence::High
            };
            let verb = match *role {
                "creator" => "Made with",
                "producer" => "Turned into a PDF by",
                _ => "Edited with",
            };
            clue(
                "made_with",
                format!(
                    "{verb} {} (\u{201c}{}\u{201d}): {}.",
                    t.name,
                    clip(v, 80),
                    kind_text(t.kind)
                ),
                conf,
            );
            if first_kind.is_none() {
                first_kind = Some(t.kind);
            }
        }
    }
    if tools_seen.is_empty()
        && let Some((_, v)) = sources.first()
    {
        clue(
            "made_with",
            format!(
                "Made with software that identifies itself as \u{201c}{}\u{201d}.",
                clip(v, 80)
            ),
            Confidence::Medium,
        );
    }
    // Device / operating system versions.
    for (_, v) in &sources {
        let l = v.to_lowercase();
        if l.starts_with("mozilla/") {
            let os = if l.contains("(iphone") || l.contains("(ipad") {
                Some("an iPhone or iPad")
            } else if l.contains("android") {
                Some("an Android device")
            } else if l.contains("(macintosh") {
                Some("a Mac")
            } else if l.contains("(windows") {
                Some("a Windows PC")
            } else if l.contains("linux") || l.contains("(x11") {
                Some("a Linux computer")
            } else {
                None
            };
            if let Some(os) = os {
                clue(
                    "device",
                    format!("Created in a web browser on {os}."),
                    Confidence::High,
                );
            }
        } else if let Some(p) = l.find("macos version ").or_else(|| l.find("mac os x ")) {
            let ver: String = v[p..]
                .chars()
                .take(40)
                .take_while(|c| *c != ')' && *c != ';')
                .collect();
            clue(
                "device",
                format!("Created on a Mac ({}).", ver.trim()),
                Confidence::High,
            );
        } else if let Some(p) = l.find("ios version ") {
            let ver: String = v[p..].chars().take(30).take_while(|c| *c != ')').collect();
            clue(
                "device",
                format!("Created on an iPhone or iPad ({}).", ver.trim()),
                Confidence::High,
            );
        } else if l.contains("android") {
            clue(
                "device",
                "Created on an Android phone or tablet.".into(),
                Confidence::High,
            );
        } else if l.contains("windows") || l.contains("pscript5") || l.contains("print to pdf") {
            clue(
                "device",
                "Created on a Windows PC.".into(),
                Confidence::Medium,
            );
        } else if l.contains("for mac") {
            clue("device", "Created on a Mac.".into(), Confidence::High);
        } else if l.contains("linux") || l.contains("ubuntu") {
            clue(
                "device",
                "Created on a Linux computer.".into(),
                Confidence::Medium,
            );
        }
    }
    if let (Some(cr), Some(pr)) = (
        creator.as_deref().and_then(tool_for),
        producer.as_deref().and_then(tool_for),
    ) && cr.kind != pr.kind
        && (pr.kind == Kind::Online || pr.kind == Kind::Viewer || pr.kind == Kind::Esign)
    {
        clue(
            "edited",
            format!(
                "It was first made in {} and later processed by {}.",
                cr.name, pr.name
            ),
            Confidence::High,
        );
    }
    // Author.
    if let Some(a) = author.clone().or(x_author.clone()) {
        clue(
            "author",
            format!(
                "The author field says \u{201c}{a}\u{201d}. Programs usually fill this in from the computer\u{2019}s user account or Office user name, so it often names the person or organisation who created it (it can be edited, though)."
            ),
            Confidence::Medium,
        );
    }
    for sig in &r.signatures {
        let who = sig
            .signer
            .clone()
            .unwrap_or_else(|| "an unnamed signer".into());
        let when = sig
            .signed_at
            .as_deref()
            .map(|w| format!(" on {w}"))
            .unwrap_or_default();
        let by = sig
            .issuer
            .as_deref()
            .map(|i| format!(", with a certificate issued by {i}"))
            .unwrap_or_default();
        let when = format!("{when}{by}");
        clue(
            "signed",
            format!(
                "Digitally signed by {who}{when}.{}",
                if sig.covers_whole_file {
                    ""
                } else {
                    " The file was changed after this signature was applied."
                }
            ),
            Confidence::High,
        );
    }
    // Dates and time zone.
    if let Some(d) = created {
        let mut t = format!("Created {}", d.show());
        if let Some(m) = modified {
            let gap = m.epoch() - d.epoch();
            if gap > 120 {
                t.push_str(&format!(
                    "; last modified {} ({} later)",
                    m.show(),
                    human_gap(gap)
                ));
            } else if gap < -120 {
                t.push_str(&format!("; the \u{201c}modified\u{201d} date ({}) is earlier than the creation date, which suggests the dates were edited or the clock was wrong", m.show()));
            }
        }
        t.push('.');
        clue("dates", t, Confidence::High);
        if let Some(tz) = d.tz
            && tz != 0
        {
            let place = tz_region(tz)
                .map(|p| format!(", the time zone used in {p}"))
                .unwrap_or_default();
            clue(
                "region",
                format!(
                    "The creating device\u{2019}s clock was set to {}{place}.",
                    tz_str(tz)
                ),
                Confidence::Medium,
            );
        }
    }
    if let Some(lang) = c
        .catalog
        .as_ref()
        .and_then(|k| k.get("Lang"))
        .and_then(Obj::text)
    {
        clue(
            "region",
            format!("Document language is set to \u{201c}{lang}\u{201d}."),
            Confidence::Low,
        );
    }
    if let Some((w, h)) = c.first_mediabox {
        let p = paper(w, h);
        if p.starts_with("US Letter") || p.starts_with("US Legal") {
            clue(
                "region",
                format!(
                    "Page size is {p}, the standard in the US, Canada and parts of Latin America."
                ),
                Confidence::Low,
            );
        } else if p.starts_with("A4") {
            clue(
                "region",
                format!("Page size is {p}, the standard outside North America."),
                Confidence::Low,
            );
        }
    }
    // Edits.
    if r.revisions > 1 {
        let signed_saves = r.signatures.len() as u32;
        let last_signed_whole = r.signatures.last().is_some_and(|s| s.covers_whole_file);
        if signed_saves > 0 && r.revisions <= signed_saves + 1 && last_signed_whole {
            clue(
                "edited",
                format!(
                    "Saved {} times: the later save{} added the digital signature{}, which is normal for signed documents. Nothing was changed after the last signature.",
                    r.revisions,
                    if r.revisions > 2 { "s" } else { "" },
                    if signed_saves > 1 { "s" } else { "" }
                ),
                Confidence::High,
            );
        } else {
            clue(
                "edited",
                format!(
                    "Saved {} times (incremental updates). Something was added or changed after it was first written: a filled-in form, comments, a signature or edits.",
                    r.revisions
                ),
                Confidence::High,
            );
        }
    }
    if let (Some(a), Some(z)) = (ids.first(), ids.get(1))
        && a != z
    {
        clue(
            "edited",
            "Its permanent file ID differs from its current ID, so it was saved again by some program after it was first created.".into(),
            Confidence::Medium,
        );
    }
    if let (Some(p1), Some(p2)) = (&producer, &x_producer)
        && p1 != p2
    {
        clue(
            "edited",
            format!(
                "Two metadata blocks disagree about the producing software (\u{201c}{}\u{201d} vs \u{201c}{}\u{201d}): it was re-saved by different software.",
                clip(p1, 60),
                clip(p2, 60)
            ),
            Confidence::Medium,
        );
    }
    for (k, v) in &previous {
        if (k == "Producer" || k == "Creator") && iget(k).as_deref() != Some(v.as_str()) {
            clue(
                "edited",
                format!(
                    "An earlier saved version recorded {k} \u{201c}{}\u{201d}; it has since changed to \u{201c}{}\u{201d}.",
                    clip(v, 60),
                    clip(&iget(k).unwrap_or_default(), 60)
                ),
                Confidence::High,
            );
        }
    }
    if !r.history.is_empty() {
        clue(
            "edited",
            format!(
                "The document records {} step(s) of edit history (see History).",
                r.history.len()
            ),
            Confidence::High,
        );
    }
    if let Some(d) = x("stRef:documentID") {
        clue(
            "identity",
            format!(
                "It was derived from another document with ID {}.",
                clip(&d, 60)
            ),
            Confidence::Medium,
        );
    }
    // Scanned?
    if c.fonts.is_empty() && c.images > 0 && r.pages.unwrap_or(0) > 0 {
        clue(
            "scanned",
            "Its pages are pictures without any text fonts, so it is probably a scan or a photo of a paper document.".into(),
            Confidence::Medium,
        );
    } else if first_kind == Some(Kind::Scanner) {
        clue(
            "scanned",
            "Produced by scanning software: likely a scan of paper.".into(),
            Confidence::High,
        );
    }
    // Font hints.
    let fl: Vec<String> = c.fonts.iter().map(|f| f.to_lowercase()).collect();
    let has_font = |p: &str| fl.iter().any(|f| f.contains(p));
    if tools_seen.is_empty() {
        if has_font("calibri") || has_font("aptos") || has_font("cambria") {
            clue("made_with", "Uses Microsoft Office fonts (Calibri/Cambria/Aptos), so it was probably written in Word or PowerPoint.".into(), Confidence::Low);
        } else if has_font("cmr10") || has_font("lmroman") || has_font("cmbx") {
            clue(
                "made_with",
                "Uses Computer Modern fonts, the LaTeX default.".into(),
                Confidence::Medium,
            );
        } else if has_font("sfpro") || has_font("helveticaneue") {
            clue(
                "made_with",
                "Uses Apple system fonts, so it was probably created on a Mac or iPhone.".into(),
                Confidence::Low,
            );
        }
    }
    if producer.is_none()
        && creator.is_none()
        && x_tool.is_none()
        && x_producer.is_none()
        && created.is_none()
    {
        clue(
            "identity",
            "It has no information about the software that made it and no dates. Metadata was either never written or deliberately removed (privacy tools and some generators do this).".into(),
            Confidence::Medium,
        );
    }
    r.clues.sort_by_key(|c| {
        (
            std::cmp::Reverse(c.confidence),
            [
                "made_with",
                "device",
                "author",
                "signed",
                "dates",
                "edited",
                "scanned",
                "region",
                "identity",
            ]
            .iter()
            .position(|t| *t == c.topic)
            .unwrap_or(99),
        )
    });
    r
}

fn human_gap(secs: i64) -> String {
    let m = secs / 60;
    match m {
        0..=89 => format!("{m} minutes"),
        90..=2879 => format!("{} hours", m / 60),
        2880..=86_399 => format!("{} days", m / 1440),
        _ => format!("{:.1} years", m as f64 / 525_960.0),
    }
}

fn paper(w: f64, h: f64) -> String {
    let (a, b) = if w <= h { (w, h) } else { (h, w) };
    let near = |x: f64, y: f64| (a - x).abs() < 4.0 && (b - y).abs() < 4.0;
    let orient = if w > h { ", landscape" } else { "" };
    let name = if near(612.0, 792.0) {
        "US Letter"
    } else if near(612.0, 1008.0) {
        "US Legal"
    } else if near(595.0, 842.0) {
        "A4"
    } else if near(420.0, 595.0) {
        "A5"
    } else if near(842.0, 1191.0) {
        "A3"
    } else {
        return format!("{:.0} \u{00d7} {:.0} mm", w / 72.0 * 25.4, h / 72.0 * 25.4);
    };
    format!("{name}{orient}")
}

/// Per-object bookkeeping: information dictionaries, XMP packets, walking.
/// Number of leaf entries in a name tree (`/Names [key value …]`, `/Kids`).
fn tree_entries(t: &Obj, lookup: &dyn Fn(&Obj) -> Option<Obj>, depth: usize) -> u32 {
    if depth > 16 {
        return 0;
    }
    let mut n = match t.get("Names") {
        Some(Obj::Arr(a)) => (a.len() / 2) as u32,
        _ => 0,
    };
    if let Some(Obj::Arr(kids)) = t.get("Kids") {
        for k in kids.iter().take(1000) {
            if let Some(k) = lookup(k) {
                n += tree_entries(&k, lookup, depth + 1);
            }
        }
    }
    n
}

fn handle(c: &mut Collect, num: u32, obj: &Obj, stream: Option<&[u8]>, file_len: usize) {
    if obj.get("Type").is_none()
        && c.name_dicts.len() < 5000
        && obj.dict_keys().any(|k| {
            matches!(
                k,
                "Names" | "Kids" | "JavaScript" | "EmbeddedFiles" | "Dests"
            )
        })
    {
        c.name_dicts.insert(num, obj.clone());
    }
    if let Some(f) = info_fields(obj) {
        c.info_versions.push((num, f));
    }
    if obj.type_is("Metadata")
        && obj.get("Subtype").is_some_and(|s| s.is_name("XML"))
        && let Some(data) = stream
        && c.xmp_bytes < 4 * MAX_XMP
    {
        let filters = obj.filters();
        let bytes = if filters.is_empty() {
            data.get(..MAX_XMP.min(data.len())).unwrap_or(data).to_vec()
        } else if filters == ["FlateDecode"] {
            inflate(data, MAX_XMP)
        } else {
            Vec::new()
        };
        if !bytes.is_empty() {
            c.xmp_bytes += bytes.len();
            c.xmp
                .insert(num, String::from_utf8_lossy(&bytes).into_owned());
        }
    }
    c.walk(obj, file_len, 0);
}

/// Decode an object stream and process the objects inside it.
fn objstm(c: &mut Collect, obj: &Obj, data: &[u8], file_len: usize) {
    if obj.filters() != ["FlateDecode"] || c.objstm_total >= MAX_OBJSTM_TOTAL {
        c.objstm_failed += 1;
        return;
    }
    let dec = inflate(data, MAX_OBJSTM_OUT.min(MAX_OBJSTM_TOTAL - c.objstm_total));
    c.objstm_total += dec.len();
    if dec.is_empty() {
        c.objstm_failed += 1;
        return;
    }
    let n = obj
        .get("N")
        .and_then(Obj::num)
        .unwrap_or(0.0)
        .clamp(0.0, 100_000.0) as usize;
    let first = obj.get("First").and_then(Obj::num).unwrap_or(0.0).max(0.0) as usize;
    let mut p = Parser::new(&dec, 0);
    let mut idx = Vec::with_capacity(n.min(4096));
    for _ in 0..n {
        let (Some(Obj::Num(num)), Some(Obj::Num(off))) = (p.object(0), p.object(0)) else {
            break;
        };
        idx.push((num.max(0.0) as u32, off.max(0.0) as usize));
    }
    for (num, off) in idx {
        if c.objects >= MAX_OBJECTS {
            break;
        }
        let Some(start) = first.checked_add(off).filter(|&s| s < dec.len()) else {
            continue;
        };
        if let Some(o) = Parser::new(&dec, start).object(0) {
            c.objects += 1;
            handle(c, num, &o, None, file_len);
            if o.type_is("XRef") {
                c.trailers.push(o);
            }
        }
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn deflate(b: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b).unwrap();
        e.finish().unwrap()
    }

    /// Assemble a PDF from object bodies (1-based numbering) and a trailer.
    fn pdf(objs: &[Vec<u8>], trailer: &str) -> Vec<u8> {
        let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
        for (i, o) in objs.iter().enumerate() {
            out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            out.extend_from_slice(o);
            out.extend_from_slice(b"\nendobj\n");
        }
        out.extend_from_slice(format!("trailer\n{trailer}\nstartxref\n0\n%%EOF\n").as_bytes());
        out
    }

    fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
        let mut o = format!("<< {dict} /Length {} >>\nstream\n", data.len()).into_bytes();
        o.extend_from_slice(data);
        o.extend_from_slice(b"\nendstream");
        o
    }

    #[test]
    fn word_document_on_windows_in_india() {
        let xmp = br#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/" xmp:CreatorTool="Microsoft&#174; Word for Microsoft 365" xmpMM:DocumentID="uuid:ABC"><dc:creator><rdf:Seq><rdf:li>Asha Rao</rdf:li></rdf:Seq></dc:creator><xmpMM:History><rdf:Seq><rdf:li stEvt:action="converted" stEvt:when="2024-03-01T10:00:00+05:30" stEvt:softwareAgent="Acrobat 23"/></rdf:Seq></xmpMM:History></rdf:Description></rdf:RDF></x:xmpmeta>"#;
        let objs = vec![
            b"<< /Type /Catalog /Pages 2 0 R /Metadata 4 0 R /Lang (en-IN) >>".to_vec(),
            b"<< /Type /Pages /Count 3 /Kids [5 0 R] /MediaBox [0 0 595.32 841.92] >>".to_vec(),
            b"<< /Author (Asha Rao) /Creator (Microsoft\xae Word for Microsoft 365) /Producer (Microsoft\xae Word for Microsoft 365) /CreationDate (D:20240301095512+05'30') /ModDate (D:20240302110000+05'30') /Company (Acme Pvt Ltd) >>".to_vec(),
            stream("/Type /Metadata /Subtype /XML /Filter /FlateDecode", &deflate(xmp)),
            b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 << /Type /Font /BaseFont /ABCDEF+Calibri >> >> >> /Annots [<< /Subtype /Link /A << /S /URI /URI (https://example.com/apply) >> >>] >>".to_vec(),
        ];
        let b = pdf(&objs, "<< /Root 1 0 R /Info 3 0 R /ID [<0011> <0022>] >>");
        let r = analyze(&b);
        assert_eq!(r.version.as_deref(), Some("1.7"));
        assert_eq!(r.pages, Some(3));
        assert_eq!(r.page_size.as_deref(), Some("A4"));
        assert_eq!(r.risk, Severity::Info, "{:?}", r.features);
        assert_eq!(r.fonts, vec!["Calibri".to_string()]);
        assert_eq!(r.links, vec!["https://example.com/apply".to_string()]);
        assert!(
            r.metadata
                .iter()
                .any(|m| m.key == "Company" && m.value == "Acme Pvt Ltd")
        );
        assert!(
            r.metadata
                .iter()
                .any(|m| m.key == "Document ID" && m.value == "uuid:ABC")
        );
        assert_eq!(r.history.len(), 1);
        assert_eq!(r.history[0].software.as_deref(), Some("Acrobat 23"));
        let all: String = r
            .clues
            .iter()
            .map(|c| c.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(all.contains("Microsoft Word"), "{all}");
        assert!(all.contains("India"), "{all}");
        assert!(all.contains("Asha Rao"), "{all}");
        assert!(
            all.contains("1 days later")
                || all.contains("hours later")
                || all.contains("days later"),
            "{all}"
        );
        assert!(all.contains("saved again"), "{all}");
    }

    #[test]
    fn script_on_open_is_high_risk_even_when_obfuscated() {
        let objs = vec![
            b"<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /#4Aava#53cript /#4AS 3 0 R >> >>"
                .to_vec(),
            b"<< /Type /Pages /Count 0 /Kids [] >>".to_vec(),
            // `/#4Aava#53cript` hides "/JavaScript" from naive scanners.
            b"(app.alert\\(1\\))".to_vec(),
            b"<< /Type /Filespec /F (invoice.pdf.exe) /EF << /F 5 0 R >> >>".to_vec(),
            stream("/Type /EmbeddedFile", b"MZ"),
        ];
        let b = pdf(&objs, "<< /Root 1 0 R >>");
        let r = analyze(&b);
        assert_eq!(r.risk, Severity::High, "{:?}", r.features);
        let names: Vec<&str> = r.features.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"JavaScript"), "{names:?}");
        assert!(names.contains(&"Risky attachment"), "{names:?}");
        assert!(names.contains(&"Script runs on open"), "{names:?}");
        assert_eq!(r.embedded_files, vec!["invoice.pdf.exe".to_string()]);
    }

    #[test]
    fn object_streams_incremental_updates_and_signatures() {
        // Info dictionary and catalog inside a compressed object stream.
        let inner = b"<< /Type /Catalog /Pages 4 0 R >> << /Producer (iLovePDF) /Creator (Microsoft Word) /CreationDate (D:20230101000000Z) >> ";
        let header = b"1 0 6 34 ";
        let mut body = header.to_vec();
        body.extend_from_slice(inner);
        let objstm = stream(
            &format!(
                "/Type /ObjStm /N 2 /First {} /Filter /FlateDecode",
                header.len()
            ),
            &deflate(&body),
        );
        let sig = format!(
            "<< /Type /Sig /Filter /Adobe.PPKLite /Name (Ravi Kumar) /M (D:20230105120000+05'30') /ByteRange [0 10 20 30] /Contents <{}> >>",
            hex_of_bytes(&[cert("Test CA", "Test CA"), cert("Ravi Kumar", "Test CA")].concat())
        );
        let objs = vec![
            b"<< /Type /Catalog /Pages 4 0 R >>".to_vec(),
            b"<< /Producer (old) >>".to_vec(),
            objstm,
            b"<< /Type /Pages /Count 1 /Kids [] >>".to_vec(),
            sig.into_bytes(),
        ];
        let mut b = pdf(&objs, "<< /Root 1 0 R /Info 2 0 R >>");
        b.extend_from_slice(b"2 0 obj\n<< /Producer (iLovePDF) /Creator (Microsoft Word) /CreationDate (D:20230101000000Z) >>\nendobj\ntrailer\n<< /Root 1 0 R /Info 2 0 R /Prev 0 >>\nstartxref\n0\n%%EOF\n");
        let r = analyze(&b);
        assert_eq!(r.revisions, 2);
        assert_eq!(r.signatures.len(), 1);
        assert_eq!(r.signatures[0].signer.as_deref(), Some("Ravi Kumar"));
        assert!(
            r.signatures[0]
                .certificate_names
                .contains(&"Ravi Kumar".to_string())
        );
        assert_eq!(r.signatures[0].issuer.as_deref(), Some("Test CA"));
        assert!(!r.signatures[0].covers_whole_file);
        let all: String = r
            .clues
            .iter()
            .map(|c| c.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(all.contains("iLovePDF"), "{all}");
        assert!(all.contains("later processed by"), "{all}");
        assert!(all.contains("changed after this signature"), "{all}");
        assert!(all.contains("Saved 2 times"), "{all}");
        assert!(all.contains("earlier saved version"), "{all}");
    }

    fn hex_of_bytes(s: &[u8]) -> String {
        s.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        if body.len() < 128 {
            v.push(body.len() as u8);
        } else {
            v.extend_from_slice(&[0x82, (body.len() >> 8) as u8, body.len() as u8]);
        }
        v.extend_from_slice(body);
        v
    }

    fn x509_name(cn: &str) -> Vec<u8> {
        let attr = [tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, cn.as_bytes())].concat();
        tlv(0x30, &tlv(0x31, &tlv(0x30, &attr)))
    }

    /// Minimal certificate: just enough structure for `certificates()`.
    fn cert(subject: &str, issuer: &str) -> Vec<u8> {
        let tbs = [
            tlv(0xa0, &tlv(0x02, &[2])),
            tlv(0x02, &[1]),
            tlv(0x30, &tlv(0x06, &[0x2a, 0x86, 0x48])),
            x509_name(issuer),
            tlv(0x30, &tlv(0x17, b"250101000000Z")),
            x509_name(subject),
            tlv(0x30, &tlv(0x03, &[0])),
        ]
        .concat();
        let body = [
            tlv(0x30, &tbs),
            tlv(0x30, &tlv(0x06, &[0x2a])),
            tlv(0x03, &[0]),
        ]
        .concat();
        tlv(0x30, &body)
    }

    #[test]
    fn document_level_scripts() {
        // A dangling name tree (as in Google exports) is not a script…
        let objs = vec![b"<< /Type /Catalog /Names << /JavaScript 9 0 R >> >>".to_vec()];
        let r = analyze(&pdf(&objs, "<< /Root 1 0 R >>"));
        assert_eq!(r.risk, Severity::Info, "{:?}", r.features);
        // …but a populated one runs on open.
        let objs = vec![
            b"<< /Type /Catalog /Names 2 0 R >>".to_vec(),
            b"<< /JavaScript 3 0 R >>".to_vec(),
            b"<< /Names [(init) 4 0 R] >>".to_vec(),
            b"<< /S /JavaScript /JS (this.print\\(\\)) >>".to_vec(),
        ];
        let r = analyze(&pdf(&objs, "<< /Root 1 0 R >>"));
        assert_eq!(r.risk, Severity::High, "{:?}", r.features);
    }

    #[test]
    fn dates_parse() {
        let d = parse_date("D:20240301095512+05'30'").unwrap();
        assert_eq!(
            (d.y, d.mo, d.d, d.h, d.mi, d.s, d.tz),
            (2024, 3, 1, 9, 55, 12, Some(330))
        );
        let x = parse_date("2024-03-01T09:55:12.120+05:30").unwrap();
        assert_eq!(d.epoch(), x.epoch());
        assert_eq!(parse_date("D:2024").unwrap().mo, 1);
        assert!(parse_date("garbage").is_none());
        assert_eq!(parse_date("D:20240301095512Z").unwrap().tz, Some(0));
    }

    #[test]
    fn text_strings_decode() {
        assert_eq!(decode_text(&[0xfe, 0xff, 0, b'H', 0, b'i']), "Hi");
        let mut p = Parser::new(b"(a\\(b\\)\\101\\\nc)", 1);
        assert_eq!(p.literal(), b"a(b)Ac");
        let mut p = Parser::new(b"<48 6>", 1);
        assert_eq!(p.hex(), b"H`");
    }

    #[test]
    fn hostile_inputs_do_not_panic() {
        let cases: Vec<Vec<u8>> = vec![
            b"%PDF-1.4\n1 0 obj << /Length 99999999999 >> stream\nabc".to_vec(),
            b"%PDF-1.4\n1 0 obj [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[".to_vec(),
            b"%PDF-1.4\n1 0 obj << /Type /ObjStm /N 99999 /First 5 /Filter /FlateDecode /Length 3 >> stream\nxyz\nendstream".to_vec(),
            b"%PDF-1.4\n0 0 obj (\\".to_vec(),
            b"%PDF-1.4\ntrailer << /ID [<zz> 5 0 R] /Info 99 0 R >>".to_vec(),
            b"obj obj 1 obj 1 1 obj".to_vec(),
            vec![b'['; 100_000],
        ];
        for c in cases {
            let _ = analyze(&c);
        }
    }

    #[test]
    fn xmp_forms() {
        let x = r#" <x:a xmp:CreatorTool="A &amp; B"/><pdf:Producer>P<b/></pdf:Producer><dc:title><rdf:Alt><rdf:li xml:lang="x-default">T1</rdf:li></rdf:Alt></dc:title>"#;
        assert_eq!(xmp_get(x, "xmp:CreatorTool").as_deref(), Some("A & B"));
        assert_eq!(xmp_get(x, "pdf:Producer").as_deref(), Some("P"));
        assert_eq!(xmp_get(x, "dc:title").as_deref(), Some("T1"));
        assert_eq!(xmp_get(x, "dc:missing"), None);
    }
}
