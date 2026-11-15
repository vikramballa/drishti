//! Checkable claims in AI answers (Day 4, roadmap D3). The model is asked to
//! end its answer with a `<claims>` block that lists the concrete things it
//! relied on, one per line:
//!
//! ```text
//! <claims>
//! imports: SecItemCopyMatching
//! calls: sub_100004a20 -> connect
//! string: https://api.example.com/v1
//! address: 0x100004a20
//! function: main
//! </claims>
//! ```
//!
//! [`parse`] splits an answer into the prose people read and the claims a
//! checker can test against the call graph, imports, strings and addresses
//! (Day 5). Answers without a block (older models, older chats) are plain
//! prose with no claims, so they display exactly as before. Parsing is
//! lenient: bullets, code fences, quotes, `[F3]` citations, a missing
//! closing tag (a cut-off stream) and unknown kinds are all tolerated.

use serde::Serialize;

/// What a claim says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    /// `subject` (a function, or the file when absent) calls `target`.
    Calls,
    /// The file imports `target` (a symbol or library).
    Imports,
    /// The file contains the text `target`.
    String,
    /// `target` is an address in the file.
    Address,
    /// A function named (or at) `target` exists.
    Function,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Claim {
    pub kind: ClaimKind,
    /// The thing being cited.
    pub target: String,
    /// For `calls`: the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Fact ids cited on the claim line (`[F3]`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub facts: Vec<u32>,
}

/// An answer split into prose and claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Parsed {
    pub prose: String,
    pub claims: Vec<Claim>,
}

/// Instructions appended to the system prompt.
pub const PROMPT: &str = "- After the answer, add a claims block listing the concrete things you relied on, one per line, using only these kinds:\n\
<claims>\n\
calls: <function> -> <function or API it calls>\n\
imports: <imported function or library>\n\
string: <exact text found in the file>\n\
address: <hex address>\n\
function: <function name or address>\n\
</claims>\n\
  Copy names, text and addresses exactly as they appear in the FACTS. Leave the block out if you made no such claims. It is not shown to the person and does not count towards the word limit.";

const MAX_CLAIMS: usize = 64;
const MAX_VALUE: usize = 300;
const OPEN: &str = "<claims>";
const CLOSE: &str = "</claims>";

/// Split an answer into prose and claims.
pub fn parse(answer: &str) -> Parsed {
    let lower = answer.to_ascii_lowercase();
    // The last block wins: a model may quote the format earlier.
    let Some(open) = lower.rfind(OPEN) else {
        return Parsed {
            prose: answer.trim().to_string(),
            claims: Vec::new(),
        };
    };
    let body_start = open + OPEN.len();
    let body_end = lower[body_start..]
        .find(CLOSE)
        .map_or(answer.len(), |i| body_start + i);
    let tail = lower[body_end..]
        .find(CLOSE)
        .map_or(answer.len(), |i| body_end + i + CLOSE.len());

    let mut prose = answer[..open].trim_end().to_string();
    // A block wrapped in a code fence leaves a dangling opening fence
    // ("```" or "```text"); a fence that closes a real code block stays.
    if prose.matches("```").count() % 2 == 1
        && let Some(i) = prose.rfind("```")
        && prose[i + 3..].chars().all(|c| c.is_ascii_alphabetic())
    {
        prose = prose[..i].trim_end().to_string();
    }
    let after = answer[tail..].trim().trim_start_matches("```").trim();
    if !after.is_empty() {
        prose.push_str("\n\n");
        prose.push_str(after);
    }

    let mut claims: Vec<Claim> = Vec::new();
    for line in answer[body_start..body_end].lines() {
        if claims.len() >= MAX_CLAIMS {
            break;
        }
        if let Some(c) = parse_line(line)
            && !claims.contains(&c)
        {
            claims.push(c);
        }
    }
    Parsed {
        prose: prose.trim().to_string(),
        claims,
    }
}

fn parse_line(line: &str) -> Option<Claim> {
    let mut l = line.trim();
    if l.starts_with("```") {
        return None;
    }
    // Bullets and numbering: "- ", "* ", "• ", "1. ", "2) ".
    l = l.trim_start_matches(['-', '*', '•']).trim_start();
    let digits = l.len() - l.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    if digits > 0 && l[digits..].starts_with(['.', ')']) {
        l = l[digits + 1..].trim_start();
    }
    let (kind, value) = l.split_once(':')?;
    let kind = match kind
        .trim()
        .trim_matches(['*', '`', '"'])
        .to_ascii_lowercase()
        .as_str()
    {
        "calls" | "call" => ClaimKind::Calls,
        "imports" | "import" => ClaimKind::Imports,
        "string" | "strings" | "text" => ClaimKind::String,
        "address" | "addr" => ClaimKind::Address,
        "function" | "func" | "fn" => ClaimKind::Function,
        _ => return None,
    };
    let (value, facts) = strip_cites(value);
    let (subject, target) = match kind {
        ClaimKind::Calls => match value.split_once("->").or_else(|| value.split_once('→')) {
            Some((s, t)) => (Some(clean(s)).filter(|s| !s.is_empty()), clean(t)),
            None => (None, clean(&value)),
        },
        // Strings are compared exactly: only strip the wrapping quotes.
        ClaimKind::String => (None, unquote(value.trim())),
        _ => (None, clean(&value)),
    };
    if target.is_empty() {
        return None;
    }
    Some(Claim {
        kind,
        target: clip(target),
        subject: subject.map(clip),
        facts,
    })
}

/// Remove `[F3]` / `[F3, F7]` citations, returning the fact ids.
fn strip_cites(v: &str) -> (String, Vec<u32>) {
    let mut out = String::with_capacity(v.len());
    let mut facts = Vec::new();
    let mut rest = v;
    while let Some(i) = rest.find("[F") {
        let Some(j) = rest[i..].find(']') else { break };
        let inner = &rest[i + 1..i + j];
        let ids: Option<Vec<u32>> = inner
            .split(',')
            .map(|s| s.trim().trim_start_matches('F').parse().ok())
            .collect();
        match ids {
            Some(ids) => {
                out.push_str(&rest[..i]);
                facts.extend(ids);
            }
            None => out.push_str(&rest[..i + j + 1]),
        }
        rest = &rest[i + j + 1..];
    }
    out.push_str(rest);
    facts.dedup();
    (out, facts)
}

fn unquote(s: &str) -> String {
    for q in ['"', '`', '\'', '“'] {
        let close = if q == '“' { '”' } else { q };
        if let Some(inner) = s.strip_prefix(q).and_then(|r| r.strip_suffix(close)) {
            return inner.to_string();
        }
    }
    s.to_string()
}

/// Names and addresses: trim, unquote, drop a trailing `()` and punctuation.
fn clean(s: &str) -> String {
    let s = unquote(s.trim());
    let s = s.trim().trim_end_matches(['.', ',', ';']);
    let s = s.strip_suffix("()").unwrap_or(s);
    s.trim().to_string()
}

fn clip(mut s: String) -> String {
    if s.len() > MAX_VALUE {
        let mut cut = MAX_VALUE;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

// ---- Checker (Day 5) ---------------------------------------------------------

/// Outcome of checking one claim against Drishti's own results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The file's call graph, imports, strings or addresses confirm it.
    Verified,
    /// Drishti has the data and it says otherwise.
    Refuted,
    /// Drishti cannot tell (no analysis, ambiguous, or not checkable).
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Checked {
    #[serde(flatten)]
    pub claim: Claim,
    pub status: Verdict,
    /// One plain sentence: why this verdict.
    pub reason: String,
}

/// What the checker may ask about the open file. Implemented over a loaded
/// session in `ai.rs`; tests use a small fake.
pub trait Evidence {
    /// The file was parsed as an executable image (imports, addresses).
    fn has_image(&self) -> bool;
    /// Functions and the call graph are available.
    fn analysed(&self) -> bool;
    /// Entries of functions whose name (or user rename) matches `norm`
    /// (see [`norm`]).
    fn functions_named(&self, norm: &str) -> Vec<u64>;
    /// `(entry, name)` of the function starting at or containing `addr`.
    fn function_at(&self, addr: u64) -> Option<(u64, String)>;
    fn is_mapped(&self, addr: u64) -> bool;
    /// Addresses an import is reached through (pointer slot, stubs), or
    /// `None` if the file does not import `norm`.
    fn import_addrs(&self, norm: &str) -> Option<Vec<u64>>;
    /// The file links a library whose name matches `norm`.
    fn links_library(&self, norm: &str) -> bool;
    /// Direct call targets of the function at `entry`.
    fn calls_of(&self, entry: u64) -> Vec<u64>;
    /// Some code calls or jumps to `addr`.
    fn is_called(&self, addr: u64) -> bool;
    /// The file contains `text` (extracted strings or raw UTF-8/UTF-16LE).
    fn contains_text(&self, text: &str) -> bool;
}

/// Normalise a symbol name for comparison: no surrounding `_`, no `@plt` /
/// `@@GLIBC_2.2` / `$UNIX2003` suffix, no `()`, lower case.
pub fn norm(name: &str) -> String {
    let n = name.trim().strip_suffix("()").unwrap_or(name.trim());
    let n = n.split('@').next().unwrap_or(n);
    let n = n.split('$').next().unwrap_or(n);
    n.trim_start_matches('_').to_ascii_lowercase()
}

/// Parse `0x1234`, `1234h`, `sub_1234` or bare hex (with a hex letter or
/// at least 5 digits, so small decimal-looking numbers are not guessed).
pub fn parse_addr(s: &str) -> Option<u64> {
    let t = s.trim().trim_matches('`');
    let lower = t.to_ascii_lowercase();
    let hex = if let Some(h) = lower.strip_prefix("0x") {
        h
    } else if let Some(h) = lower
        .strip_prefix("sub_")
        .or_else(|| lower.strip_prefix("fun_"))
    {
        h
    } else if let Some(h) = lower.strip_suffix('h') {
        h
    } else if lower.len() >= 5 && lower.chars().all(|c| c.is_ascii_hexdigit()) {
        &lower
    } else {
        return None;
    };
    let hex = hex.replace(['_', '\''], "");
    if hex.is_empty() || hex.len() > 16 {
        return None;
    }
    u64::from_str_radix(&hex, 16).ok()
}

/// "the network code" is a description; `operator new(unsigned long)` and
/// `ns::Foo::bar` are names.
fn looks_like_prose(s: &str) -> bool {
    s.trim().contains(' ') && !s.contains(['(', ':', '<'])
}

/// Functions a name or address refers to.
fn resolve_function(ev: &dyn Evidence, s: &str) -> Vec<u64> {
    let mut v = ev.functions_named(&norm(s));
    if v.is_empty()
        && let Some(a) = parse_addr(s)
        && let Some((e, _)) = ev.function_at(a)
    {
        v.push(e);
    }
    v
}

/// Check every claim. Claims are independent; order is kept.
pub fn check(claims: &[Claim], ev: &dyn Evidence) -> Vec<Checked> {
    claims
        .iter()
        .map(|c| {
            let (status, reason) = check_one(c, ev);
            Checked {
                claim: c.clone(),
                status,
                reason,
            }
        })
        .collect()
}

fn check_one(c: &Claim, ev: &dyn Evidence) -> (Verdict, String) {
    use Verdict::*;
    let t = c.target.as_str();
    match c.kind {
        ClaimKind::String => {
            if t.chars().count() < 3 {
                return (Unverified, "Too short to check.".into());
            }
            if ev.contains_text(t) {
                (Verified, "This text is in the file.".into())
            } else {
                (Refuted, "This exact text is not in the file.".into())
            }
        }
        ClaimKind::Address => {
            let Some(a) = parse_addr(t) else {
                return (Unverified, "Not an address Drishti can read.".into());
            };
            if !ev.has_image() {
                return (Unverified, "This file has no code addresses.".into());
            }
            if !ev.is_mapped(a) {
                return (Refuted, format!("{a:#x} is not an address in this file."));
            }
            match ev.function_at(a) {
                Some((e, n)) if e == a => (Verified, format!("{a:#x} is the start of {n}.")),
                Some((_, n)) => (Verified, format!("{a:#x} is inside {n}.")),
                None => (Verified, format!("{a:#x} is in the file.")),
            }
        }
        ClaimKind::Imports => {
            if !ev.has_image() {
                return (Unverified, "This file has no import table.".into());
            }
            let n = norm(t);
            if ev.import_addrs(&n).is_some() {
                (Verified, format!("The file imports {t}."))
            } else if ev.links_library(&n) {
                (Verified, format!("The file links the {t} library."))
            } else {
                (Refuted, format!("{t} is not in the file's imports."))
            }
        }
        ClaimKind::Function => {
            if looks_like_prose(t) {
                return (
                    Unverified,
                    "This is a description, not a function name.".into(),
                );
            }
            if !ev.analysed() {
                return (Unverified, "Functions have not been analysed.".into());
            }
            match resolve_function(ev, t).first() {
                Some(&e) => {
                    let n = ev.function_at(e).map_or_else(|| t.to_string(), |f| f.1);
                    (Verified, format!("{n} is a function at {e:#x}."))
                }
                None => (Refuted, format!("No function called {t} was found.")),
            }
        }
        ClaimKind::Calls => {
            if !ev.analysed() {
                return (Unverified, "The call graph is not available.".into());
            }
            // Where a call to the target would land: its functions (thunks
            // are named after their import), import slots and stubs.
            let n = norm(t);
            let mut targets = ev.functions_named(&n);
            targets.extend(ev.import_addrs(&n).unwrap_or_default());
            if targets.is_empty()
                && let Some(a) = parse_addr(t)
            {
                targets.push(a);
            }
            if targets.is_empty() {
                return (
                    Refuted,
                    format!("{t} is not a function or import in this file."),
                );
            }
            let Some(subject) = c.subject.as_deref() else {
                return if targets.iter().any(|&a| ev.is_called(a)) {
                    (Verified, format!("The file's code calls {t}."))
                } else {
                    (Refuted, format!("No code in the file calls {t} directly."))
                };
            };
            let callers = resolve_function(ev, subject);
            if callers.is_empty() {
                return (Refuted, format!("No function called {subject} was found."));
            }
            if callers
                .iter()
                .any(|&f| ev.calls_of(f).iter().any(|x| targets.contains(x)))
            {
                (Verified, format!("{subject} calls {t}."))
            } else {
                (
                    Refuted,
                    format!(
                        "Drishti sees no direct call from {subject} to {t} (calls through pointers can't be ruled out)."
                    ),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(kind: ClaimKind, target: &str, subject: Option<&str>, facts: &[u32]) -> Claim {
        Claim {
            kind,
            target: target.into(),
            subject: subject.map(str::to_string),
            facts: facts.to_vec(),
        }
    }

    /// Day 4 "done when": a sample answer parsed into claims.
    #[test]
    fn sample_answer_is_parsed_into_claims() {
        let answer = "**Be careful.** This app can read saved passwords from your keychain [F12] \
and sends data to a web server [F31].\n\n\
- It contacts `api.example.com` [F40].\n\n\
<claims>\n\
imports: SecItemCopyMatching [F12]\n\
- calls: sub_100004a20 -> connect() [F31]\n\
2. string: \"https://api.example.com/v1/upload\" [F40]\n\
address: 0x100004a20\n\
function: `sub_100004a20`\n\
mood: suspicious\n\
imports: SecItemCopyMatching [F12]\n\
</claims>";
        let p = parse(answer);
        assert!(p.prose.starts_with("**Be careful.**"));
        assert!(p.prose.ends_with("[F40]."));
        assert!(!p.prose.contains("claims"));
        assert_eq!(
            p.claims,
            vec![
                claim(ClaimKind::Imports, "SecItemCopyMatching", None, &[12]),
                claim(ClaimKind::Calls, "connect", Some("sub_100004a20"), &[31]),
                claim(
                    ClaimKind::String,
                    "https://api.example.com/v1/upload",
                    None,
                    &[40]
                ),
                claim(ClaimKind::Address, "0x100004a20", None, &[]),
                claim(ClaimKind::Function, "sub_100004a20", None, &[]),
            ],
            "unknown kinds and duplicates are dropped"
        );
        // JSON shape the UI reads.
        let j = serde_json::to_value(&p.claims[1]).expect("json");
        assert_eq!(
            j,
            serde_json::json!({"kind": "calls", "target": "connect", "subject": "sub_100004a20", "facts": [31]})
        );
    }

    #[test]
    fn old_free_text_answers_are_unchanged() {
        let a = "  It looks normal [F2].\n\n- No network code was found.  ";
        let p = parse(a);
        assert_eq!(p.prose, a.trim());
        assert!(p.claims.is_empty());
    }

    #[test]
    fn tolerant_forms() {
        // Fenced block, upper-case tag, arrow variant, call without a caller.
        let p = parse(
            "Short answer.\n```\n<CLAIMS>\ncalls: main → system\ncalls: dlopen\nstring: has: colons\n</CLAIMS>\n```\nHope that helps.",
        );
        assert_eq!(p.prose, "Short answer.\n\nHope that helps.");
        assert_eq!(
            p.claims,
            vec![
                claim(ClaimKind::Calls, "system", Some("main"), &[]),
                claim(ClaimKind::Calls, "dlopen", None, &[]),
                claim(ClaimKind::String, "has: colons", None, &[]),
            ]
        );
        // A real code block right before the claims keeps its closing fence.
        let p = parse("See:\n```\nmov x0, #1\n```\n<claims>\nfunction: main\n</claims>");
        assert_eq!(p.prose, "See:\n```\nmov x0, #1\n```");
        let p = parse("Short.\n```text\n<claims>\nfunction: main\n</claims>\n```");
        assert_eq!(p.prose, "Short.");
        // A cut-off stream: no closing tag.
        let p = parse("Answer.\n<claims>\nimports: socket\nfunct");
        assert_eq!(p.prose, "Answer.");
        assert_eq!(
            p.claims,
            vec![claim(ClaimKind::Imports, "socket", None, &[])]
        );
        // Text in brackets that is not a citation stays.
        let p = parse("<claims>\nstring: [Fatal] error [F2]\n</claims>");
        assert_eq!(p.claims[0].target, "[Fatal] error");
        assert_eq!(p.claims[0].facts, vec![2]);
        // Empty values are skipped; huge ones are clipped on a char boundary.
        let long = "é".repeat(400);
        let p = parse(&format!("<claims>\nfunction:\nstring: {long}\n</claims>"));
        assert_eq!(p.claims.len(), 1);
        assert!(p.claims[0].target.len() <= MAX_VALUE);
    }

    /// A tiny fake file: main (0x1000) calls helper (0x2000) and the
    /// `connect` import (slot 0x9000, stub 0x3000); "hello world" is a string.
    struct Fake {
        analysed: bool,
    }

    impl Evidence for Fake {
        fn has_image(&self) -> bool {
            true
        }
        fn analysed(&self) -> bool {
            self.analysed
        }
        fn functions_named(&self, n: &str) -> Vec<u64> {
            match n {
                "main" => vec![0x1000],
                "helper" => vec![0x2000],
                _ => vec![],
            }
        }
        fn function_at(&self, a: u64) -> Option<(u64, String)> {
            match a {
                0x1000..0x1100 => Some((0x1000, "main".into())),
                0x2000..0x2100 => Some((0x2000, "helper".into())),
                _ => None,
            }
        }
        fn is_mapped(&self, a: u64) -> bool {
            (0x1000..0xa000).contains(&a)
        }
        fn import_addrs(&self, n: &str) -> Option<Vec<u64>> {
            (n == "connect").then(|| vec![0x9000, 0x3000])
        }
        fn links_library(&self, n: &str) -> bool {
            n == "libsystem.b.dylib"
        }
        fn calls_of(&self, e: u64) -> Vec<u64> {
            if e == 0x1000 {
                vec![0x2000, 0x3000]
            } else {
                vec![]
            }
        }
        fn is_called(&self, a: u64) -> bool {
            matches!(a, 0x2000 | 0x3000)
        }
        fn contains_text(&self, t: &str) -> bool {
            "hello world".contains(t)
        }
    }

    fn status(kind: ClaimKind, target: &str, subject: Option<&str>, ev: &dyn Evidence) -> Verdict {
        check(&[claim(kind, target, subject, &[])], ev)[0].status
    }

    /// Day 5 "done when": a true claim, a false claim and an uncheckable one.
    #[test]
    fn true_false_and_uncheckable_claims() {
        let ev = Fake { analysed: true };
        use ClaimKind::*;
        use Verdict::*;
        // True.
        assert_eq!(status(Calls, "connect()", Some("_main"), &ev), Verified);
        assert_eq!(status(Calls, "helper", Some("0x1000"), &ev), Verified);
        assert_eq!(status(Calls, "connect", None, &ev), Verified);
        assert_eq!(status(Imports, "_connect", None, &ev), Verified);
        assert_eq!(status(Imports, "libSystem.B.dylib", None, &ev), Verified);
        assert_eq!(status(String, "hello", None, &ev), Verified);
        assert_eq!(status(Address, "0x1010", None, &ev), Verified);
        assert_eq!(status(Function, "sub_2000", None, &ev), Verified);
        // False.
        assert_eq!(status(Calls, "system", Some("main"), &ev), Refuted);
        assert_eq!(status(Calls, "main", Some("helper"), &ev), Refuted);
        assert_eq!(status(Calls, "connect", Some("nosuchfn"), &ev), Refuted);
        assert_eq!(status(Imports, "SecItemCopyMatching", None, &ev), Refuted);
        assert_eq!(status(String, "goodbye", None, &ev), Refuted);
        assert_eq!(status(Address, "0xdead0000", None, &ev), Refuted);
        assert_eq!(status(Function, "login", None, &ev), Refuted);
        // Uncheckable.
        assert_eq!(status(Address, "the start", None, &ev), Unverified);
        assert_eq!(status(String, "hi", None, &ev), Unverified);
        assert_eq!(status(Function, "the network code", None, &ev), Unverified);
        let raw = Fake { analysed: false };
        assert_eq!(status(Calls, "connect", Some("main"), &raw), Unverified);
        assert_eq!(status(Function, "main", None, &raw), Unverified);
        // Reasons are plain sentences and the claim is kept.
        let c = check(&[claim(Calls, "main", Some("helper"), &[4])], &ev);
        assert!(c[0].reason.contains("no direct call"), "{}", c[0].reason);
        let c2 = check(&[claim(Calls, "system", Some("main"), &[])], &ev);
        assert!(c2[0].reason.contains("not a function or import"));
        let j = serde_json::to_value(&c[0]).expect("json");
        assert_eq!(j["status"], "refuted");
        assert_eq!(j["kind"], "calls");
        assert_eq!(j["facts"], serde_json::json!([4]));
    }

    #[test]
    fn names_and_addresses() {
        assert_eq!(norm("__stack_chk_fail"), "stack_chk_fail");
        assert_eq!(norm("printf@plt"), "printf");
        assert_eq!(norm("memcpy@@GLIBC_2.14"), "memcpy");
        assert_eq!(norm("_fopen$UNIX2003"), "fopen");
        assert_eq!(norm("Connect()"), "connect");
        assert_eq!(parse_addr("0x100004A20"), Some(0x1_0000_4a20));
        assert_eq!(parse_addr("sub_4a20"), Some(0x4a20));
        assert_eq!(parse_addr("401000h"), Some(0x40_1000));
        assert_eq!(parse_addr("100004a20"), Some(0x1_0000_4a20));
        assert_eq!(parse_addr("1234"), None);
        assert_eq!(parse_addr("main"), None);
        assert_eq!(parse_addr("0x"), None);
        assert_eq!(parse_addr("0x11112222333344445"), None);
    }
}
