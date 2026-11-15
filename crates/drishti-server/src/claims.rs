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
}
