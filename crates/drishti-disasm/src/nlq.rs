//! Natural-language → function-query translation (Feature 6).
//!
//! The target language is the existing function query (`search::FnQuery`), so a
//! translated query is transparent: it is shown to the user, runs through the
//! same parser as a hand-typed one, and can be edited. The server prefers an AI
//! translation (grounded by [`SYSTEM_PROMPT`]) and validates it with
//! `FnQuery::parse`; this module's [`heuristic`] is the offline fallback.

/// One concept the heuristic understands: any trigger word maps to query terms.
struct Concept {
    triggers: &'static [&'static str],
    terms: &'static [&'static str],
    note: &'static str,
}

const CONCEPTS: &[Concept] = &[
    Concept {
        triggers: &["json"],
        terms: &["str:json"],
        note: "references a JSON string",
    },
    Concept {
        triggers: &["xml"],
        terms: &["str:xml"],
        note: "references XML",
    },
    Concept {
        triggers: &["sql", "sqlite", "database"],
        terms: &["str:select"],
        note: "references SQL",
    },
    Concept {
        triggers: &["file", "disk", "write to disk", "save", "fopen"],
        terms: &["calls:fopen"],
        note: "opens a file",
    },
    Concept {
        triggers: &["read a file", "fread", "load from disk"],
        terms: &["calls:fread"],
        note: "reads a file",
    },
    Concept {
        triggers: &["network", "socket", "connect", "tcp", "udp"],
        terms: &["calls:socket"],
        note: "opens a socket",
    },
    Concept {
        triggers: &["http", "url", "web request", "download"],
        terms: &["str:http"],
        note: "references a URL",
    },
    Concept {
        triggers: &["receive", "recv", "incoming", "from the network"],
        terms: &["calls:recv"],
        note: "receives network data",
    },
    Concept {
        triggers: &["encrypt", "decrypt", "crypto", "cipher", "aes"],
        terms: &["calls:crypt"],
        note: "calls an encryption routine",
    },
    Concept {
        triggers: &["hash", "sha", "md5"],
        terms: &["calls:SHA"],
        note: "hashes data",
    },
    Concept {
        triggers: &["password", "credential", "secret", "token", "api key"],
        terms: &["str:password"],
        note: "references a password/credential string",
    },
    Concept {
        triggers: &["keychain", "secitem"],
        terms: &["calls:SecItem"],
        note: "uses the keychain",
    },
    Concept {
        triggers: &["command", "shell", "spawn", "execute a program", "system("],
        terms: &["calls:system"],
        note: "runs a shell command",
    },
    Concept {
        triggers: &["process", "fork", "exec"],
        terms: &["calls:exec"],
        note: "starts a process",
    },
    Concept {
        triggers: &["allocate", "malloc", "heap"],
        terms: &["calls:malloc"],
        note: "allocates memory",
    },
    Concept {
        triggers: &["copy memory", "memcpy", "buffer copy"],
        terms: &["calls:memcpy"],
        note: "copies memory",
    },
    Concept {
        triggers: &["print", "format string", "printf"],
        terms: &["calls:printf"],
        note: "formats output",
    },
    Concept {
        triggers: &["registry", "hkey"],
        terms: &["str:HKEY"],
        note: "touches the Windows registry",
    },
    Concept {
        triggers: &["environment variable", "getenv"],
        terms: &["calls:getenv"],
        note: "reads an environment variable",
    },
    Concept {
        triggers: &["load a library", "dlopen", "loadlibrary"],
        terms: &["calls:dlopen"],
        note: "loads a library dynamically",
    },
    // Structural concepts.
    Concept {
        triggers: &["complex", "complicated", "large function", "big function"],
        terms: &["complexity>20"],
        note: "is structurally complex",
    },
    Concept {
        triggers: &["small", "tiny", "leaf"],
        terms: &["is:leaf"],
        note: "is a leaf (calls nothing)",
    },
    Concept {
        triggers: &[
            "unused",
            "dead",
            "never called",
            "no callers",
            "unreferenced",
        ],
        terms: &["callers=0"],
        note: "has no callers",
    },
    Concept {
        triggers: &["recursive", "recursion", "calls itself"],
        terms: &["is:recursive"],
        note: "is recursive",
    },
    Concept {
        triggers: &["renamed", "i renamed"],
        terms: &["is:renamed"],
        note: "was renamed by a user",
    },
    Concept {
        triggers: &["named", "has a name", "symbol"],
        terms: &["is:named"],
        note: "has a known name",
    },
    Concept {
        triggers: &["entry", "main", "start"],
        terms: &["name:main"],
        note: "is the entry point",
    },
    Concept {
        triggers: &["never returns", "noreturn", "exits", "aborts"],
        terms: &["is:noreturn"],
        note: "never returns",
    },
    Concept {
        triggers: &[
            "doesn't check",
            "without checking",
            "no bounds",
            "unbounded",
            "unsafe copy",
        ],
        terms: &["calls:strcpy"],
        note: "uses an unbounded copy",
    },
];

/// The result of translating a question.
#[derive(Debug, Clone, PartialEq)]
pub struct Translation {
    /// The generated function-query string (may be empty).
    pub query: String,
    /// What each term was understood to mean.
    pub notes: Vec<String>,
    /// True when nothing in the question was recognised.
    pub empty: bool,
}

/// Translate a question into a function query using keyword heuristics.
pub fn heuristic(nl: &str) -> Translation {
    let q = nl.to_lowercase();
    let mut terms: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for c in CONCEPTS {
        if c.triggers.iter().any(|t| q.contains(t)) {
            for &t in c.terms {
                if !terms.iter().any(|x| x == t) {
                    terms.push(t.to_string());
                    notes.push(format!("`{t}` — {}", c.note));
                }
            }
        }
    }
    // Size hints like "bigger than 500 bytes".
    if let Some(n) = extract_after(&q, &["bigger than", "larger than", "more than", "over"]) {
        let t = format!("size>{n}");
        if !terms.iter().any(|x| x == &t) {
            terms.push(t);
            notes.push(format!("`size>{n}` — larger than {n} bytes"));
        }
    }
    let query = terms.join(" ");
    Translation {
        empty: terms.is_empty(),
        query,
        notes,
    }
}

/// Pull the first integer that appears right after any of `markers`.
fn extract_after(q: &str, markers: &[&str]) -> Option<u64> {
    for m in markers {
        if let Some(i) = q.find(m) {
            let rest = &q[i + m.len()..];
            let digits: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(n) = digits.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

/// System prompt that grounds an AI translator in the query grammar.
pub const SYSTEM_PROMPT: &str = "\
You translate a question about a binary into ONE line of Drishti's function-query \
language. Output only the query, nothing else.

Grammar (terms are ANDed; prefix a term with - to negate):
  bare word        matches the function name or address
  calls:NAME       the function calls NAME (an API or function; substring, case-insensitive)
  callers:NAME     the function is called by NAME
  str:TEXT         the function references a string containing TEXT
  refs:NAME        the function references the symbol/string NAME
  name:/REGEX/     the name matches a regex
  size>N  size<N   extent in bytes
  blocks>N  blocks>=N
  callers=0        no callers (also callers>N)
  complexity>N     cyclomatic complexity
  section:NAME     defined in a section (e.g. __text, .rdata)
  is:FLAG          one of: thunk leaf unreferenced recursive named renamed noreturn

Examples:
  Q: functions that process JSON and write to a file
  A: str:json calls:fopen
  Q: large functions that run shell commands
  A: calls:system complexity>20
  Q: unused functions that were renamed
  A: callers=0 is:renamed
  Q: code that receives from the network without bounds checking
  A: calls:recv calls:strcpy

If the question cannot be expressed, output an empty line.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_and_file() {
        let t = heuristic("find functions that process JSON and write to disk");
        assert!(t.query.contains("str:json"), "{}", t.query);
        assert!(t.query.contains("calls:fopen"), "{}", t.query);
        assert!(!t.empty);
    }

    #[test]
    fn shell_commands() {
        let t = heuristic("which large functions run shell commands?");
        assert!(t.query.contains("calls:system"));
        assert!(t.query.contains("complexity>20"));
    }

    #[test]
    fn size_hint() {
        let t = heuristic("functions bigger than 500 bytes");
        assert!(t.query.contains("size>500"), "{}", t.query);
    }

    #[test]
    fn unknown() {
        let t = heuristic("what is the meaning of life");
        assert!(t.empty);
        assert_eq!(t.query, "");
    }
}
