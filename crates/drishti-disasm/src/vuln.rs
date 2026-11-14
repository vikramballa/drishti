//! Static vulnerability auditor (Feature 1 "Vuln Hunter" / Feature 5 analysis).
//!
//! This is a **reachability** auditor, not a value-level taint engine: it finds
//! functions that read untrusted input ("sources") and functions that reach a
//! dangerous operation ("sinks"), and reports a sink when a call-graph path
//! connects a source to it, or when the sink itself is an inherently unsafe API.
//!
//! It never proves exploitability — proving that the *same bytes* flow from a
//! source into a sink needs the IR + dataflow of milestone B. Every finding
//! says how it was reached and carries an honest confidence level so a human
//! (or an agent) knows what still has to be checked by reading the code.
//!
//! Pure and read-only: it only inspects the parsed image and the call graph.

use crate::analyze::Analysis;
use drishti_loader::Image;
use drishti_model::Addr;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct FnRef {
    pub entry: Addr,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnFinding {
    /// Machine slug, e.g. `"command-injection"`.
    pub class: &'static str,
    pub title: String,
    /// "high" | "medium" | "low" | "info"
    pub severity: &'static str,
    /// "high" | "medium" | "low" — how sure we are untrusted input reaches it.
    pub confidence: &'static str,
    /// The dangerous API that is called.
    pub sink_api: String,
    /// The function that calls the dangerous API.
    pub sink_fn: FnRef,
    /// The untrusted-input API, if a source was connected to the sink.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_api: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_fn: Option<FnRef>,
    /// Call path source → … → sink (function entries), when one was found.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<FnRef>,
    /// Plain-language description of the weak spot and what to verify.
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnReport {
    pub findings: Vec<VulnFinding>,
    pub scanned_functions: usize,
    pub sources_found: usize,
    pub sinks_found: usize,
    /// Honest caveat shown to the user.
    pub note: &'static str,
}

/// Untrusted-input APIs. Category is only for the explanation text.
const SOURCES: &[(&str, &str)] = &[
    ("recv", "network"),
    ("recvfrom", "network"),
    ("recvmsg", "network"),
    ("read", "input"),
    ("pread", "input"),
    ("fread", "input"),
    ("fgets", "input"),
    ("fgetc", "input"),
    ("fscanf", "input"),
    ("gets", "input"),
    ("scanf", "input"),
    ("getenv", "environment"),
    ("getline", "input"),
    ("ReadFile", "input"),
    ("InternetReadFile", "network"),
    ("WSARecv", "network"),
    ("WinHttpReadData", "network"),
    ("accept", "network"),
    ("CFReadStreamRead", "network"),
    ("SSL_read", "network"),
    ("curl_easy_perform", "network"),
];

struct SinkRule {
    /// Exact API (case-insensitive); a trailing `*` matches a prefix.
    api: &'static str,
    class: &'static str,
    severity: &'static str,
    /// Inherently unsafe even with no proven input path (banned API).
    banned: bool,
    why: &'static str,
}

const SINKS: &[SinkRule] = &[
    // Command execution.
    SinkRule {
        api: "system",
        class: "command-injection",
        severity: "high",
        banned: true,
        why: "runs a shell command",
    },
    SinkRule {
        api: "popen",
        class: "command-injection",
        severity: "high",
        banned: true,
        why: "runs a shell command and opens a pipe to it",
    },
    SinkRule {
        api: "execl",
        class: "command-injection",
        severity: "high",
        banned: false,
        why: "executes a program",
    },
    SinkRule {
        api: "execlp",
        class: "command-injection",
        severity: "high",
        banned: false,
        why: "executes a program found on PATH",
    },
    SinkRule {
        api: "execv",
        class: "command-injection",
        severity: "high",
        banned: false,
        why: "executes a program",
    },
    SinkRule {
        api: "execvp",
        class: "command-injection",
        severity: "high",
        banned: false,
        why: "executes a program found on PATH",
    },
    SinkRule {
        api: "execve",
        class: "command-injection",
        severity: "high",
        banned: false,
        why: "executes a program",
    },
    SinkRule {
        api: "posix_spawn",
        class: "command-injection",
        severity: "high",
        banned: false,
        why: "spawns a program",
    },
    SinkRule {
        api: "posix_spawnp",
        class: "command-injection",
        severity: "high",
        banned: false,
        why: "spawns a program found on PATH",
    },
    SinkRule {
        api: "CreateProcess*",
        class: "command-injection",
        severity: "high",
        banned: false,
        why: "starts a new process",
    },
    SinkRule {
        api: "ShellExecute*",
        class: "command-injection",
        severity: "high",
        banned: false,
        why: "launches a file or command via the shell",
    },
    SinkRule {
        api: "WinExec",
        class: "command-injection",
        severity: "high",
        banned: true,
        why: "runs a command line",
    },
    // Memory-unsafe string / buffer operations.
    SinkRule {
        api: "strcpy",
        class: "buffer-overflow",
        severity: "high",
        banned: true,
        why: "copies a string with no size limit",
    },
    SinkRule {
        api: "strcat",
        class: "buffer-overflow",
        severity: "high",
        banned: true,
        why: "appends a string with no size limit",
    },
    SinkRule {
        api: "stpcpy",
        class: "buffer-overflow",
        severity: "high",
        banned: true,
        why: "copies a string with no size limit",
    },
    SinkRule {
        api: "sprintf",
        class: "buffer-overflow",
        severity: "high",
        banned: true,
        why: "formats into a buffer with no size limit",
    },
    SinkRule {
        api: "vsprintf",
        class: "buffer-overflow",
        severity: "high",
        banned: true,
        why: "formats into a buffer with no size limit",
    },
    SinkRule {
        api: "gets",
        class: "buffer-overflow",
        severity: "high",
        banned: true,
        why: "reads a line into a buffer with no size limit",
    },
    SinkRule {
        api: "scanf",
        class: "buffer-overflow",
        severity: "medium",
        banned: false,
        why: "can write past a buffer with unbounded `%s`",
    },
    SinkRule {
        api: "sscanf",
        class: "buffer-overflow",
        severity: "medium",
        banned: false,
        why: "can write past a buffer with unbounded `%s`",
    },
    SinkRule {
        api: "memcpy",
        class: "buffer-overflow",
        severity: "medium",
        banned: false,
        why: "copies raw bytes; the length must be bounded by the destination",
    },
    SinkRule {
        api: "memmove",
        class: "buffer-overflow",
        severity: "medium",
        banned: false,
        why: "moves raw bytes; the length must be bounded by the destination",
    },
    SinkRule {
        api: "alloca",
        class: "buffer-overflow",
        severity: "medium",
        banned: false,
        why: "allocates on the stack; an attacker-sized value can exhaust the stack",
    },
    SinkRule {
        api: "strncpy",
        class: "buffer-overflow",
        severity: "low",
        banned: false,
        why: "does not guarantee a terminating NUL",
    },
    // Format-string.
    SinkRule {
        api: "printf",
        class: "format-string",
        severity: "medium",
        banned: false,
        why: "is dangerous if the format argument is attacker-controlled",
    },
    SinkRule {
        api: "fprintf",
        class: "format-string",
        severity: "medium",
        banned: false,
        why: "is dangerous if the format argument is attacker-controlled",
    },
    SinkRule {
        api: "snprintf",
        class: "format-string",
        severity: "low",
        banned: false,
        why: "is dangerous if the format argument is attacker-controlled",
    },
    SinkRule {
        api: "syslog",
        class: "format-string",
        severity: "medium",
        banned: false,
        why: "is dangerous if the format argument is attacker-controlled",
    },
    SinkRule {
        api: "NSLog",
        class: "format-string",
        severity: "low",
        banned: false,
        why: "is dangerous if the format argument is attacker-controlled",
    },
    // Dynamic code / library loading.
    SinkRule {
        api: "dlopen",
        class: "unsafe-load",
        severity: "medium",
        banned: false,
        why: "loads a library by name; an attacker-controlled path loads attacker code",
    },
    SinkRule {
        api: "LoadLibrary*",
        class: "unsafe-load",
        severity: "medium",
        banned: false,
        why: "loads a DLL by name; an attacker-controlled path loads attacker code",
    },
    SinkRule {
        api: "dlsym",
        class: "unsafe-load",
        severity: "low",
        banned: false,
        why: "resolves a symbol by name at runtime",
    },
];

/// `___strcpy_chk` → (`strcpy`, fortified = true). macOS/glibc emit these
/// bounded `_chk` variants for most buffer APIs even at `-O0`.
fn core_api(name: &str) -> (&str, bool) {
    let n = name.trim_start_matches('_');
    match n.strip_suffix("_chk") {
        Some(core) => (core, true),
        None => (n, false),
    }
}

fn matches(import: &str, pat: &str) -> bool {
    let (n, _) = core_api(import);
    match pat.strip_suffix('*') {
        Some(p) => n.len() >= p.len() && n[..p.len()].eq_ignore_ascii_case(p),
        None => n.eq_ignore_ascii_case(pat),
    }
}

fn is_fortified(name: &str) -> bool {
    core_api(name).1
}

/// Functions that reference an import slot, mirroring `insights::behaviors`.
fn referencing_functions(img: &Image, a: &Analysis, import_va: u64, out: &mut Vec<u64>) {
    if import_va == 0 {
        return;
    }
    for x in a.xrefs_to(import_va).iter().take(4000) {
        if let Some(f) = a.function_containing(x.from) {
            out.push(f.entry);
        }
    }
    // `call [slot]` thunks: the stub function's callers reference the import.
    if let Some(stub) = a.function_at(import_va) {
        out.extend(stub.called_by.iter().copied());
        // The stub itself (one-instruction jump to the import) is a thunk, not
        // interesting as a sink host; its callers are what we want.
    }
    // Direct target in `calls` (import-slot targets are recorded there too).
    let _ = img;
}

const MAX_DEPTH: u32 = 12;
const MAX_FINDINGS: usize = 120;

/// Audit the binary for input-reaches-dangerous-operation weak spots.
pub fn audit(img: &Image, a: &Analysis) -> VulnReport {
    // 1. Resolve sources → the set of functions that read untrusted input.
    let mut source_api_of: HashMap<u64, String> = HashMap::new();
    for imp in &img.imports {
        if let Some(&(api, _cat)) = SOURCES.iter().find(|(p, _)| matches(&imp.name, p)) {
            let mut fns = Vec::new();
            referencing_functions(img, a, imp.addr.0, &mut fns);
            for e in fns {
                source_api_of.entry(e).or_insert_with(|| api.to_string());
            }
        }
    }

    // 2. Resolve sinks → (function entry, rule, api) hits.
    struct SinkHit<'r> {
        f_entry: u64,
        rule: &'r SinkRule,
        api: String,
        fortified: bool,
    }
    let mut sink_hits: Vec<SinkHit> = Vec::new();
    for imp in &img.imports {
        if let Some(rule) = SINKS.iter().find(|r| matches(&imp.name, r.api)) {
            let mut fns = Vec::new();
            referencing_functions(img, a, imp.addr.0, &mut fns);
            fns.sort_unstable();
            fns.dedup();
            let api = imp.display_name().trim_start_matches('_').to_string();
            let fortified = is_fortified(&imp.name);
            for e in fns {
                sink_hits.push(SinkHit {
                    f_entry: e,
                    rule,
                    api: api.clone(),
                    fortified,
                });
            }
        }
    }

    // 3. Multi-source forward BFS over the call graph, recording a parent so we
    //    can reconstruct a path. Depth-bounded; visits each function once.
    let parent = bfs_from_sources(a, &source_api_of);

    // 4. Turn sink hits into findings.
    let name_of = |e: u64| -> String {
        a.function_at(e)
            .map(|f| f.name.to_string())
            .unwrap_or_else(|| Addr(e).to_string())
    };
    let fref = |e: u64| FnRef {
        entry: Addr(e),
        name: name_of(e),
    };

    let mut findings: Vec<VulnFinding> = Vec::new();
    for h in &sink_hits {
        let title_fn = name_of(h.f_entry);
        let (confidence, source_api, source_fn, path);
        if let Some(src_api) = source_api_of.get(&h.f_entry) {
            // Source and sink in the same function: strongest signal.
            confidence = "high";
            source_api = Some(src_api.clone());
            source_fn = Some(fref(h.f_entry));
            path = vec![fref(h.f_entry)];
        } else if let Some((src_entry, p)) = reconstruct_path(&parent, h.f_entry) {
            confidence = "medium";
            source_api = source_api_of.get(&src_entry).cloned();
            source_fn = Some(fref(src_entry));
            path = p.into_iter().map(fref).collect();
        } else if h.rule.banned {
            // No input path, but the API is unsafe by its nature.
            confidence = "low";
            source_api = None;
            source_fn = None;
            path = Vec::new();
        } else {
            // Non-banned sink with no input path: too noisy to report.
            continue;
        }

        let mut severity = if confidence == "low" && h.rule.severity == "high" {
            // A banned API with no proven input path is still worth flagging,
            // but not as a top "high" alarm.
            "medium"
        } else {
            h.rule.severity
        };
        // A fortified `_chk` variant is bounded (it aborts on overflow), so it
        // is a weaker signal than the raw API.
        if h.fortified && severity == "high" {
            severity = "medium";
        }

        let mut explanation = explain(
            h.rule,
            &h.api,
            &title_fn,
            source_api.as_deref(),
            confidence,
            path.len(),
        );
        if h.fortified {
            explanation.push_str(
                " This is the bounded `_chk` form, which aborts on overflow rather than \
                 corrupting memory silently — lower risk, but still worth confirming the size.",
            );
        }
        findings.push(VulnFinding {
            class: h.rule.class,
            title: format!("{} {}", h.api, short_class(h.rule.class)),
            severity,
            confidence,
            sink_api: h.api.clone(),
            sink_fn: fref(h.f_entry),
            source_api,
            source_fn,
            path,
            explanation,
        });
    }

    // 5. De-duplicate by (sink_fn, sink_api), keeping the strongest, and rank.
    findings.sort_by_key(|f| {
        (
            f.sink_fn.entry.0,
            f.sink_api.clone(),
            conf_rank(f.confidence),
        )
    });
    findings.dedup_by(|a, b| a.sink_fn.entry.0 == b.sink_fn.entry.0 && a.sink_api == b.sink_api);
    findings.sort_by_key(|f| {
        (
            conf_rank(f.confidence),
            sev_rank(f.severity),
            f.sink_fn.entry.0,
        )
    });
    findings.truncate(MAX_FINDINGS);

    VulnReport {
        findings,
        scanned_functions: a.functions.len(),
        sources_found: source_api_of.len(),
        sinks_found: sink_hits.len(),
        note: "Reachability analysis: a path from input to a risky call does not prove the \
               input reaches that call's dangerous argument. Confirm each finding by reading \
               the function. Value-level taint arrives with the IR (milestone B).",
    }
}

/// Multi-source BFS; returns entry → parent-entry (sources map to themselves).
fn bfs_from_sources(a: &Analysis, sources: &HashMap<u64, String>) -> HashMap<u64, u64> {
    let mut parent: HashMap<u64, u64> = HashMap::with_capacity(sources.len() * 4);
    let mut frontier: Vec<u64> = Vec::new();
    for &s in sources.keys() {
        parent.insert(s, s);
        frontier.push(s);
    }
    let mut depth = 0u32;
    while !frontier.is_empty() && depth < MAX_DEPTH {
        let mut next = Vec::new();
        for &f in &frontier {
            let Some(func) = a.function_at(f) else {
                continue;
            };
            for &callee_target in func.calls.iter() {
                // Resolve a call target to a function entry.
                let Some(callee) = a
                    .function_at(callee_target)
                    .or_else(|| a.function_containing(callee_target))
                else {
                    continue;
                };
                if parent.contains_key(&callee.entry) {
                    continue;
                }
                parent.insert(callee.entry, f);
                next.push(callee.entry);
            }
        }
        frontier = next;
        depth += 1;
    }
    parent
}

/// Walk parents from a sink function back to its source; returns
/// (source_entry, path source→…→sink).
fn reconstruct_path(parent: &HashMap<u64, u64>, sink: u64) -> Option<(u64, Vec<u64>)> {
    parent.get(&sink)?;
    let mut path = vec![sink];
    let mut cur = sink;
    for _ in 0..(MAX_DEPTH as usize + 2) {
        let p = *parent.get(&cur)?;
        if p == cur {
            // `cur` is a source (maps to itself).
            path.reverse();
            return Some((cur, path));
        }
        path.push(p);
        cur = p;
    }
    None
}

fn short_class(c: &str) -> &'static str {
    match c {
        "command-injection" => "(command execution)",
        "buffer-overflow" => "(memory safety)",
        "format-string" => "(format string)",
        "unsafe-load" => "(dynamic loading)",
        _ => "",
    }
}

fn conf_rank(c: &str) -> u8 {
    match c {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    }
}
fn sev_rank(s: &str) -> u8 {
    match s {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    }
}

fn explain(
    rule: &SinkRule,
    sink_api: &str,
    sink_fn: &str,
    source_api: Option<&str>,
    confidence: &str,
    path_len: usize,
) -> String {
    let base = format!("`{sink_api}` {}.", rule.why);
    match (confidence, source_api) {
        ("high", Some(src)) => format!(
            "{base} `{sink_fn}` reads untrusted input with `{src}` and calls `{sink_api}` in the \
             same function, so attacker-influenced data is close to this operation. Check whether \
             the input reaches the dangerous argument."
        ),
        ("medium", Some(src)) => format!(
            "{base} There is a call path of {path_len} functions from code that reads untrusted \
             input with `{src}` down to `{sink_fn}`, which calls `{sink_api}`. Follow the path to \
             confirm the data actually flows into the dangerous argument."
        ),
        ("medium", None) => format!(
            "{base} `{sink_fn}` is reachable from code that reads untrusted input. Confirm by \
             reading the path."
        ),
        _ => format!(
            "{base} `{sink_fn}` uses this unsafe API. No path from untrusted input was found, but \
             the call is worth reviewing; prefer a bounded alternative."
        ),
    }
}
