//! MCP server over stdio (`drishti mcp`): lets LLM agents such as Claude
//! Code inspect binaries with the core engine. JSON-RPC 2.0, one message
//! per line. Runs fully in-process; nothing is executed or uploaded.

use anyhow::{Context, Result, anyhow};
use drishti_disasm::{Analysis, Options, analyze};
use drishti_loader::{Blob, Image};
use drishti_model::{Addr, StringRef};
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

struct Loaded {
    blob: Arc<Blob>,
    img: Image,
    analysis: Analysis,
    strings: Vec<StringRef>,
    sha: String,
    name: String,
}

struct Server {
    data_dir: PathBuf,
    cache: Vec<(String, Loaded)>,
}

fn tool(name: &str, desc: &str, props: Value, required: &[&str]) -> Value {
    json!({"name": name, "description": desc, "inputSchema": {"type": "object", "properties": props, "required": required}})
}

fn tools() -> Value {
    let path = json!({"type": "string", "description": "Absolute path to the binary (or a macOS .app bundle)"});
    let addr = json!({"type": "string", "description": "Virtual address in hex, e.g. 0x100003f20"});
    json!([
        tool(
            "document_report",
            "Where a file came from and whether it is safe, for any file (not just programs): for PDFs the producing software, device, author, dates and time zone, edit history, revisions, signatures (signer and issuer), links, attachments and risky features (scripts, auto-actions, launches); for files on this Mac also the download URL, app and time recorded by macOS.",
            json!({"path": {"type": "string", "description": "Absolute path to the file"}}),
            &["path"]
        ),
        tool(
            "open_binary",
            "Load and analyse a binary. Returns a plain-language summary, file facts, security hardening, detected behaviours and findings. Call this first.",
            json!({"path": path}),
            &["path"]
        ),
        tool(
            "list_functions",
            "List functions (name, address, size, blocks, callers). The filter is a query: bare words match the name or address; `calls:malloc`, `callers:main`, `str:password`, `refs:kSecClass`, `name:/^sub_/`, `size>200`, `blocks>=10`, `callers=0`, `complexity>20`, `is:thunk|leaf|unreferenced|recursive|named|renamed|noreturn`, `section:__text`; `-term` negates; terms are ANDed.",
            json!({"path": path, "filter": {"type": "string", "description": "Query, e.g. `calls:SecItemCopyMatching -is:thunk size>100`"}, "sort": {"type": "string", "enum": ["addr", "size", "callers", "complexity"]}, "limit": {"type": "integer", "default": 100}}),
            &["path"]
        ),
        tool(
            "function",
            "Full disassembly of the function at (or containing) an address, grouped by basic block, with callers, callees and referenced strings.",
            json!({"path": path, "addr": addr}),
            &["path", "addr"]
        ),
        tool(
            "disassemble",
            "Disassemble `count` instructions starting at an address.",
            json!({"path": path, "addr": addr, "count": {"type": "integer", "default": 40}}),
            &["path", "addr"]
        ),
        tool(
            "xrefs_to",
            "Code locations that reference an address (function, import, string or data).",
            json!({"path": path, "addr": addr}),
            &["path", "addr"]
        ),
        tool(
            "strings",
            "Strings in the binary with the functions that reference them.",
            json!({"path": path, "filter": {"type": "string"}, "limit": {"type": "integer", "default": 100}}),
            &["path"]
        ),
        tool(
            "imports",
            "Imported functions with library and capability.",
            json!({"path": path, "filter": {"type": "string"}}),
            &["path"]
        ),
        tool(
            "search_bytes",
            "Search the raw file. Modes: `text` (case-insensitive, UTF-8 and UTF-16LE by default), `hex` (YARA-style: `48 8b ?? 05`, nibbles `4?`, jumps `[2-4]`, alternatives `( 90 | cc )`, not-byte `~00`), `regex` (over raw bytes: `.` is any byte, `\\x00` a byte), `number` (`0xdeadbeef`, `-1`, `3.14`: every width that fits, file byte order). Returns offset, address, section, kind and the matched text.",
            json!({"path": path,
                "mode": {"type": "string", "enum": ["text", "hex", "regex", "number"], "default": "text"},
                "query": {"type": "string"},
                "case_sensitive": {"type": "boolean", "default": false},
                "encodings": {"type": "string", "description": "text mode: comma list of utf8, utf16le, utf16be"},
                "width": {"type": "integer", "enum": [8, 16, 32, 64], "description": "number mode: only this width"},
                "endian": {"type": "string", "enum": ["file", "le", "be", "both"]},
                "scope": {"type": "string", "description": "all (default), code, data, or a section name such as __cstring or .rdata"},
                "limit": {"type": "integer", "default": 100},
                "hex": {"type": "string", "description": "shorthand for mode=hex"},
                "text": {"type": "string", "description": "shorthand for mode=text"}}),
            &["path"]
        ),
        tool(
            "search_code",
            "Find instruction patterns in the disassembly of every function (or one). `*` matches anything; `;` separates consecutive instructions, e.g. `mov edi, *; call *malloc` or `xor *, 0x5a`. Lines include resolved call targets, so `call *SecItemCopyMatching` works. Set regex=true for regular expressions per instruction.",
            json!({"path": path, "pattern": {"type": "string"},
                "regex": {"type": "boolean", "default": false},
                "case_sensitive": {"type": "boolean", "default": false},
                "addr": {"type": "string", "description": "only the function containing this address"},
                "limit": {"type": "integer", "default": 100}}),
            &["path", "pattern"]
        ),
        tool(
            "triage",
            "Autonomous triage briefing: one executive summary combining the file verdict, what it can do (behaviours), indicators (URLs/IPs/paths), security hardening and the count of potential weak spots. Run this to orient before anything else.",
            json!({"path": path}),
            &["path"]
        ),
        tool(
            "find_vulns",
            "Static vulnerability audit (reachability): finds where untrusted input (recv/read/fread/getenv/…) can reach a dangerous operation (system/exec/strcpy/sprintf/memcpy/format strings/dlopen) through the call graph. Each result has a confidence level and a call path. Reachability only — it does not prove exploitability.",
            json!({"path": path, "min_confidence": {"type": "string", "enum": ["low", "medium", "high"], "default": "low"}, "limit": {"type": "integer", "default": 100}}),
            &["path"]
        ),
        tool(
            "nl_query",
            "Ask for functions in plain English (e.g. 'functions that process JSON and write to disk', 'large functions that run shell commands'). Translates to Drishti's function-query language, shows the query it used, and returns the matches.",
            json!({"path": path, "question": {"type": "string"}, "limit": {"type": "integer", "default": 100}}),
            &["path", "question"]
        ),
        tool(
            "rename",
            "Rename a function (saved as a user annotation, visible in the Drishti UI).",
            json!({"path": path, "addr": addr, "name": {"type": "string"}}),
            &["path", "addr", "name"]
        ),
        tool(
            "comment",
            "Attach a comment to an address.",
            json!({"path": path, "addr": addr, "text": {"type": "string"}}),
            &["path", "addr", "text"]
        ),
    ])
}

fn resolve(p: &str) -> PathBuf {
    let path = PathBuf::from(p);
    if path.is_dir() {
        if let Some(stem) = path.file_stem() {
            let c = path.join("Contents/MacOS").join(stem);
            if c.is_file() {
                return c;
            }
        }
        if let Ok(mut rd) = std::fs::read_dir(path.join("Contents/MacOS"))
            && let Some(Ok(e)) = rd.next()
        {
            return e.path();
        }
    }
    path
}

impl Server {
    fn load(&mut self, path: &str) -> Result<&Loaded> {
        if let Some(i) = self.cache.iter().position(|(p, _)| p == path) {
            let e = self.cache.remove(i);
            self.cache.insert(0, e);
            return Ok(&self.cache[0].1);
        }
        let real = resolve(path);
        let blob = drishti_loader::open(&real)
            .with_context(|| format!("cannot open {}", real.display()))?;
        let img = drishti_loader::load_image(blob.clone(), None).map_err(|e| anyhow!("{e}"))?;
        let sha = drishti_loader::util::sha256_hex(blob.as_ref().as_ref());
        // Shared with the server: a binary analysed once (by either) reopens instantly.
        let cache = self.data_dir.join("cache").join(format!(
            "{}.bin",
            drishti_disasm::cache::cache_key(&sha, &Options::default())
        ));
        let analysis = match drishti_disasm::cache::load(&cache) {
            Some(a) => a,
            None => {
                let a = analyze(&img, &Options::default(), &|_| {}, &AtomicBool::new(false))
                    .map_err(|e| anyhow!("{e}"))?;
                let _ = drishti_disasm::cache::store(&cache, &a);
                a
            }
        };
        let mut strings = drishti_loader::strings(&blob, Some(&img), 4, 300_000);
        strings.sort_by_key(|s| s.addr);
        let name = real
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.cache.insert(
            0,
            (
                path.to_string(),
                Loaded {
                    blob,
                    img,
                    analysis,
                    strings,
                    sha,
                    name,
                },
            ),
        );
        self.cache.truncate(2);
        Ok(&self.cache[0].1)
    }

    fn call(&mut self, name: &str, a: &Value) -> Result<String> {
        let path = a
            .get("path")
            .and_then(Value::as_str)
            .context("missing `path`")?
            .to_string();
        if name == "document_report" {
            let p = std::path::Path::new(&path);
            let blob = drishti_loader::open(p)?;
            let bytes: &[u8] = blob.as_ref().as_ref();
            let doc = (drishti_loader::detect(bytes).format == drishti_model::Format::Pdf)
                .then(|| drishti_loader::pdf::analyze(bytes));
            let origin = drishti_server::origin::file_origin(p);
            return Ok(serde_json::to_string_pretty(
                &json!({"document": doc, "origin": origin, "format": drishti_loader::detect(bytes).format}),
            )?);
        }
        let data_dir = self.data_dir.clone();
        let addr = || -> Result<u64> {
            a.get("addr")
                .and_then(Value::as_str)
                .and_then(Addr::parse)
                .map(|x| x.0)
                .context("missing or invalid `addr`")
        };
        let filter = a
            .get("filter")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_lowercase();
        let limit = a
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(100)
            .min(2000) as usize;
        let l = self.load(&path)?;
        let renames = drishti_server::state::renames_offline(&data_dir, &l.sha);
        let fname = |e: u64| {
            renames
                .get(&e)
                .cloned()
                .or_else(|| l.analysis.function_at(e).map(|f| f.name.to_string()))
        };
        let namer = |t: u64| -> Option<String> {
            fname(t)
                .or_else(|| l.img.import_at(t).map(|s| s.display_name().to_string()))
                .or_else(|| {
                    l.strings
                        .binary_search_by_key(&Addr(t), |s| s.addr)
                        .ok()
                        .map(|i| {
                            format!(
                                "{:?}",
                                l.strings[i].value.chars().take(60).collect::<String>()
                            )
                        })
                })
        };
        let line = |i: &drishti_model::Instruction| {
            format!(
                "{}  {:<8} {}{}",
                i.addr,
                i.mnemonic,
                i.operands,
                i.comment
                    .as_ref()
                    .map(|c| format!("  ; {c}"))
                    .unwrap_or_default()
            )
        };
        Ok(match name {
            "open_binary" => {
                let info = drishti_loader::file_info(&l.blob, &l.name, Some(&l.img));
                let (hard, sig) = drishti_loader::insights::hardening(&l.img);
                let beh = drishti_disasm::insights::behaviors(&l.img, Some(&l.analysis));
                let summary = drishti_disasm::insights::summary(
                    &info,
                    Some(&l.img),
                    sig.as_ref(),
                    &beh,
                    Some(l.analysis.functions.len()),
                );
                let mut findings = drishti_loader::triage::findings(&l.img);
                findings.extend(drishti_loader::insights::crypto_constants(&l.img));
                let iocs = drishti_loader::insights::iocs(&l.strings);
                serde_json::to_string_pretty(&json!({
                    "summary": summary, "sha256": l.sha, "format": info.format, "arch": info.arch, "platform": info.platform,
                    "entry_point": info.entry_point, "functions": l.analysis.functions.len(), "imports": l.img.imports.len(), "strings": l.strings.len(),
                    "libraries": l.img.libraries.iter().take(40).collect::<Vec<_>>(),
                    "hardening": hard, "signing": sig,
                    "behaviors": beh.iter().map(|b| json!({"name": b.name, "severity": b.severity, "apis": b.apis, "functions": b.functions.iter().take(8).collect::<Vec<_>>()})).collect::<Vec<_>>(),
                    "findings": findings.iter().map(|f| json!({"title": f.title, "addrs": f.addrs})).collect::<Vec<_>>(),
                    "indicators": iocs.iter().take(60).map(|i| format!("{}: {}", i.kind, i.value)).collect::<Vec<_>>(),
                }))?
            }
            "list_functions" => {
                let fq = drishti_disasm::search::FnQuery::parse(
                    a.get("filter").and_then(Value::as_str).unwrap_or(""),
                )
                .map_err(|e| anyhow!(e))?;
                let is_renamed = |e: u64| renames.contains_key(&e);
                let cx = drishti_disasm::search::FnCtx {
                    analysis: &l.analysis,
                    image: Some(&l.img),
                    strings: &l.strings,
                    name_of: &namer,
                    is_renamed: &is_renamed,
                };
                let mut v: Vec<_> = l
                    .analysis
                    .functions
                    .iter()
                    .filter(|f| {
                        fq.is_empty() || fq.matches(f, &fname(f.entry).unwrap_or_default(), &cx)
                    })
                    .collect();
                match a.get("sort").and_then(Value::as_str) {
                    Some("size") => v.sort_by_key(|f| std::cmp::Reverse(f.size)),
                    Some("callers") => v.sort_by_key(|f| std::cmp::Reverse(f.called_by.len())),
                    Some("complexity") => v.sort_by_key(|f| std::cmp::Reverse(f.cyclomatic())),
                    _ => {}
                }
                let total = v.len();
                let mut s = format!(
                    "{total} functions{}\naddress  size  blocks  callers  name\n",
                    if total > limit {
                        format!(" (showing {limit})")
                    } else {
                        String::new()
                    }
                );
                for f in v.into_iter().take(limit) {
                    s += &format!(
                        "{}  {}  {}  {}  {}{}\n",
                        Addr(f.entry),
                        f.size,
                        f.nblocks,
                        f.called_by.len(),
                        fname(f.entry).unwrap_or_default(),
                        if f.is_thunk { " [import thunk]" } else { "" }
                    );
                }
                s
            }
            "function" => {
                let at = addr()?;
                let f = l
                    .analysis
                    .function_at(at)
                    .or_else(|| l.analysis.function_containing(at))
                    .context("no function at that address")?;
                let cfg = l.analysis.cfg(&l.img, f.entry).unwrap_or_default();
                let mut s = format!(
                    "function {} at {} — {} bytes, {} blocks, cyclomatic complexity {}\n",
                    fname(f.entry).unwrap_or_default(),
                    Addr(f.entry),
                    f.size,
                    cfg.len(),
                    f.cyclomatic()
                );
                s += &format!(
                    "callers: {}\n",
                    f.called_by
                        .iter()
                        .take(30)
                        .map(|&c| namer(c).unwrap_or_else(|| Addr(c).to_string()))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                s += &format!(
                    "calls: {}\n\n",
                    f.calls
                        .iter()
                        .take(60)
                        .map(|&c| namer(c).unwrap_or_else(|| Addr(c).to_string()))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                let mut budget = 3000usize;
                for b in &cfg {
                    s += &format!("block {}:\n", Addr(b.start));
                    let n = (b.insns as usize).min(budget);
                    budget -= n;
                    for i in drishti_disasm::disasm(&l.img, b.start, n, &namer)
                        .iter()
                        .filter(|i| i.addr.0 < b.end)
                    {
                        s += &format!("  {}\n", line(i));
                    }
                    if !b.succs.is_empty() {
                        s += &format!(
                            "  -> {}\n",
                            b.succs
                                .iter()
                                .map(|(t, k)| format!("{k:?} {}", Addr(*t)))
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                    }
                    if budget == 0 {
                        s += "… truncated (function too large)\n";
                        break;
                    }
                }
                s
            }
            "disassemble" => {
                let count = a
                    .get("count")
                    .and_then(Value::as_u64)
                    .unwrap_or(40)
                    .min(1000) as usize;
                drishti_disasm::disasm(&l.img, addr()?, count, &namer)
                    .iter()
                    .map(line)
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            "xrefs_to" => {
                let at = addr()?;
                let x = l.analysis.xrefs_to(at);
                let mut s = format!(
                    "{} references to {} ({})\n",
                    x.len(),
                    Addr(at),
                    namer(at).unwrap_or_default()
                );
                for r in x.iter().take(300) {
                    let f = l.analysis.function_containing(r.from);
                    s += &format!(
                        "{}  {:?}  in {}\n",
                        Addr(r.from),
                        r.kind,
                        f.and_then(|f| fname(f.entry)).unwrap_or_else(|| "?".into())
                    );
                }
                s
            }
            "strings" => {
                let v: Vec<_> = l
                    .strings
                    .iter()
                    .filter(|s| filter.is_empty() || s.value.to_lowercase().contains(&filter))
                    .collect();
                let mut s = format!(
                    "{} strings{}\n",
                    v.len(),
                    if v.len() > limit {
                        format!(" (showing {limit})")
                    } else {
                        String::new()
                    }
                );
                for x in v.into_iter().take(limit) {
                    let refs: Vec<String> = l
                        .analysis
                        .xrefs_to(x.addr.0)
                        .iter()
                        .take(4)
                        .filter_map(|r| {
                            l.analysis
                                .function_containing(r.from)
                                .and_then(|f| fname(f.entry))
                        })
                        .collect();
                    s += &format!(
                        "{}  {:?}{}\n",
                        x.addr,
                        x.value,
                        if refs.is_empty() {
                            String::new()
                        } else {
                            format!("  <- {}", refs.join(", "))
                        }
                    );
                }
                s
            }
            "imports" => {
                let mut s = String::new();
                for i in l
                    .img
                    .imports
                    .iter()
                    .filter(|i| {
                        filter.is_empty() || i.display_name().to_lowercase().contains(&filter)
                    })
                    .take(1500)
                {
                    s += &format!(
                        "{}  {}  [{}]{}\n",
                        i.addr,
                        i.display_name(),
                        i.library.as_deref().unwrap_or("?"),
                        drishti_loader::image::import_capability(&i.name)
                            .map(|c| format!("  ({c})"))
                            .unwrap_or_default()
                    );
                }
                s
            }
            "search_bytes" => {
                use drishti_disasm::search::{
                    self as eng, ByteQuery, Enc, Limits, Mode, Order, Scope,
                };
                let s_of = |k: &str| a.get(k).and_then(Value::as_str).filter(|v| !v.is_empty());
                let (mode, query) = if let Some(h) = s_of("hex") {
                    (Mode::Hex, h)
                } else if let Some(t) = s_of("text") {
                    (Mode::Text, t)
                } else {
                    let m = s_of("mode").unwrap_or("text");
                    (
                        Mode::parse(m).with_context(|| format!("unknown mode `{m}`"))?,
                        s_of("query").context("pass `query` (or `hex` / `text`)")?,
                    )
                };
                let mut bq = ByteQuery::new(mode, query);
                bq.case_sensitive = a
                    .get("case_sensitive")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if let Some(e) = s_of("encodings") {
                    bq.encodings = Enc::parse_list(e).map_err(|e| anyhow!(e))?;
                }
                bq.width = match a.get("width").and_then(Value::as_u64) {
                    None => None,
                    Some(8) => Some(1),
                    Some(16) => Some(2),
                    Some(32) => Some(4),
                    Some(64) => Some(8),
                    Some(w) => anyhow::bail!("width {w} must be 8, 16, 32 or 64"),
                };
                bq.endian = match s_of("endian").unwrap_or("file") {
                    "le" | "little" => Some(Order::Little),
                    "be" | "big" => Some(Order::Big),
                    "both" => None,
                    _ if l.img.endian == drishti_model::Endian::Big => Some(Order::Big),
                    _ => Some(Order::Little),
                };
                let c = eng::compile(&bq).map_err(|e| anyhow!(e))?;
                let data = l.blob.as_ref().as_ref();
                let ranges = eng::scope_ranges(
                    data.len(),
                    Some(&l.img),
                    &Scope::parse(s_of("scope").unwrap_or("all")),
                )
                .map_err(|e| anyhow!(e))?;
                let out = eng::scan(
                    data,
                    &ranges,
                    &c,
                    Limits::new(100_000, std::time::Duration::from_secs(20)),
                );
                let mut s = format!(
                    "{}{} matches{}\n",
                    out.total,
                    if out.capped || out.timed_out { "+" } else { "" },
                    if out.total > limit {
                        format!(" (showing {limit})")
                    } else {
                        String::new()
                    }
                );
                for h in out.hits.iter().take(limit) {
                    let va = h
                        .offset
                        .checked_sub(l.img.slice_offset)
                        .and_then(|o| l.img.offset_to_va(o as u64));
                    let f = va
                        .and_then(|v| l.analysis.function_containing(v))
                        .and_then(|f| fname(f.entry));
                    s += &format!(
                        "offset {:#x}  va {}  [{}] {}  {:?}{}\n",
                        h.offset,
                        va.map(|v| Addr(v).to_string())
                            .unwrap_or_else(|| "-".into()),
                        va.and_then(|v| l.img.section_name(v)).unwrap_or("-"),
                        h.label,
                        eng::match_text(data, h)
                            .chars()
                            .take(80)
                            .collect::<String>(),
                        f.map(|f| format!("  in {f}")).unwrap_or_default()
                    );
                }
                s
            }
            "search_code" => {
                use drishti_disasm::search::{self as eng, InsnPattern, Limits};
                let pat = a
                    .get("pattern")
                    .and_then(Value::as_str)
                    .context("missing `pattern`")?;
                let p = InsnPattern::compile(
                    pat,
                    a.get("regex").and_then(Value::as_bool).unwrap_or(false),
                    a.get("case_sensitive")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                )
                .map_err(|e| anyhow!(e))?;
                let only = a
                    .get("addr")
                    .and_then(Value::as_str)
                    .map(|v| Addr::parse(v).map(|x| x.0).context("invalid `addr`"))
                    .transpose()?;
                let out = eng::search_insns(
                    &l.img,
                    &l.analysis,
                    &namer,
                    &p,
                    only,
                    Limits::new(20_000, std::time::Duration::from_secs(30)),
                );
                let mut s = format!(
                    "{}{} matches in {} functions scanned{}\n",
                    out.total,
                    if out.capped || out.timed_out { "+" } else { "" },
                    out.functions_scanned,
                    if out.total > limit {
                        format!(" (showing {limit})")
                    } else {
                        String::new()
                    }
                );
                for h in out.hits.iter().take(limit) {
                    s += &format!(
                        "{}  in {}: {}\n",
                        Addr(h.addr),
                        fname(h.function).unwrap_or_else(|| Addr(h.function).to_string()),
                        h.lines.join(" | ")
                    );
                }
                s
            }
            "find_vulns" => {
                let report = drishti_disasm::vuln::audit(&l.img, &l.analysis);
                let min = a
                    .get("min_confidence")
                    .and_then(Value::as_str)
                    .unwrap_or("low");
                let rank = |c: &str| match c {
                    "high" => 2,
                    "medium" => 1,
                    _ => 0,
                };
                let floor = rank(min);
                let shown: Vec<_> = report
                    .findings
                    .iter()
                    .filter(|f| rank(f.confidence) >= floor)
                    .take(limit)
                    .collect();
                let mut s = format!(
                    "{} potential weak spot(s) ({} sources, {} dangerous-call sites scanned over {} functions).\nNote: {}\n\n",
                    report.findings.len(),
                    report.sources_found,
                    report.sinks_found,
                    report.scanned_functions,
                    report.note
                );
                for f in shown {
                    let sink = fname(f.sink_fn.entry.0).unwrap_or_else(|| f.sink_fn.name.clone());
                    s += &format!(
                        "[{}/{}] {} — in {} ({})\n    {}\n",
                        f.severity, f.confidence, f.title, sink, f.sink_fn.entry, f.explanation
                    );
                    if !f.path.is_empty() {
                        let path = f
                            .path
                            .iter()
                            .map(|p| fname(p.entry.0).unwrap_or_else(|| p.name.clone()))
                            .collect::<Vec<_>>()
                            .join(" → ");
                        s += &format!("    path: {path}\n");
                    }
                    s += "\n";
                }
                s
            }
            "nl_query" => {
                let question = a
                    .get("question")
                    .and_then(Value::as_str)
                    .context("missing `question`")?;
                let t = drishti_disasm::nlq::heuristic(question);
                if t.empty {
                    format!(
                        "Could not translate {question:?} into a query. Try terms like JSON, file, network, shell command, encrypt, password, complex, unused.\nYou can also use the `list_functions` filter directly."
                    )
                } else {
                    let fq = drishti_disasm::search::FnQuery::parse(&t.query).map_err(|e| {
                        anyhow!("translated query `{}` did not parse: {e}", t.query)
                    })?;
                    let is_renamed = |e: u64| renames.contains_key(&e);
                    let cx = drishti_disasm::search::FnCtx {
                        analysis: &l.analysis,
                        image: Some(&l.img),
                        strings: &l.strings,
                        name_of: &namer,
                        is_renamed: &is_renamed,
                    };
                    let v: Vec<_> = l
                        .analysis
                        .functions
                        .iter()
                        .filter(|f| fq.matches(f, &fname(f.entry).unwrap_or_default(), &cx))
                        .collect();
                    let total = v.len();
                    let mut s = format!(
                        "question: {question}\nquery:    {}\nmeaning:  {}\n{total} match(es){}\n\n",
                        t.query,
                        t.notes.join("; "),
                        if total > limit {
                            format!(" (showing {limit})")
                        } else {
                            String::new()
                        }
                    );
                    for f in v.into_iter().take(limit) {
                        s += &format!(
                            "{}  {} bytes  {} callers  {}\n",
                            Addr(f.entry),
                            f.size,
                            f.called_by.len(),
                            fname(f.entry).unwrap_or_default()
                        );
                    }
                    s
                }
            }
            "triage" => {
                let info = drishti_loader::file_info(&l.blob, &l.name, Some(&l.img));
                let (hard, sig) = drishti_loader::insights::hardening(&l.img);
                let beh = drishti_disasm::insights::behaviors(&l.img, Some(&l.analysis));
                let summary = drishti_disasm::insights::summary(
                    &info,
                    Some(&l.img),
                    sig.as_ref(),
                    &beh,
                    Some(l.analysis.functions.len()),
                );
                let iocs = drishti_loader::insights::iocs(&l.strings);
                let report = drishti_disasm::vuln::audit(&l.img, &l.analysis);
                let (mut high, mut med) = (0usize, 0usize);
                for f in &report.findings {
                    match f.confidence {
                        "high" => high += 1,
                        "medium" => med += 1,
                        _ => {}
                    }
                }
                let top_beh = beh
                    .iter()
                    .filter(|b| b.severity != "info")
                    .take(8)
                    .map(|b| format!("  - [{}] {}", b.severity, b.name))
                    .collect::<Vec<_>>()
                    .join("\n");
                let top_ioc = iocs
                    .iter()
                    .take(15)
                    .map(|i| format!("  - {}: {}", i.kind, i.value))
                    .collect::<Vec<_>>()
                    .join("\n");
                format!(
                    "=== TRIAGE BRIEFING: {} ===\n\n{summary}\n\nFACTS\n  sha256: {}\n  format: {:?}  arch: {:?}  platform: {:?}\n  functions: {}  imports: {}  strings: {}\n\nWHAT IT CAN DO\n{}\n\nWEAK SPOTS (static reachability)\n  {} high-confidence, {} medium-confidence input→sink paths (run find_vulns for detail)\n\nINDICATORS\n{}\n\nHARDENING\n  {}\n",
                    l.name,
                    l.sha,
                    info.format,
                    info.arch,
                    info.platform,
                    l.analysis.functions.len(),
                    l.img.imports.len(),
                    l.strings.len(),
                    if top_beh.is_empty() {
                        "  (nothing notable)".into()
                    } else {
                        top_beh
                    },
                    high,
                    med,
                    if top_ioc.is_empty() {
                        "  (none extracted)".into()
                    } else {
                        top_ioc
                    },
                    serde_json::to_string(&hard).unwrap_or_default(),
                )
            }
            "rename" | "comment" => {
                let at = addr()?;
                let (kind, val) = if name == "rename" {
                    ("rename_function", a.get("name"))
                } else {
                    ("comment", a.get("text"))
                };
                let val = val.and_then(Value::as_str).context("missing value")?;
                anyhow::ensure!(val.len() <= 4096, "value too long");
                if name == "rename" {
                    anyhow::ensure!(
                        l.analysis.function_at(at).is_some(),
                        "no function starts at that address"
                    );
                }
                drishti_server::state::annotate_offline(&data_dir, &l.sha, at, kind, val)?;
                format!("saved {kind} at {}", Addr(at))
            }
            other => anyhow::bail!("unknown tool {other}"),
        })
    }
}

pub fn run(data_dir: &Path) -> Result<()> {
    let mut srv = Server {
        data_dir: data_dir.to_path_buf(),
        cache: Vec::new(),
    };
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            writeln!(
                out,
                "{}",
                json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}})
            )?;
            out.flush()?;
            continue;
        };
        let Some(id) = msg.get("id").cloned() else {
            continue;
        }; // notification
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let result: Result<Value, (i64, String)> = match method {
            "initialize" => Ok(json!({
                "protocolVersion": params.get("protocolVersion").and_then(Value::as_str).unwrap_or("2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "drishti", "version": env!("CARGO_PKG_VERSION")},
                "instructions": "Static reverse-engineering tools. Start with open_binary, then list_functions / function / strings / xrefs_to. Addresses are hex strings. Input files are never executed.",
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                // A panic inside analysis must not kill the session.
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    srv.call(name, &args)
                }));
                Ok(match r {
                    Ok(Ok(text)) => {
                        json!({"content": [{"type": "text", "text": text}], "isError": false})
                    }
                    Ok(Err(e)) => {
                        json!({"content": [{"type": "text", "text": format!("error: {e:#}")}], "isError": true})
                    }
                    Err(_) => {
                        json!({"content": [{"type": "text", "text": "internal error while analysing this input"}], "isError": true})
                    }
                })
            }
            _ => Err((-32601, format!("method not found: {method}"))),
        };
        let reply = match result {
            Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            Err((code, message)) => {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
            }
        };
        writeln!(out, "{reply}")?;
        out.flush()?;
    }
    Ok(())
}
