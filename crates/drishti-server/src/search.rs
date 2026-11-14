//! Search endpoints: one file (bytes, text, regex, numbers, instructions)
//! and every file in the library at once. The matching itself lives in
//! `drishti_disasm::search` so the CLI and MCP server share it.

use crate::api::{R, analysed, bad, session};
use crate::state::{Session, Shared};
use axum::Json;
use axum::extract::{Path, Query, State};
use drishti_disasm::search::{
    self as eng, ByteQuery, Enc, InsnPattern, Limits, Mode, Order, RawHit, Scope,
};
use drishti_model::{Addr, Endian};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// `48 8b 05` — spaced hex, as the hex view shows bytes.
fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 3);
    for (i, x) in b.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s += &format!("{x:02x}");
    }
    s
}

const MAX_HITS: usize = 100_000;
const MAX_INSN_HITS: usize = 20_000;
const BUDGET: Duration = Duration::from_secs(20);

#[derive(Deserialize, Default)]
pub struct SearchQ {
    /// text | hex | regex | number | insn
    mode: Option<String>,
    q: Option<String>,
    /// Legacy: `?hex=` / `?text=`.
    hex: Option<String>,
    text: Option<String>,
    /// Case-sensitive (text, regex, insn). Default: no.
    case: Option<String>,
    /// Text encodings, comma separated: utf8, utf16le, utf16be.
    enc: Option<String>,
    /// Number width in bits (8, 16, 32, 64) or bytes (1, 2, 4, 8).
    width: Option<String>,
    /// Number byte order: file (default), le, be, both.
    endian: Option<String>,
    /// all | code | data | section:<name>
    scope: Option<String>,
    /// Instruction search: only the function containing this address.
    #[serde(rename = "fn")]
    func: Option<String>,
    /// Instruction search: parts are regular expressions.
    regex: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
}

fn truthy(v: &Option<String>) -> bool {
    v.as_deref()
        .is_some_and(|s| matches!(s, "1" | "true" | "yes" | "on"))
}

/// Mode + query from the new (`mode`, `q`) or legacy (`hex`, `text`) params.
fn mode_query(q: &SearchQ) -> R<(String, String)> {
    if let Some(m) = q.mode.as_deref().filter(|m| !m.is_empty()) {
        let text = q.q.clone().unwrap_or_default();
        return Ok((m.to_string(), text));
    }
    match (&q.hex, &q.text) {
        (Some(h), _) if !h.trim().is_empty() => Ok(("hex".into(), h.clone())),
        (_, Some(t)) if !t.is_empty() => Ok(("text".into(), t.clone())),
        _ => Err(bad("pass ?mode=text|hex|regex|number|insn&q=…")),
    }
}

fn byte_query(q: &SearchQ, mode: Mode, text: String, file_endian: Option<Endian>) -> R<ByteQuery> {
    let mut bq = ByteQuery::new(mode, text);
    // Legacy `?text=` was case-sensitive, ASCII only.
    let legacy_text = q.mode.is_none() && q.text.is_some();
    bq.case_sensitive = truthy(&q.case) || legacy_text;
    bq.encodings = match q.enc.as_deref() {
        Some(e) => Enc::parse_list(e).map_err(bad)?,
        None if legacy_text => vec![Enc::Utf8],
        None => Vec::new(),
    };
    bq.width = match q.width.as_deref().unwrap_or("").trim() {
        "" | "auto" => None,
        "1" | "8" => Some(1),
        "2" | "16" => Some(2),
        "4" | "32" => Some(4),
        "64" => Some(8),
        w => return Err(bad(format!("width `{w}` must be 8, 16, 32 or 64"))),
    };
    let file = match file_endian {
        Some(Endian::Big) => Order::Big,
        _ => Order::Little,
    };
    bq.endian = match q.endian.as_deref().unwrap_or("file") {
        "file" | "" => Some(file),
        "le" | "little" => Some(Order::Little),
        "be" | "big" => Some(Order::Big),
        "both" | "any" => None,
        e => return Err(bad(format!("endian `{e}` must be file, le, be or both"))),
    };
    Ok(bq)
}

fn page<T: Clone>(v: &[T], q: &SearchQ, default: usize) -> (usize, Vec<T>) {
    let off = q.offset.unwrap_or(0).min(v.len());
    let lim = q.limit.unwrap_or(default).clamp(1, 2000);
    (off, v[off..(off + lim).min(v.len())].to_vec())
}

fn renamed_name(renames: &HashMap<u64, String>, s: &Session, entry: u64, fallback: &str) -> String {
    renames
        .get(&entry)
        .cloned()
        .or_else(|| {
            s.analysis
                .as_ref()
                .and_then(|a| a.function_at(entry))
                .map(|f| f.name.to_string())
        })
        .unwrap_or_else(|| fallback.to_string())
}

/// Address, section, function and readable context of one byte hit.
fn hit_json(s: &Session, renames: &HashMap<u64, String>, data: &[u8], h: &RawHit) -> Value {
    let img = s.image.as_deref();
    let va = img.and_then(|im| {
        let rel = h.offset.checked_sub(im.slice_offset)?;
        (rel < im.slice_len).then_some(())?;
        im.offset_to_va(rel as u64)
    });
    let section = va.and_then(|v| img?.section_name(v)).map(str::to_string);
    let function = va.and_then(|v| {
        let f = s.analysis.as_ref()?.function_containing(v)?;
        Some(json!({"entry": Addr(f.entry), "name": renamed_name(renames, s, f.entry, &f.name)}))
    });
    let end = (h.offset + h.len).min(data.len());
    let wide = h.label.starts_with("utf-16");
    let (before, after) = if wide {
        (String::new(), String::new())
    } else {
        (
            eng::printable(&data[h.offset.saturating_sub(16)..h.offset]),
            eng::printable(&data[end..(end + 24).min(data.len())]),
        )
    };
    json!({
        "offset": h.offset,
        "len": h.len,
        "va": va.map(Addr),
        "section": section,
        "function": function,
        "label": h.label,
        "bytes": hex(&data[h.offset..(h.offset + h.len.min(32)).min(data.len())]),
        "text": eng::match_text(data, h),
        "before": before,
        "after": after,
    })
}

/// `GET /binaries/{sha}/search?mode=&q=…` — search one file.
pub async fn search(
    State(st): State<Shared>,
    Path(sha): Path<String>,
    Query(q): Query<SearchQ>,
) -> R<Json<Value>> {
    let (mode_s, text) = mode_query(&q)?;
    if mode_s == "insn" || mode_s == "code" || mode_s == "instructions" {
        return insn_search(st, sha, q, text).await;
    }
    let mode = Mode::parse(&mode_s).ok_or_else(|| {
        bad(format!(
            "unknown mode `{mode_s}` (text, hex, regex, number, insn)"
        ))
    })?;
    let s = session(&st, &sha).await?;
    let bq = byte_query(&q, mode, text, s.image.as_ref().map(|i| i.endian))?;
    let compiled = eng::compile(&bq).map_err(bad)?;
    let scope = Scope::parse(q.scope.as_deref().unwrap_or("all"));
    let renames = st.renames(&sha);
    let v = tokio::task::spawn_blocking(move || -> Result<Value, String> {
        let t0 = Instant::now();
        let data = s.blob.as_ref().as_ref();
        let ranges = eng::scope_ranges(data.len(), s.image.as_deref(), &scope)?;
        let out = eng::scan(data, &ranges, &compiled, Limits::new(MAX_HITS, BUDGET));
        let (off, pg) = page(&out.hits, &q, 200);
        let hits: Vec<Value> = pg.iter().map(|h| hit_json(&s, &renames, data, h)).collect();
        let mut labels: HashMap<&str, usize> = HashMap::new();
        for h in &out.hits {
            *labels.entry(h.label.as_str()).or_default() += 1;
        }
        Ok(json!({
            "mode": mode_s,
            "total": out.total,
            "capped": out.capped,
            "partial": out.timed_out,
            "offset": off,
            "hits": hits,
            "by_kind": labels,
            "searched_bytes": ranges.iter().map(|r| r.1 - r.0).sum::<usize>(),
            "elapsed_ms": t0.elapsed().as_millis() as u64,
        }))
    })
    .await?
    .map_err(bad)?;
    Ok(Json(v))
}

async fn insn_search(st: Shared, sha: String, q: SearchQ, text: String) -> R<Json<Value>> {
    let pat = InsnPattern::compile(&text, truthy(&q.regex), truthy(&q.case)).map_err(bad)?;
    let s = analysed(&st, &sha).await?;
    let only = match q.func.as_deref().filter(|f| !f.is_empty()) {
        Some(f) => Some(
            Addr::parse(f)
                .ok_or_else(|| bad(format!("`{f}` is not an address")))?
                .0,
        ),
        None => None,
    };
    let renames = st.renames(&sha);
    let v = tokio::task::spawn_blocking(move || -> Result<Value, String> {
        let t0 = Instant::now();
        let img = s.image.as_deref().ok_or("no code to search in this file")?;
        let a = s.analysis.as_ref().ok_or("not analysed")?;
        let namer = |x: u64| renames.get(&x).cloned().or_else(|| s.base_name(x));
        let out = eng::search_insns(img, a, &namer, &pat, only, Limits::new(MAX_INSN_HITS, BUDGET));
        let (off, pg) = page(&out.hits, &q, 200);
        let hits: Vec<Value> = pg
            .iter()
            .map(|h| {
                let f = a.function_at(h.function);
                json!({
                    "va": Addr(h.addr),
                    "function": f.map(|f| json!({"entry": Addr(f.entry), "name": renamed_name(&renames, &s, f.entry, &f.name)})),
                    "section": img.section_name(h.addr),
                    "lines": h.lines,
                    "label": "insn",
                })
            })
            .collect();
        Ok(json!({
            "mode": "insn",
            "total": out.total,
            "capped": out.capped,
            "partial": out.timed_out,
            "offset": off,
            "hits": hits,
            "functions_scanned": out.functions_scanned,
            "functions_total": if only.is_some() { 1 } else { a.functions.len() },
            "instructions_scanned": out.instructions_scanned,
            "elapsed_ms": t0.elapsed().as_millis() as u64,
        }))
    })
    .await?
    .map_err(bad)?;
    Ok(Json(v))
}

/// `GET /search?mode=&q=…` — which files in the library contain this?
pub async fn search_all(State(st): State<Shared>, Query(q): Query<SearchQ>) -> R<Json<Value>> {
    let (mode_s, text) = mode_query(&q)?;
    let mode = Mode::parse(&mode_s).ok_or_else(|| {
        bad("searching every file works for text, hex, regex and number searches")
    })?;
    let bq = byte_query(&q, mode, text, None)?;
    let compiled = Arc::new(eng::compile(&bq).map_err(bad)?);
    let rows: Vec<(String, String, i64)> = {
        let db = st.db.lock().map_err(|e| e.to_string())?;
        let mut stmt = db.prepare(
            "SELECT sha256, file_name, size FROM binaries ORDER BY created_at DESC LIMIT 500",
        )?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .flatten()
            .collect()
    };
    let per_file = q.limit.unwrap_or(5).clamp(1, 50);
    let v = tokio::task::spawn_blocking(move || {
        let t0 = Instant::now();
        let deadline = t0 + Duration::from_secs(30);
        let mut files = Vec::new();
        let (mut searched, mut unreadable, mut bytes) = (0usize, 0usize, 0u64);
        let mut partial = false;
        let mut seen = std::collections::HashSet::new();
        for (sha, name, _size) in rows {
            if !seen.insert(sha.clone()) {
                continue;
            }
            if Instant::now() > deadline {
                partial = true;
                break;
            }
            let Some(path) = st.binary_location(&sha) else {
                unreadable += 1;
                continue;
            };
            let Ok(blob) = drishti_loader::open(&path) else {
                unreadable += 1;
                continue;
            };
            let data = blob.as_ref().as_ref();
            searched += 1;
            bytes += data.len() as u64;
            let out = eng::scan(
                data,
                &[(0, data.len())],
                &compiled,
                Limits {
                    max_hits: 10_000,
                    deadline,
                },
            );
            partial |= out.timed_out;
            if out.total == 0 {
                continue;
            }
            // Addresses only when the file is already open (no parsing here).
            let sess = st.cached(&sha);
            let renames = HashMap::new();
            let hits: Vec<Value> = out
                .hits
                .iter()
                .take(per_file)
                .map(|h| match &sess {
                    Some(s) => hit_json(s, &renames, data, h),
                    None => json!({
                        "offset": h.offset, "len": h.len, "label": h.label,
                        "text": eng::match_text(data, h),
                        "bytes": hex(&data[h.offset..(h.offset + h.len.min(32)).min(data.len())]),
                    }),
                })
                .collect();
            files.push(json!({
                "sha256": sha, "file_name": name, "size": data.len(),
                "total": out.total, "capped": out.capped, "hits": hits,
            }));
        }
        files.sort_by(|a, b| b["total"].as_u64().cmp(&a["total"].as_u64()));
        json!({
            "mode": mode_s,
            "files": files,
            "searched": searched,
            "unreadable": unreadable,
            "searched_bytes": bytes,
            "partial": partial,
            "elapsed_ms": t0.elapsed().as_millis() as u64,
        })
    })
    .await?;
    Ok(Json(v))
}
