//! REST + WebSocket API under `/api/v1` (spec §7.12).

use crate::state::*;
use crate::util::{new_id, now};
use axum::Json;
use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use drishti_disasm::{Options, analyze};
use drishti_model::{Addr, Annotation, AnnotationKind, Author, Xref};
use futures_util::StreamExt;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::AsyncWriteExt;

pub struct ApiError(pub StatusCode, pub String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}
impl<E: std::fmt::Display> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}
pub(crate) fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}
pub(crate) fn not_found(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, msg.into())
}
pub(crate) type R<T> = Result<T, ApiError>;

pub(crate) fn valid_sha(s: &str) -> R<()> {
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(bad("invalid sha256"))
    }
}
fn parse_addr(s: &str) -> R<u64> {
    Addr::parse(s)
        .map(|a| a.0)
        .ok_or_else(|| bad(format!("invalid address {s}")))
}

// ---------------------------------------------------------------- sessions

/// Get (or load) the session for `sha`. Loading runs on the blocking pool.
pub async fn session(st: &Shared, sha: &str) -> R<Arc<Session>> {
    valid_sha(sha)?;
    if let Some(s) = st.cached(sha) {
        return Ok(s);
    }
    // Single-flight: one load per binary; others wait and reuse it.
    let gate = {
        let mut m = st.session_loads.lock().map_err(|e| e.to_string())?;
        m.entry(sha.to_string()).or_default().clone()
    };
    let _guard = gate.lock().await;
    if let Some(s) = st.cached(sha) {
        return Ok(s);
    }
    let r = load_session_now(st, sha).await;
    if let Ok(mut m) = st.session_loads.lock() {
        m.remove(sha);
    }
    r
}

async fn load_session_now(st: &Shared, sha: &str) -> R<Arc<Session>> {
    let path = st
        .binary_location(sha)
        .ok_or_else(|| not_found("unknown binary"))?;
    let (name, known_info) = {
        let db = st.db.lock().map_err(|e| e.to_string())?;
        db.query_row(
            "SELECT file_name, file_info FROM binaries WHERE sha256=?1",
            params![sha],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
        )
        .map(|(n, fi)| {
            let fi = fi.and_then(|j| serde_json::from_str::<drishti_model::FileInfo>(&j).ok());
            (n, fi)
        })
        .unwrap_or_default()
    };
    let sha2 = sha.to_string();
    let cache = st.analysis_cache_path(sha);
    let cache_dir = st.data_dir.join("cache");
    let sess = tokio::task::spawn_blocking(move || {
        let t = std::time::Instant::now();
        let mut s = load_session(&sha2, &path, &name, known_info, Some(&cache_dir));
        // A persisted analysis makes a restarted server ready at once.
        if s.image.is_some() && s.load_error.is_none() {
            s.analysis = drishti_disasm::cache::load(&cache);
        }
        tracing::info!(
            "session {} loaded in {:?} (analysis {})",
            &sha2[..12.min(sha2.len())],
            t.elapsed(),
            if s.analysis.is_some() {
                "from cache"
            } else {
                "pending"
            }
        );
        s
    })
    .await?;
    let sess = Arc::new(sess);
    st.put_session(sess.clone());
    Ok(sess)
}

pub(crate) async fn analysed(st: &Shared, sha: &str) -> R<Arc<Session>> {
    let s = session(st, sha).await?;
    if s.analysis.is_none() {
        // Kick off analysis transparently; caller gets 409 + job id.
        let job = start_job(st, sha).await?;
        return Err(ApiError(
            StatusCode::CONFLICT,
            format!("analysis running: job {job}"),
        ));
    }
    Ok(s)
}

// ---------------------------------------------------------------- binaries

#[derive(Serialize)]
struct BinaryRow {
    sha256: String,
    file_name: String,
    size: i64,
    format: String,
    ext_path: Option<String>,
    created_at: String,
}

pub async fn list_binaries(State(st): State<Shared>) -> R<Json<Value>> {
    let db = st.db.lock().map_err(|e| e.to_string())?;
    let mut q = db.prepare("SELECT sha256, file_name, size, format, ext_path, created_at FROM binaries ORDER BY created_at DESC LIMIT 200")?;
    let rows: Vec<BinaryRow> = q
        .query_map([], |r| {
            Ok(BinaryRow {
                sha256: r.get(0)?,
                file_name: r.get(1)?,
                size: r.get(2)?,
                format: r.get(3)?,
                ext_path: r.get(4)?,
                created_at: r.get(5)?,
            })
        })?
        .flatten()
        .collect();
    Ok(Json(json!({ "binaries": rows })))
}

fn register(
    st: &Shared,
    sha: &str,
    name: &str,
    ext_path: Option<&str>,
    mtime: Option<i64>,
) -> R<drishti_model::FileInfo> {
    let path = match ext_path {
        Some(p) => PathBuf::from(p),
        None => st.blob_path(sha),
    };
    let blob = drishti_loader::open(&path)?;
    let img = drishti_loader::load_image(blob.clone(), None).ok();
    let mut info = drishti_loader::file_info(&blob, name, img.as_ref());
    info.sha256 = sha.to_string();
    let fmt = serde_json::to_value(info.format)?
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let db = st.db.lock().map_err(|e| e.to_string())?;
    db.execute(
        "INSERT INTO binaries (sha256, file_name, size, format, file_info, ext_path, mtime, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
         ON CONFLICT(sha256) DO UPDATE SET file_name=excluded.file_name, ext_path=COALESCE(excluded.ext_path, binaries.ext_path), mtime=excluded.mtime, created_at=excluded.created_at",
        params![sha, name, info.size as i64, fmt, serde_json::to_string(&info)?, ext_path, mtime, now()],
    )?;
    Ok(info)
}

#[derive(Deserialize)]
pub struct UploadQ {
    name: Option<String>,
    #[serde(default)]
    analyze: Option<bool>,
}

/// Upload raw bytes (body = file). Streams to disk while hashing, so memory
/// use is constant regardless of file size.
pub async fn upload(
    State(st): State<Shared>,
    Query(q): Query<UploadQ>,
    headers: HeaderMap,
    req: Request,
) -> R<Json<Value>> {
    let name = q
        .name
        .or_else(|| {
            headers
                .get("x-file-name")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "upload.bin".into());
    let name: String = name
        .chars()
        .filter(|c| !matches!(c, '/' | '\\' | '\0'))
        .take(255)
        .collect();
    let tmp_dir = st.data_dir.join("tmp");
    tokio::fs::create_dir_all(&tmp_dir).await?;
    let tmp = tmp_dir.join(new_id());
    let mut f = tokio::fs::File::create(&tmp).await?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut stream = req.into_body().into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| bad(e.to_string()))?;
        total += chunk.len() as u64;
        if total > st.upload_limit {
            drop(f);
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(ApiError(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("upload exceeds {} bytes", st.upload_limit),
            ));
        }
        hasher.update(&chunk);
        f.write_all(&chunk).await?;
    }
    f.flush().await?;
    drop(f);
    if total == 0 {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(bad("empty upload"));
    }
    let sha = drishti_loader::util::hex(&hasher.finalize());
    let dest = st.blob_path(&sha);
    if let Some(p) = dest.parent() {
        tokio::fs::create_dir_all(p).await?;
    }
    if tokio::fs::metadata(&dest).await.is_ok() {
        let _ = tokio::fs::remove_file(&tmp).await;
    } else {
        tokio::fs::rename(&tmp, &dest).await?;
    }
    let st2 = st.clone();
    let sha2 = sha.clone();
    let info =
        tokio::task::spawn_blocking(move || register(&st2, &sha2, &name, None, None)).await??;
    let job = if q.analyze.unwrap_or(true) && info.format.is_native() {
        Some(start_job(&st, &sha).await?)
    } else {
        None
    };
    Ok(Json(
        json!({ "binary_id": sha, "file": info, "job_id": job }),
    ))
}

#[derive(Deserialize)]
pub struct OpenPath {
    path: String,
    #[serde(default)]
    analyze: Option<bool>,
}

/// Resolve `.app` bundles to their main executable.
fn resolve_bundle(p: PathBuf) -> PathBuf {
    if !p.is_dir() {
        return p;
    }
    let macos = p.join("Contents").join("MacOS");
    if let Some(stem) = p.file_stem() {
        let cand = macos.join(stem);
        if cand.is_file() {
            return cand;
        }
    }
    if let Ok(plist) = std::fs::read_to_string(p.join("Contents").join("Info.plist"))
        && let Some(i) = plist.find("<key>CFBundleExecutable</key>")
    {
        let rest = &plist[i..];
        if let (Some(a), Some(b)) = (rest.find("<string>"), rest.find("</string>"))
            && a + 8 < b
        {
            let cand = macos.join(&rest[a + 8..b]);
            if cand.is_file() {
                return cand;
            }
        }
    }
    if let Ok(mut rd) = std::fs::read_dir(&macos)
        && let Some(Ok(e)) = rd.next()
    {
        return e.path();
    }
    p
}

/// Local mode only: analyse a file in place (no copy → no extra disk use).
/// Files opened this way are watched and re-analysed when they change.
pub async fn open_path(State(st): State<Shared>, Json(b): Json<OpenPath>) -> R<Json<Value>> {
    if !st.local_mode {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "opening server paths is disabled in server mode".into(),
        ));
    }
    let raw = PathBuf::from(shellexpand(&b.path));
    let path = resolve_bundle(raw);
    let meta = tokio::fs::metadata(&path)
        .await
        .map_err(|e| bad(format!("{}: {e}", path.display())))?;
    if !meta.is_file() {
        return Err(bad("not a file"));
    }
    let res = open_local(&st, path, b.analyze.unwrap_or(true)).await?;
    Ok(Json(res))
}

fn shellexpand(p: &str) -> String {
    let p = p.trim().trim_matches('"').trim_matches('\'');
    if let Some(rest) = p.strip_prefix("~/")
        && let Some(h) = std::env::var_os("HOME")
    {
        return format!("{}/{}", h.to_string_lossy(), rest);
    }
    p.to_string()
}

fn mtime_of(m: &std::fs::Metadata) -> i64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A previously registered in-place file at `path` with the same mtime and
/// size: its sha and FileInfo, so reopening skips hashing the whole file
/// (~1 s for a 190 MB binary). Same change signal the file watcher uses.
fn known_unchanged(
    st: &Shared,
    path: &str,
    mtime: i64,
    size: u64,
) -> Option<(String, drishti_model::FileInfo)> {
    let db = st.db.lock().ok()?;
    let (sha, fi): (String, String) = db
        .query_row(
            "SELECT sha256, file_info FROM binaries WHERE ext_path=?1 AND mtime=?2 AND size=?3
             ORDER BY created_at DESC LIMIT 1",
            params![path, mtime, size as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .ok()??;
    let info: drishti_model::FileInfo = serde_json::from_str(&fi).ok()?;
    // Keep "Recent" ordering current.
    let _ = db.execute(
        "UPDATE binaries SET created_at=?1 WHERE sha256=?2",
        params![now(), sha],
    );
    Some((sha, info))
}

pub async fn open_local(st: &Shared, path: PathBuf, analyze_now: bool) -> R<Value> {
    let meta = tokio::fs::metadata(&path).await?;
    let mtime = mtime_of(&meta);
    let ps = path.to_string_lossy().into_owned();
    let (sha, info) = match known_unchanged(st, &ps, mtime, meta.len()) {
        Some(known) => known,
        None => {
            let p2 = path.clone();
            let sha = tokio::task::spawn_blocking(move || -> std::io::Result<String> {
                let b = drishti_loader::Blob::open(&p2)?;
                Ok(drishti_loader::util::sha256_hex(b.as_ref()))
            })
            .await??;
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let st2 = st.clone();
            let sha2 = sha.clone();
            let info = tokio::task::spawn_blocking(move || {
                register(&st2, &sha2, &name, Some(&ps), Some(mtime))
            })
            .await??;
            (sha, info)
        }
    };
    if let Ok(mut w) = st.watched.lock() {
        w.retain(|_, (p, _)| *p != path);
        w.insert(sha.clone(), (path.clone(), mtime));
    }
    let job = if analyze_now && info.format.is_native() {
        Some(start_job(st, &sha).await?)
    } else {
        None
    };
    Ok(json!({ "binary_id": sha, "file": info, "job_id": job }))
}

pub async fn get_binary(State(st): State<Shared>, Path(sha): Path<String>) -> R<Json<Value>> {
    let s = session(&st, &sha).await?;
    // Opening a binary is enough: analyse automatically (e.g. after a
    // server restart) and resume watching files that were opened in place.
    if s.analysis.is_none() && s.image.is_some() && s.load_error.is_none() {
        let failed = st
            .jobs
            .lock()
            .ok()
            .is_some_and(|j| j.values().any(|j| j.sha256 == sha && j.status == "failed"));
        if !failed {
            let _ = start_job(&st, &sha).await;
        }
    }
    if st.local_mode
        && !st
            .watched
            .lock()
            .map(|w| w.contains_key(&sha))
            .unwrap_or(true)
        && let Some(p) = st
            .binary_location(&sha)
            .filter(|p| *p != st.blob_path(&sha))
        && let Ok(m) = tokio::fs::metadata(&p).await
        && let Ok(mut w) = st.watched.lock()
    {
        w.insert(sha.clone(), (p, mtime_of(&m)));
    }
    let job = st.jobs.lock().ok().and_then(|j| {
        j.values()
            .filter(|j| j.sha256 == sha)
            .max_by(|a, b| a.created_at.cmp(&b.created_at))
            .cloned()
    });
    let stats = s.analysis.as_ref().map(|a| json!({"functions": a.functions.len(), "instructions": a.stats.instructions, "xrefs": a.xrefs.len(), "jump_tables": a.stats.jump_tables, "gap_functions": a.stats.gap_functions, "duration_ms": a.stats.duration_ms}));
    let img = s.image.as_ref();
    Ok(Json(json!({
        "file": s.info,
        "sections": img.map(|i| &i.sections),
        "findings": s.findings,
        "counts": { "imports": img.map(|i| i.imports.len()), "exports": img.map(|i| i.exports.len()), "symbols": img.map(|i| i.symbols.len()), "strings": s.strings.len() },
        "image_base": img.map(|i| Addr(i.image_base)),
        "analysed": s.analysis.is_some(),
        "analysis": stats,
        "job": job,
        "warnings": img.map(|i| &i.warnings),
        "load_error": s.load_error,
        "watched": st.watched.lock().ok().map(|w| w.contains_key(&sha)).unwrap_or(false),
    })))
}

#[derive(Deserialize)]
pub struct BytesQ {
    offset: Option<u64>,
    va: Option<String>,
    len: Option<usize>,
}

/// Raw bytes for the hex view (≤ 64 KiB per call), by file offset or VA.
pub async fn bytes(
    State(st): State<Shared>,
    Path(sha): Path<String>,
    Query(q): Query<BytesQ>,
) -> R<Response> {
    let s = session(&st, &sha).await?;
    let len = q.len.unwrap_or(4096).min(65536);
    let data = s.blob.as_ref().as_ref();
    let off = match (&q.va, &s.image) {
        (Some(va), Some(img)) => img
            .va_to_offset(parse_addr(va)?)
            .map(|o| o + img.slice_offset as u64)
            .ok_or_else(|| bad("address not file-backed"))?,
        _ => q.offset.unwrap_or(0),
    };
    let start = (off as usize).min(data.len());
    let end = start.saturating_add(len).min(data.len());
    let body = data[start..end].to_vec();
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, "attachment")
        .header("x-offset", start.to_string())
        .header("x-file-size", data.len().to_string())
        .body(Body::from(body))?)
}

// ---------------------------------------------------------------- tables

#[derive(Deserialize, Default)]
pub struct ListQ {
    filter: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
    sort: Option<String>,
    /// Strings: only these encodings (comma separated: ascii, utf8, utf16le).
    enc: Option<String>,
    /// Strings: minimum length in characters.
    min: Option<usize>,
    /// Strings: only ones referenced from code (`1`).
    refs: Option<String>,
}

fn page<T: Serialize>(items: Vec<T>, q: &ListQ) -> Value {
    let total = items.len();
    let off = q.offset.unwrap_or(0).min(total);
    let lim = q.limit.unwrap_or(1000).min(20000);
    let slice: Vec<&T> = items.iter().skip(off).take(lim).collect();
    json!({ "total": total, "offset": off, "items": slice })
}

/// Table filter: case-insensitive substring, or a regex written `/like this/`.
fn matcher(q: &ListQ) -> R<impl Fn(&str) -> bool> {
    let raw = q.filter.clone().unwrap_or_default();
    let re = if raw.len() >= 2 && raw.starts_with('/') && raw.ends_with('/') {
        Some(
            regex::RegexBuilder::new(&raw[1..raw.len() - 1])
                .case_insensitive(true)
                .size_limit(4 << 20)
                .build()
                .map_err(|e| {
                    bad(format!(
                        "invalid regex: {}",
                        e.to_string().lines().last().unwrap_or("").trim()
                    ))
                })?,
        )
    } else {
        None
    };
    let f = raw.to_lowercase();
    Ok(move |s: &str| match &re {
        Some(r) => r.is_match(s),
        None => f.is_empty() || s.to_lowercase().contains(&f),
    })
}

pub async fn t_symbols(st: State<Shared>, sha: Path<String>, q: Query<ListQ>) -> R<Json<Value>> {
    table(st, sha, q, "symbols").await
}
pub async fn t_imports(st: State<Shared>, sha: Path<String>, q: Query<ListQ>) -> R<Json<Value>> {
    table(st, sha, q, "imports").await
}
pub async fn t_exports(st: State<Shared>, sha: Path<String>, q: Query<ListQ>) -> R<Json<Value>> {
    table(st, sha, q, "exports").await
}

async fn table(
    State(st): State<Shared>,
    Path(sha): Path<String>,
    Query(q): Query<ListQ>,
    which: &str,
) -> R<Json<Value>> {
    let s = session(&st, &sha).await?;
    let img = s
        .image
        .as_ref()
        .ok_or_else(|| not_found("no native image"))?;
    let m = matcher(&q)?;
    let list = match which {
        "symbols" => &img.symbols,
        "imports" => &img.imports,
        "exports" => &img.exports,
        _ => return Err(not_found("unknown table")),
    };
    let items: Vec<Value> = list
        .iter()
        .filter(|x| m(x.display_name()) || m(&x.name) || x.library.as_deref().is_some_and(&m))
        .map(|x| {
            let mut v = serde_json::to_value(x).unwrap_or(Value::Null);
            if which == "imports" {
                v["capability"] = json!(drishti_loader::image::import_capability(&x.name));
            }
            v
        })
        .collect();
    Ok(Json(page(items, &q)))
}

pub async fn strings(
    State(st): State<Shared>,
    Path(sha): Path<String>,
    Query(q): Query<ListQ>,
) -> R<Json<Value>> {
    let s = session(&st, &sha).await?;
    let m = matcher(&q)?;
    let encs: Vec<String> = q
        .enc
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|e| e.trim().to_ascii_lowercase().replace(['-', '_'], ""))
        .filter(|e| !e.is_empty())
        .collect();
    let min = q.min.unwrap_or(0);
    let only_refs = matches!(q.refs.as_deref(), Some("1" | "true" | "yes"));
    let items: Vec<Value> = s
        .strings
        .iter()
        .filter(|x| {
            encs.is_empty()
                || encs.iter().any(|e| {
                    serde_json::to_value(x.encoding)
                        .ok()
                        .and_then(|v| v.as_str().map(|v| v == e))
                        .unwrap_or(false)
                })
        })
        .filter(|x| min == 0 || x.value.chars().count() >= min)
        .filter(|x| m(&x.value))
        .filter_map(|x| {
            let xr: Vec<Addr> = s
                .analysis
                .as_ref()
                .map(|a| {
                    a.xrefs_to(x.addr.0)
                        .iter()
                        .map(|r| Addr(r.from))
                        .take(32)
                        .collect()
                })
                .unwrap_or_default();
            if only_refs && xr.is_empty() {
                return None;
            }
            Some(json!({"addr": x.addr, "value": x.value, "encoding": x.encoding, "xrefs": xr}))
        })
        .collect();
    Ok(Json(page(items, &q)))
}

#[derive(Serialize)]
struct FnRow {
    entry: Addr,
    name: String,
    renamed: bool,
    size: u64,
    blocks: usize,
    insns: u32,
    calls: usize,
    callers: usize,
    cyclomatic: u32,
    thunk: bool,
    noreturn: bool,
}

pub async fn functions(
    State(st): State<Shared>,
    Path(sha): Path<String>,
    Query(q): Query<ListQ>,
) -> R<Json<Value>> {
    let s = analysed(&st, &sha).await?;
    let a = s
        .analysis
        .as_ref()
        .ok_or_else(|| not_found("not analysed"))?;
    let renames = st.renames(&sha);
    // Query language (drishti_disasm::search::FnQuery): bare words match the
    // name or address as before; `calls:x size>200 -is:thunk` etc. filter.
    let fq =
        drishti_disasm::search::FnQuery::parse(q.filter.as_deref().unwrap_or("")).map_err(bad)?;
    let name_of = |x: u64| renames.get(&x).cloned().or_else(|| s.base_name(x));
    let is_renamed = |x: u64| renames.contains_key(&x);
    let cx = drishti_disasm::search::FnCtx {
        analysis: a,
        image: s.image.as_deref(),
        strings: &s.strings,
        name_of: &name_of,
        is_renamed: &is_renamed,
    };
    let mut rows: Vec<FnRow> = a
        .functions
        .iter()
        .filter(|f| {
            fq.is_empty()
                || fq.matches(
                    f,
                    renames.get(&f.entry).map(String::as_str).unwrap_or(&f.name),
                    &cx,
                )
        })
        .map(|f| {
            let rn = renames.get(&f.entry);
            FnRow {
                entry: Addr(f.entry),
                name: rn.cloned().unwrap_or_else(|| f.name.to_string()),
                renamed: rn.is_some(),
                size: f.size,
                blocks: f.nblocks as usize,
                insns: f.insns,
                calls: f.calls.len(),
                callers: f.called_by.len(),
                cyclomatic: f.cyclomatic(),
                thunk: f.is_thunk,
                noreturn: f.noreturn,
            }
        })
        .collect();
    match q.sort.as_deref() {
        Some("name") => rows.sort_by(|a, b| a.name.cmp(&b.name)),
        Some("size") => rows.sort_by(|a, b| b.size.cmp(&a.size)),
        Some("blocks") => rows.sort_by(|a, b| b.blocks.cmp(&a.blocks)),
        Some("callers") => rows.sort_by(|a, b| b.callers.cmp(&a.callers)),
        Some("complexity") => rows.sort_by(|a, b| b.cyclomatic.cmp(&a.cyclomatic)),
        _ => {}
    }
    Ok(Json(page(rows, &q)))
}

fn namer<'a>(
    s: &'a Session,
    renames: &'a HashMap<u64, String>,
) -> impl Fn(u64) -> Option<String> + 'a {
    move |a| renames.get(&a).cloned().or_else(|| s.base_name(a))
}

pub async fn function_detail(
    State(st): State<Shared>,
    Path((sha, addr)): Path<(String, String)>,
) -> R<Json<Value>> {
    let s = analysed(&st, &sha).await?;
    let a = s
        .analysis
        .as_ref()
        .ok_or_else(|| not_found("not analysed"))?;
    let img = s.image.as_ref().ok_or_else(|| not_found("no image"))?;
    let at = parse_addr(&addr)?;
    let f = a
        .function_at(at)
        .or_else(|| a.function_containing(at))
        .ok_or_else(|| not_found("no function at address"))?;
    let renames = st.renames(&sha);
    let cfg = a.cfg(img, f.entry).unwrap_or_default();
    let lo = cfg.iter().map(|b| b.start).min().unwrap_or(f.entry);
    let hi = cfg.iter().map(|b| b.end).max().unwrap_or(f.entry);
    let comments = st.comments(&sha, lo, hi);
    let nm = namer(&s, &renames);
    let mut budget = 30_000usize;
    let mut blocks = Vec::with_capacity(cfg.len());
    for b in &cfg {
        let n = (b.insns as usize).min(budget);
        budget -= n;
        let mut insns = drishti_disasm::disasm(img, b.start, n, &nm);
        insns.retain(|i| i.addr.0 < b.end);
        for i in &mut insns {
            if let Some(c) = comments.get(&i.addr.0) {
                i.comment = Some(match &i.comment {
                    Some(x) => format!("{x} | {c}"),
                    None => c.clone(),
                });
            }
        }
        blocks.push(json!({
            "start": Addr(b.start), "end": Addr(b.end),
            "successors": b.succs.iter().map(|&(t, k)| json!({"target": Addr(t), "kind": k})).collect::<Vec<_>>(),
            "instructions": insns,
        }));
    }
    let callees: Vec<Value> = f
        .calls
        .iter()
        .map(|&c| json!({"addr": Addr(c), "name": nm(c)}))
        .collect();
    let callers: Vec<Value> = f
        .called_by
        .iter()
        .map(|&c| json!({"addr": Addr(c), "name": nm(c)}))
        .collect();
    let xrefs: Vec<Xref> = a
        .xrefs_to(f.entry)
        .iter()
        .take(500)
        .map(|x| Xref {
            from: Addr(x.from),
            to: Addr(x.to),
            kind: x.kind,
        })
        .collect();
    let strings: Vec<Value> = a
        .xrefs_from(lo, hi)
        .into_iter()
        .filter_map(|x| s.strings.binary_search_by_key(&Addr(x.to), |s| s.addr).ok().map(|i| json!({"from": Addr(x.from), "addr": Addr(x.to), "value": s.strings[i].value})))
        .take(500)
        .collect();
    Ok(Json(json!({
        "entry": Addr(f.entry),
        "name": renames.get(&f.entry).cloned().unwrap_or_else(|| f.name.to_string()),
        "original_name": f.name,
        "name_source": f.name_source,
        "size": f.size,
        "insns": f.insns,
        "is_thunk": f.is_thunk,
        "noreturn": f.noreturn,
        "metrics": {"block_count": cfg.len(), "edge_count": cfg.iter().map(|b| b.succs.len()).sum::<usize>(), "cyclomatic": f.cyclomatic()},
        "blocks": blocks,
        "truncated": budget == 0,
        "callees": callees,
        "callers": callers,
        "xrefs_to": xrefs,
        "strings": strings,
    })))
}

#[derive(Deserialize)]
pub struct DisasmQ {
    addr: Option<String>,
    count: Option<usize>,
}

pub async fn disasm(
    State(st): State<Shared>,
    Path(sha): Path<String>,
    Query(q): Query<DisasmQ>,
) -> R<Json<Value>> {
    let s = session(&st, &sha).await?;
    let img = s
        .image
        .as_ref()
        .ok_or_else(|| not_found("no native image"))?;
    let at = match q.addr {
        Some(a) => parse_addr(&a)?,
        None => img
            .entry
            .or(img.code.first().map(|c| c.start))
            .unwrap_or(img.image_base),
    };
    let renames = st.renames(&sha);
    let nm = namer(&s, &renames);
    let count = q.count.unwrap_or(200).min(2000);
    let mut ins = drishti_disasm::disasm(img, at, count, &nm);
    let comments = st.comments(
        &sha,
        at,
        ins.last().map(|i| i.addr.0 + 16).unwrap_or(at + 1),
    );
    let labels: HashMap<u64, String> = ins
        .iter()
        .filter_map(|i| {
            s.analysis
                .as_ref()?
                .function_at(i.addr.0)
                .map(|_| (i.addr.0, nm(i.addr.0).unwrap_or_default()))
        })
        .collect();
    for i in &mut ins {
        if let Some(c) = comments.get(&i.addr.0) {
            i.comment = Some(c.clone());
        }
    }
    let containing = s
        .analysis
        .as_ref()
        .and_then(|a| a.function_containing(at))
        .map(|f| json!({"entry": Addr(f.entry), "name": nm(f.entry)}));
    Ok(Json(
        json!({ "addr": Addr(at), "instructions": ins, "labels": labels.into_iter().map(|(k, v)| (format!("{k:#x}"), v)).collect::<HashMap<_, _>>(), "section": img.section_name(at), "function": containing }),
    ))
}

#[derive(Deserialize)]
pub struct XrefQ {
    to: Option<String>,
    from: Option<String>,
}

pub async fn xrefs(
    State(st): State<Shared>,
    Path(sha): Path<String>,
    Query(q): Query<XrefQ>,
) -> R<Json<Value>> {
    let s = analysed(&st, &sha).await?;
    let a = s
        .analysis
        .as_ref()
        .ok_or_else(|| not_found("not analysed"))?;
    let renames = st.renames(&sha);
    let nm = namer(&s, &renames);
    let list: Vec<_> = if let Some(t) = q.to {
        a.xrefs_to(parse_addr(&t)?).to_vec()
    } else if let Some(f) = q.from {
        let f = parse_addr(&f)?;
        let hi = a
            .function_at(f)
            .map(|x| x.entry + x.size.max(1))
            .unwrap_or(f + 1);
        a.xrefs_from(f, hi)
    } else {
        return Err(bad("pass ?to= or ?from="));
    };
    let items: Vec<Value> = list
        .iter()
        .take(5000)
        .map(|x| {
            let func = a.function_containing(x.from).map(|f| json!({"entry": Addr(f.entry), "name": nm(f.entry)}));
            json!({"from": Addr(x.from), "to": Addr(x.to), "kind": x.kind, "function": func, "target_name": nm(x.to)})
        })
        .collect();
    Ok(Json(json!({ "items": items })))
}

#[derive(Deserialize)]
pub struct CgQ {
    root: String,
    depth: Option<usize>,
}

pub async fn callgraph(
    State(st): State<Shared>,
    Path(sha): Path<String>,
    Query(q): Query<CgQ>,
) -> R<Json<Value>> {
    let s = analysed(&st, &sha).await?;
    let a = s
        .analysis
        .as_ref()
        .ok_or_else(|| not_found("not analysed"))?;
    let renames = st.renames(&sha);
    let nm = namer(&s, &renames);
    let root = parse_addr(&q.root)?;
    let depth = q.depth.unwrap_or(2).min(5);
    let mut nodes: HashSet<u64> = HashSet::from([root]);
    let mut edges: HashSet<(u64, u64)> = HashSet::new();
    let mut qu: VecDeque<(u64, usize)> = VecDeque::from([(root, 0)]);
    while let Some((n, d)) = qu.pop_front() {
        if d >= depth || nodes.len() > 300 {
            continue;
        }
        if let Some(f) = a.function_at(n) {
            for &c in &f.calls {
                edges.insert((n, c));
                if nodes.insert(c) {
                    qu.push_back((c, d + 1));
                }
            }
            for &c in &f.called_by {
                edges.insert((c, n));
                if nodes.insert(c) {
                    qu.push_back((c, d + 1));
                }
            }
        }
    }
    let nodes: Vec<Value> = nodes.iter().map(|&n| json!({"addr": Addr(n), "name": nm(n).unwrap_or_else(|| format!("{n:#x}")), "import": s.image.as_ref().and_then(|i| i.import_at(n)).is_some(), "root": n == root})).collect();
    let edges: Vec<Value> = edges
        .iter()
        .map(|&(a, b)| json!({"from": Addr(a), "to": Addr(b)}))
        .collect();
    Ok(Json(json!({ "nodes": nodes, "edges": edges })))
}

#[derive(Deserialize)]
pub struct ResolveQ {
    q: String,
}

/// "Go to": address, function name, symbol or string.
pub async fn resolve(
    State(st): State<Shared>,
    Path(sha): Path<String>,
    Query(q): Query<ResolveQ>,
) -> R<Json<Value>> {
    let s = session(&st, &sha).await?;
    let needle = q.q.trim();
    let mut out = Vec::new();
    if let Some(a) = Addr::parse(needle)
        .filter(|_| needle.starts_with("0x") || needle.chars().all(|c| c.is_ascii_hexdigit()))
        && s.image.as_ref().is_some_and(|i| i.is_mapped(a.0))
    {
        out.push(json!({"kind": "address", "addr": a, "label": a.to_string()}));
    }
    let lower = needle.to_lowercase();
    let renames = st.renames(&sha);
    for (a, n) in &renames {
        if n.to_lowercase().contains(&lower) {
            out.push(json!({"kind": "function", "addr": Addr(*a), "label": n}));
        }
    }
    if let Some(an) = &s.analysis {
        for f in an
            .functions
            .iter()
            .filter(|f| f.name.to_lowercase().contains(&lower))
            .take(30)
        {
            out.push(json!({"kind": "function", "addr": Addr(f.entry), "label": f.name}));
        }
    }
    if let Some(img) = &s.image {
        for x in img
            .imports
            .iter()
            .filter(|x| x.display_name().to_lowercase().contains(&lower))
            .take(10)
        {
            out.push(json!({"kind": "import", "addr": x.addr, "label": x.display_name()}));
        }
    }
    for x in s
        .strings
        .iter()
        .filter(|x| x.value.to_lowercase().contains(&lower))
        .take(15)
    {
        out.push(json!({"kind": "string", "addr": x.addr, "label": x.value}));
    }
    out.truncate(60);
    Ok(Json(json!({ "results": out })))
}

// ---------------------------------------------------------------- jobs

#[derive(Deserialize)]
pub struct JobReq {
    binary: String,
    #[serde(default)]
    engines: Vec<String>,
}

pub async fn create_job(State(st): State<Shared>, Json(b): Json<JobReq>) -> R<Json<Value>> {
    valid_sha(&b.binary)?;
    if b.engines.iter().any(|e| e != "core") {
        return Err(bad(
            "only the core engine is available in this build (see GET /engines)",
        ));
    }
    let id = start_job(&st, &b.binary).await?;
    Ok(Json(json!({ "job_id": id })))
}

/// Start (or join) the core analysis job for `sha`.
pub async fn start_job(st: &Shared, sha: &str) -> R<String> {
    if let Ok(j) = st.jobs.lock()
        && let Some(existing) = j
            .values()
            .find(|j| j.sha256 == sha && (j.status == "queued" || j.status == "running"))
    {
        return Ok(existing.id.clone());
    }
    let id = new_id();
    let cancel = Arc::new(AtomicBool::new(false));
    let info = JobInfo {
        id: id.clone(),
        sha256: sha.into(),
        engines: vec!["core".into()],
        status: "queued".into(),
        phase: None,
        functions: 0,
        instructions: 0,
        error: None,
        created_at: now(),
        finished_at: None,
        cancel: cancel.clone(),
    };
    st.jobs
        .lock()
        .map_err(|e| e.to_string())?
        .insert(id.clone(), info);
    {
        let db = st.db.lock().map_err(|e| e.to_string())?;
        db.execute("INSERT INTO jobs (id, sha256, engines, status, created_at) VALUES (?1, ?2, 'core', 'queued', ?3)", params![id, sha, now()])?;
    }
    st.emit(Event::job(&id, sha, "queued"));
    let st2 = st.clone();
    let (id2, sha2) = (id.clone(), sha.to_string());
    tokio::spawn(async move {
        let result = run_job(&st2, &id2, &sha2, cancel).await;
        let (status, err) = match &result {
            Ok(()) => ("done", None),
            Err(e) => (
                if e.1.contains("cancelled") {
                    "cancelled"
                } else {
                    "failed"
                },
                Some(e.1.clone()),
            ),
        };
        if let Ok(mut j) = st2.jobs.lock()
            && let Some(j) = j.get_mut(&id2)
        {
            j.status = status.into();
            j.error = err.clone();
            j.finished_at = Some(now());
        }
        if let Ok(db) = st2.db.lock() {
            let _ = db.execute(
                "UPDATE jobs SET status=?1, error=?2, finished_at=?3 WHERE id=?4",
                params![status, err, now(), id2],
            );
        }
        let mut e = Event::job(&id2, &sha2, status);
        e.message = err;
        st2.emit(e);
    });
    Ok(id)
}

async fn run_job(st: &Shared, id: &str, sha: &str, cancel: Arc<AtomicBool>) -> R<()> {
    let _permit = st.analysis_slots.acquire().await?;
    let base = session(st, sha).await?;
    if let Some(e) = &base.load_error {
        return Err(bad(e.clone()));
    }
    if base.image.is_none() {
        return Err(bad(
            "format has no native code; core analysis not applicable",
        ));
    }
    if base.analysis.is_some() {
        // Already analysed (possibly restored from the persisted cache).
        return Ok(());
    }
    if let Ok(mut j) = st.jobs.lock()
        && let Some(j) = j.get_mut(id)
    {
        j.status = "running".into();
    }
    st.emit(Event::job(id, sha, "running"));
    let st2 = st.clone();
    let (id2, sha2) = (id.to_string(), sha.to_string());
    let analysis = tokio::task::spawn_blocking(move || {
        let img = base.image.as_ref().ok_or("no image")?;
        let last =
            std::sync::Mutex::new(std::time::Instant::now() - std::time::Duration::from_secs(1));
        let progress = |p: drishti_disasm::Progress| {
            // Throttle to ~10 events/s so the UI stays live without flooding.
            let Ok(mut l) = last.lock() else { return };
            if l.elapsed().as_millis() < 100 && p.phase != "done" {
                return;
            }
            *l = std::time::Instant::now();
            if let Ok(mut j) = st2.jobs.lock()
                && let Some(j) = j.get_mut(&id2)
            {
                j.phase = Some(p.phase.into());
                j.functions = p.functions;
                j.instructions = p.instructions;
            }
            let mut e = Event::job(&id2, &sha2, "running");
            e.phase = Some(p.phase.into());
            e.functions = Some(p.functions);
            e.instructions = Some(p.instructions);
            st2.emit(e);
        };
        let a = analyze(img, &Options::default(), &progress, &cancel).map_err(|e| e.to_string())?;
        st2.store_analysis(&sha2, &a);
        Ok::<_, String>((a, base))
    })
    .await?
    .map_err(bad)?;
    let (a, base) = analysis;
    let stats = json!({"functions": a.functions.len(), "instructions": a.stats.instructions, "duration_ms": a.stats.duration_ms});
    // New session sharing the image and strings; the old one drops from the cache.
    let sess = Session {
        sha: base.sha.clone(),
        blob: base.blob.clone(),
        image: base.image.clone(),
        info: base.info.clone(),
        findings: base.findings.clone(),
        strings: base.strings.clone(),
        analysis: Some(a),
        load_error: None,
    };
    st.put_session(Arc::new(sess));
    if let Ok(db) = st.db.lock() {
        let _ = db.execute(
            "UPDATE jobs SET stats=?1 WHERE id=?2",
            params![stats.to_string(), id],
        );
    }
    Ok(())
}

pub async fn get_job(State(st): State<Shared>, Path(id): Path<String>) -> R<Json<JobInfo>> {
    st.jobs
        .lock()
        .map_err(|e| e.to_string())?
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or_else(|| not_found("unknown job"))
}

pub async fn cancel_job(State(st): State<Shared>, Path(id): Path<String>) -> R<Json<Value>> {
    let j = st.jobs.lock().map_err(|e| e.to_string())?;
    let j = j.get(&id).ok_or_else(|| not_found("unknown job"))?;
    j.cancel.store(true, Ordering::Relaxed);
    Ok(Json(json!({"ok": true})))
}

/// WebSocket: live events. `/events` streams everything; `/jobs/{id}/events`
/// only that job.
pub async fn ws_all(State(st): State<Shared>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |sock| pump(st, sock, None))
}
pub async fn ws_job(
    State(st): State<Shared>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |sock| pump(st, sock, Some(id)))
}

async fn pump(st: Shared, mut sock: WebSocket, job: Option<String>) {
    let mut rx = st.events.subscribe();
    if let Some(id) = &job {
        let snap = st.jobs.lock().ok().and_then(|j| j.get(id).cloned());
        if let Some(j) = snap {
            let _ = sock
                .send(Message::Text(
                    json!({"type": "snapshot", "job": j}).to_string().into(),
                ))
                .await;
        }
    }
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(e) => {
                    if job.as_ref().is_some_and(|id| e.job_id.as_ref() != Some(id)) { continue; }
                    let Ok(txt) = serde_json::to_string(&e) else { continue };
                    if sock.send(Message::Text(txt.into())).await.is_err() { break; }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            },
            msg = sock.recv() => match msg {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------- annotations

#[derive(Deserialize)]
pub struct AnnReq {
    addr: String,
    kind: AnnotationKind,
    value: String,
    scope: Option<String>,
    #[serde(default)]
    author: Option<Author>,
}

fn row_to_ann(r: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": r.get::<_, String>(0)?, "binary_sha256": r.get::<_, String>(1)?, "addr": Addr(r.get::<_, i64>(2)? as u64),
        "kind": r.get::<_, String>(3)?, "value": r.get::<_, String>(4)?, "scope": r.get::<_, Option<String>>(5)?,
        "author": r.get::<_, String>(6)?, "ai_status": r.get::<_, Option<String>>(7)?,
        "created_at": r.get::<_, String>(8)?, "updated_at": r.get::<_, String>(9)?,
    }))
}

pub async fn list_annotations(State(st): State<Shared>, Path(sha): Path<String>) -> R<Json<Value>> {
    valid_sha(&sha)?;
    let db = st.db.lock().map_err(|e| e.to_string())?;
    let mut q = db.prepare("SELECT id, sha256, addr, kind, value, scope, author, ai_status, created_at, updated_at FROM annotations WHERE sha256=?1 ORDER BY addr")?;
    let items: Vec<Value> = q.query_map(params![sha], row_to_ann)?.flatten().collect();
    Ok(Json(json!({ "items": items })))
}

pub async fn add_annotation(
    State(st): State<Shared>,
    Path(sha): Path<String>,
    Json(b): Json<AnnReq>,
) -> R<Json<Value>> {
    valid_sha(&sha)?;
    let addr = parse_addr(&b.addr)?;
    if b.value.len() > 4096 {
        return Err(bad("value too long"));
    }
    let author = b.author.unwrap_or(Author::User);
    let ann = Annotation {
        id: new_id(),
        binary_sha256: sha.clone(),
        addr: Addr(addr),
        kind: b.kind,
        value: b.value.trim().to_string(),
        scope: b.scope,
        author,
        ai_status: if author == Author::Ai {
            Some(drishti_model::AiStatus::Unverified)
        } else {
            None
        },
        created_at: now(),
        updated_at: now(),
    };
    {
        let db = st.db.lock().map_err(|e| e.to_string())?;
        // One rename / comment per address: replace previous user value.
        if matches!(
            b.kind,
            AnnotationKind::RenameFunction | AnnotationKind::Comment
        ) && author == Author::User
        {
            db.execute(
                "DELETE FROM annotations WHERE sha256=?1 AND addr=?2 AND kind=?3 AND author='user'",
                params![sha, addr as i64, kind_str(b.kind)],
            )?;
        }
        if !ann.value.is_empty() {
            db.execute(
                "INSERT INTO annotations (id, sha256, addr, kind, value, scope, author, ai_status, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![ann.id, sha, addr as i64, kind_str(b.kind), ann.value, ann.scope, if author == Author::Ai { "ai" } else { "user" }, ann.ai_status.map(|_| "unverified"), ann.created_at, ann.updated_at],
            )?;
        }
    }
    let mut e = Event::job("", &sha, "annotation");
    e.kind = "annotation";
    e.job_id = None;
    st.emit(e);
    Ok(Json(serde_json::to_value(ann)?))
}

#[derive(Deserialize)]
pub struct PatchReq {
    value: Option<String>,
    ai_status: Option<String>,
}

pub async fn patch_annotation(
    State(st): State<Shared>,
    Path((sha, id)): Path<(String, String)>,
    Json(b): Json<PatchReq>,
) -> R<Json<Value>> {
    let db = st.db.lock().map_err(|e| e.to_string())?;
    if let Some(v) = b.value {
        db.execute(
            "UPDATE annotations SET value=?1, updated_at=?2 WHERE id=?3 AND sha256=?4",
            params![v, now(), id, sha],
        )?;
    }
    if let Some(s) = b.ai_status {
        if !["verified", "refuted", "unverified", "accepted", "rejected"].contains(&s.as_str()) {
            return Err(bad("invalid ai_status"));
        }
        db.execute(
            "UPDATE annotations SET ai_status=?1, updated_at=?2 WHERE id=?3 AND sha256=?4",
            params![s, now(), id, sha],
        )?;
    }
    Ok(Json(json!({"ok": true})))
}

pub async fn delete_annotation(
    State(st): State<Shared>,
    Path((sha, id)): Path<(String, String)>,
) -> R<Json<Value>> {
    let db = st.db.lock().map_err(|e| e.to_string())?;
    let n = db.execute(
        "DELETE FROM annotations WHERE id=?1 AND sha256=?2",
        params![id, sha],
    )?;
    Ok(Json(json!({"deleted": n})))
}

// ---------------------------------------------------------------- misc

pub async fn health() -> Json<Value> {
    Json(json!({"ok": true, "version": env!("CARGO_PKG_VERSION")}))
}

pub async fn engines() -> Json<Value> {
    Json(json!({ "engines": crate::engines::detect() }))
}

pub async fn get_settings(State(st): State<Shared>) -> R<Json<Value>> {
    let db = st.db.lock().map_err(|e| e.to_string())?;
    let mut q = db.prepare("SELECT key, value FROM settings")?;
    let mut m = serde_json::Map::new();
    for (k, v) in q
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .flatten()
    {
        m.insert(k, serde_json::from_str(&v).unwrap_or(Value::String(v)));
    }
    m.insert("local_mode".into(), json!(st.local_mode));
    m.insert("upload_limit".into(), json!(st.upload_limit));
    Ok(Json(Value::Object(m)))
}

pub async fn put_settings(
    State(st): State<Shared>,
    Json(b): Json<serde_json::Map<String, Value>>,
) -> R<Json<Value>> {
    let db = st.db.lock().map_err(|e| e.to_string())?;
    for (k, v) in b {
        if k.len() > 64 || k.contains("key") && k.contains("api") {
            // API keys are configured via environment, never stored here.
            continue;
        }
        db.execute("INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![k, v.to_string()])?;
    }
    Ok(Json(json!({"ok": true})))
}

/// Hand-maintained route index (OpenAPI generation is a later phase).
pub async fn openapi() -> Json<Value> {
    Json(json!({
        "openapi": "3.1.0",
        "info": {"title": "Drishti API", "version": env!("CARGO_PKG_VERSION")},
        "paths": {
            "/api/v1/health": {"get": {}}, "/api/v1/engines": {"get": {}},
            "/api/v1/binaries": {"get": {}, "post": {"description": "raw body upload; ?name=&analyze="}},
            "/api/v1/binaries/open": {"post": {"description": "local mode: {path}"}},
            "/api/v1/binaries/{sha}": {"get": {}}, "/api/v1/binaries/{sha}/bytes": {"get": {}},
            "/api/v1/binaries/{sha}/{symbols|imports|exports}": {"get": {}},
            "/api/v1/binaries/{sha}/strings": {"get": {}}, "/api/v1/binaries/{sha}/functions": {"get": {}},
            "/api/v1/binaries/{sha}/functions/{addr}": {"get": {}}, "/api/v1/binaries/{sha}/disasm": {"get": {}},
            "/api/v1/binaries/{sha}/xrefs": {"get": {}}, "/api/v1/binaries/{sha}/callgraph": {"get": {}},
            "/api/v1/binaries/{sha}/resolve": {"get": {}},
            "/api/v1/binaries/{sha}/annotations": {"get": {}, "post": {}},
            "/api/v1/binaries/{sha}/annotations/{id}": {"patch": {}, "delete": {}},
            "/api/v1/jobs": {"post": {}}, "/api/v1/jobs/{id}": {"get": {}, "delete": {}},
            "/api/v1/jobs/{id}/events": {"get": {"description": "WebSocket"}}, "/api/v1/events": {"get": {"description": "WebSocket"}},
            "/api/v1/settings": {"get": {}, "put": {}},
            "/api/v1/binaries/{sha}/insights": {"get": {"description": "summary, hardening, behaviours, IOCs, document report (PDF), download origin"}},
            "/api/v1/binaries/{sha}/vulns": {"get": {"description": "static input→sink reachability audit (weak spots)"}},
            "/api/v1/binaries/{sha}/nl-query": {"post": {"description": "{question} → function query + matches (plain-English search)"}},
            "/api/v1/ai/status": {"get": {"description": "local AI server, installed models, chosen model"}},
            "/api/v1/binaries/{sha}/ai/ask": {"post": {"description": "{question, history?, addr?} → streamed text/plain answer"}},
        }
    }))
}
